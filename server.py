from __future__ import annotations

import argparse
import base64
import binascii
import copy
import json
import logging
import re
import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MAX_PACKET_BYTES = 1_048_576
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
LOGGER = logging.getLogger("secure_chat_server")


@dataclass(eq=False)
class ClientSession:
    sock: socket.socket
    address: tuple[str, int]
    username: str | None = None
    public_key_pem: str | None = None
    send_lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, packet: dict[str, Any]) -> None:
        encoded = (json.dumps(packet, separators=(",", ":")) + "\n").encode("utf-8")
        with self.send_lock:
            self.sock.sendall(encoded)


class SecureRelayServer:
    def __init__(self, host: str, port: int, malicious: bool = False) -> None:
        self.host = host
        self.port = port
        self.malicious = malicious
        self._listener: socket.socket | None = None
        self._stopping = threading.Event()
        self._lock = threading.RLock()
        self._clients: dict[str, ClientSession] = {}
        self._pending_attacks: dict[str, tuple[str, str | None]] = {}
        self._last_relay: dict[str, tuple[dict[str, Any], str]] = {}

    def serve_forever(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.port))
        listener.listen()
        listener.settimeout(0.5)
        self.port = listener.getsockname()[1]
        self._listener = listener
        LOGGER.info(
            "Secure relay listening on %s:%d (malicious mode: %s)",
            self.host,
            self.port,
            "ON" if self.malicious else "OFF",
        )

        try:
            while not self._stopping.is_set():
                try:
                    client_socket, address = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stopping.is_set():
                        break
                    raise
                thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, address),
                    daemon=True,
                    name=f"client-{address[0]}:{address[1]}",
                )
                thread.start()
        finally:
            listener.close()

    def stop(self) -> None:
        self._stopping.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        with self._lock:
            sessions = list(self._clients.values())
        for session in sessions:
            try:
                session.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            session.sock.close()

    def _handle_connection(
        self, client_socket: socket.socket, address: tuple[str, int]
    ) -> None:
        session = ClientSession(client_socket, address)
        LOGGER.info("Connection opened from %s:%d", *address)
        try:
            with client_socket, client_socket.makefile("rb") as reader:
                while not self._stopping.is_set():
                    line = reader.readline(MAX_PACKET_BYTES + 1)
                    if not line:
                        break
                    if len(line) > MAX_PACKET_BYTES:
                        self._send_error(session, "packet_too_large", "packet exceeds 1 MB")
                        break
                    try:
                        packet = json.loads(line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        self._send_error(session, "invalid_json", "packet must be UTF-8 JSON")
                        continue
                    if not isinstance(packet, dict):
                        self._send_error(session, "invalid_packet", "packet must be a JSON object")
                        continue
                    self._handle_packet(session, packet)
        except (ConnectionError, OSError):
            pass
        finally:
            removed = False
            with self._lock:
                if session.username and self._clients.get(session.username) is session:
                    del self._clients[session.username]
                    self._pending_attacks.pop(session.username, None)
                    removed = True
            LOGGER.info("Connection closed for %s", session.username or address)
            if removed:
                self._broadcast_online_users()

    def _handle_packet(self, session: ClientSession, packet: dict[str, Any]) -> None:
        packet_type = packet.get("type")
        if packet_type == "register":
            self._register(session, packet)
            return
        if session.username is None:
            self._send_error(session, "not_registered", "register before sending requests")
            return
        if packet_type == "key_request":
            self._key_request(session, packet)
        elif packet_type == "chat":
            self._chat(session, packet)
        elif packet_type == "attack":
            self._attack_request(session, packet)
        else:
            self._send_error(session, "unknown_type", "unsupported packet type")

    def _register(self, session: ClientSession, packet: dict[str, Any]) -> None:
        if session.username is not None:
            self._send_error(session, "already_registered", "connection is already registered")
            return
        username = packet.get("username")
        public_key = packet.get("public_key")
        if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
            self._send_error(
                session,
                "invalid_username",
                "use 1-32 letters, numbers, dots, dashes, or underscores",
            )
            return
        if (
            not isinstance(public_key, str)
            or len(public_key) > 10_000
            or "-----BEGIN PUBLIC KEY-----" not in public_key
            or "-----END PUBLIC KEY-----" not in public_key
        ):
            self._send_error(session, "invalid_public_key", "a PEM public key is required")
            return

        with self._lock:
            if username in self._clients:
                self._send_error(session, "username_in_use", "that username is already online")
                return
            session.username = username
            session.public_key_pem = public_key
            self._clients[username] = session
        session.send({"type": "registered", "username": username})
        LOGGER.info("Registered %s from %s:%d", username, *session.address)
        self._broadcast_online_users()

    def _key_request(self, session: ClientSession, packet: dict[str, Any]) -> None:
        username = packet.get("username")
        request_id = packet.get("request_id")
        if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
            self._send_error(
                session, "invalid_key_request", "a valid username is required", request_id
            )
            return
        with self._lock:
            target = self._clients.get(username)
            public_key = target.public_key_pem if target else None
        if public_key is None:
            self._send_error(session, "unknown_user", f"{username} is not online", request_id)
            return
        session.send(
            {
                "type": "key_response",
                "username": username,
                "public_key": public_key,
                "request_id": request_id,
            }
        )

    def _chat(self, session: ClientSession, packet: dict[str, Any]) -> None:
        sender = packet.get("from")
        recipient = packet.get("to")
        if sender != session.username:
            self._send_error(session, "sender_mismatch", "from must match this connection")
            return
        if not isinstance(recipient, str) or not USERNAME_RE.fullmatch(recipient):
            self._send_error(session, "invalid_recipient", "chat packet has no valid recipient")
            return

        outgoing = copy.deepcopy(packet)
        route_to = recipient
        applied_attack: str | None = None
        with self._lock:
            attack = self._pending_attacks.pop(session.username, None)
        if attack is not None:
            applied_attack, target = attack
            try:
                outgoing, route_to = self._apply_attack(outgoing, route_to, applied_attack, target)
            except ValueError as exc:
                self._send_error(session, "attack_failed", str(exc))
                return

        with self._lock:
            destination = self._clients.get(route_to)
        if destination is None:
            self._send_error(session, "unknown_user", f"{route_to} is not online")
            return

        try:
            self._relay(destination, outgoing, replay=False)
        except OSError:
            self._send_error(session, "delivery_failed", f"could not deliver to {route_to}")
            return

        with self._lock:
            self._last_relay[session.username] = (copy.deepcopy(outgoing), route_to)
        if applied_attack:
            session.send(
                {
                    "type": "attack_applied",
                    "action": applied_attack,
                    "routed_to": route_to,
                }
            )

    def _attack_request(self, session: ClientSession, packet: dict[str, Any]) -> None:
        if not self.malicious:
            self._send_error(session, "malicious_mode_off", "restart server with --malicious")
            return
        if packet.get("from") != session.username:
            self._send_error(session, "sender_mismatch", "from must match this connection")
            return
        action = packet.get("action")
        target = packet.get("target")
        valid_actions = {
            "flip_ciphertext",
            "change_recipient",
            "change_number",
            "misdeliver",
            "replay",
        }
        if action not in valid_actions:
            self._send_error(session, "invalid_attack", "unknown demonstration attack")
            return

        if action == "replay":
            with self._lock:
                previous = self._last_relay.get(session.username)
                destination = self._clients.get(previous[1]) if previous else None
            if previous is None:
                self._send_error(session, "nothing_to_replay", "send a normal message first")
                return
            if destination is None:
                self._send_error(session, "unknown_user", "the prior recipient is offline")
                return
            try:
                self._relay(destination, copy.deepcopy(previous[0]), replay=True)
                session.send({"type": "attack_applied", "action": "replay"})
            except OSError:
                self._send_error(session, "delivery_failed", "replay delivery failed")
            return

        if action in {"change_recipient", "misdeliver"}:
            if not isinstance(target, str) or not USERNAME_RE.fullmatch(target):
                self._send_error(session, "target_required", f"{action} requires a target user")
                return
            with self._lock:
                if target not in self._clients:
                    self._send_error(session, "unknown_user", f"{target} is not online")
                    return

        with self._lock:
            self._pending_attacks[session.username] = (action, target)
        session.send({"type": "attack_armed", "action": action, "target": target})

    def _apply_attack(
        self,
        packet: dict[str, Any],
        route_to: str,
        action: str,
        target: str | None,
    ) -> tuple[dict[str, Any], str]:
        if action == "flip_ciphertext":
            value = packet.get("ciphertext")
            if not isinstance(value, str):
                raise ValueError("chat packet has no ciphertext")
            try:
                ciphertext = bytearray(base64.b64decode(value, validate=True))
            except (binascii.Error, ValueError) as exc:
                raise ValueError("ciphertext is not valid base64") from exc
            if not ciphertext:
                raise ValueError("ciphertext is empty")
            ciphertext[0] ^= 0x01
            packet["ciphertext"] = base64.b64encode(ciphertext).decode("ascii")
        elif action == "change_recipient":
            assert target is not None
            packet["to"] = target
            route_to = target
        elif action == "change_number":
            number = packet.get("message_number")
            if isinstance(number, bool) or not isinstance(number, int):
                raise ValueError("chat packet has no valid message number")
            packet["message_number"] = number + 1
        elif action == "misdeliver":
            assert target is not None
            route_to = target
        return packet, route_to

    def _relay(
        self, destination: ClientSession, packet: dict[str, Any], replay: bool
    ) -> None:
        LOGGER.info(
            "%s opaque_packet=%s",
            "REPLAY" if replay else "RELAY",
            json.dumps(packet, separators=(",", ":"), sort_keys=True),
        )
        destination.send(packet)

    def _broadcast_online_users(self) -> None:
        with self._lock:
            users = sorted(self._clients)
            sessions = list(self._clients.values())
        packet = {"type": "online_users", "users": users}
        for session in sessions:
            try:
                session.send(packet)
            except OSError:
                pass

    @staticmethod
    def _send_error(
        session: ClientSession,
        code: str,
        message: str,
        request_id: Any = None,
    ) -> None:
        packet: dict[str, Any] = {"type": "error", "code": code, "message": message}
        if request_id is not None:
            packet["request_id"] = request_id
        try:
            session.send(packet)
        except OSError:
            pass


def configure_logging(log_file: str) -> None:
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    LOGGER.setLevel(logging.INFO)
    LOGGER.handlers.clear()
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    LOGGER.addHandler(console)
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure chat relay and key directory")
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind")
    parser.add_argument("--port", type=int, default=5050, help="TCP port (default: 5050)")
    parser.add_argument(
        "--malicious",
        action="store_true",
        help="enable requested tampering/replay demonstrations",
    )
    parser.add_argument("--log-file", default="server.log", help="relay log destination")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging(args.log_file)
    server = SecureRelayServer(args.host, args.port, args.malicious)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Stopping server")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
