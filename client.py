from __future__ import annotations

import argparse
import getpass
import json
import os
import socket
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_module import (
    DecryptionError,
    KeyFileError,
    MessageFormatError,
    SignatureVerificationError,
    USERNAME_RE,
    decrypt_and_verify,
    encrypt_and_sign,
    load_or_create_keypair,
    load_public_key,
    public_key_fingerprint,
    public_key_to_pem,
)


MAX_PACKET_BYTES = 1_048_576


@dataclass
class KeyRequest:
    username: str
    request_id: str
    event: threading.Event = field(default_factory=threading.Event)
    error: str | None = None


class SecureChatClient:
    def __init__(
        self,
        username: str,
        private_key: rsa.RSAPrivateKey,
        public_key: rsa.RSAPublicKey,
        host: str,
        port: int,
        key_directory: str | Path,
    ) -> None:
        self.username = username
        self.private_key = private_key
        self.public_key = public_key
        self.host = host
        self.port = port
        self.key_directory = Path(key_directory)
        self.trusted_directory = self.key_directory / f"{username}_trusted_peers"
        self.trusted_directory.mkdir(parents=True, exist_ok=True)

        self.sock: socket.socket | None = None
        self._reader = None
        self._send_lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._closing = threading.Event()
        self._registered = threading.Event()
        self._registration_error: str | None = None

        self._cache_lock = threading.RLock()
        self._public_keys: dict[str, rsa.RSAPublicKey] = {
            username: public_key
        }
        self._requests: dict[str, KeyRequest] = {}
        self._requests_by_user: dict[str, KeyRequest] = {}
        self._pending_messages: dict[str, list[dict[str, Any]]] = {}
        self.online_users: list[str] = []

        self._state_lock = threading.RLock()
        self._state_path = self.key_directory / f"{username}_message_state.json"
        self._own_fingerprint = public_key_fingerprint(public_key)
        self._outgoing_number = 0
        self._highest_received: dict[str, int] = {}
        self._load_message_state()

    def connect(self, timeout: float = 10.0) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=timeout)
        self.sock.settimeout(None)
        self._reader = self.sock.makefile("rb")
        threading.Thread(
            target=self._receive_loop,
            daemon=True,
            name=f"receiver-{self.username}",
        ).start()
        self._send(
            {
                "type": "register",
                "username": self.username,
                "public_key": public_key_to_pem(self.public_key),
            }
        )
        if not self._registered.wait(timeout):
            self.close()
            raise ConnectionError("server did not complete registration")
        if self._registration_error:
            self.close()
            raise ConnectionError(self._registration_error)

    def close(self) -> None:
        self._closing.set()
        sock, self.sock = self.sock, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def run_interactive(self) -> None:
        self._print(
            f"Connected as {self.username}. Use /msg USER MESSAGE, /users, /attack, or /quit."
        )
        while not self._closing.is_set():
            try:
                command = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                self._print("")
                break
            if not command:
                continue
            if command == "/quit":
                break
            if command == "/users":
                self._print("Online: " + (", ".join(self.online_users) or "none"))
                continue
            if command.startswith("/msg "):
                parts = command.split(" ", 2)
                if len(parts) != 3 or not parts[2]:
                    self._print("Usage: /msg USER MESSAGE")
                    continue
                try:
                    self.send_chat(parts[1], parts[2])
                except (ConnectionError, KeyFileError, ValueError) as exc:
                    self._print(f"[send rejected] {exc}")
                continue
            if command.startswith("/attack"):
                parts = command.split()
                if len(parts) not in (2, 3):
                    self._print("Usage: /attack ACTION [TARGET]")
                    continue
                try:
                    self.request_attack(parts[1], parts[2] if len(parts) == 3 else None)
                except ValueError as exc:
                    self._print(f"[attack rejected] {exc}")
                continue
            self._print("Unknown command.")
        self.close()

    def send_chat(self, recipient: str, plaintext: str) -> None:
        if not USERNAME_RE.fullmatch(recipient):
            raise ValueError("invalid recipient username")
        if not plaintext:
            raise ValueError("message must not be empty")
        if len(plaintext.encode("utf-8")) > 512_000:
            raise ValueError("message is too large")
        recipient_key = self.get_public_key(recipient)
        message_number = self._next_message_number()
        header = {
            "from": self.username,
            "to": recipient,
            "message_number": message_number,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }
        packet = encrypt_and_sign(
            plaintext, self.private_key, recipient_key, header
        )
        self._send(packet)
        self._print(f"[submitted #{message_number}] encrypted message to {recipient}")

    def request_attack(self, action: str, target: str | None = None) -> None:
        valid = {
            "flip_ciphertext",
            "change_recipient",
            "change_number",
            "misdeliver",
            "replay",
        }
        if action not in valid:
            raise ValueError("unknown action.")
        if action in {"change_recipient", "misdeliver"}:
            if target is None or not USERNAME_RE.fullmatch(target):
                raise ValueError(f"{action} requires a target username")
        elif target is not None:
            raise ValueError(f"{action} does not take a target")
        self._send(
            {"type": "attack", "from": self.username, "action": action, "target": target}
        )

    def get_public_key(self, username: str, timeout: float = 10.0) -> rsa.RSAPublicKey:
        with self._cache_lock:
            cached = self._public_keys.get(username)
        if cached is not None:
            return cached
        request = self._request_public_key(username)
        if not request.event.wait(timeout):
            with self._cache_lock:
                self._requests.pop(request.request_id, None)
                if self._requests_by_user.get(username) is request:
                    self._requests_by_user.pop(username, None)
            raise ConnectionError(f"timed out requesting {username}'s public key")
        if request.error:
            raise ConnectionError(request.error)
        with self._cache_lock:
            cached = self._public_keys.get(username)
        if cached is None:
            raise ConnectionError(f"server did not return {username}'s public key")
        return cached

    def _request_public_key(self, username: str) -> KeyRequest:
        if not USERNAME_RE.fullmatch(username):
            raise ValueError("invalid username in key request")
        with self._cache_lock:
            existing = self._requests_by_user.get(username)
            if existing is not None:
                return existing
            request = KeyRequest(username=username, request_id=uuid.uuid4().hex)
            self._requests[request.request_id] = request
            self._requests_by_user[username] = request
        try:
            self._send(
                {
                    "type": "key_request",
                    "username": username,
                    "request_id": request.request_id,
                }
            )
        except OSError as exc:
            request.error = str(exc)
            request.event.set()
        return request

    def _receive_loop(self) -> None:
        try:
            while not self._closing.is_set():
                line = self._reader.readline(MAX_PACKET_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_PACKET_BYTES:
                    self._print("[connection rejected] server packet exceeded 1 MiB")
                    break
                try:
                    packet = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._print("[packet rejected] server sent invalid JSON")
                    continue
                if not isinstance(packet, dict):
                    self._print("[packet rejected] expected a JSON object")
                    continue
                self._dispatch(packet)
        except (ConnectionError, OSError, AttributeError):
            pass
        finally:
            if not self._closing.is_set():
                self._print("[disconnected] server connection closed")
            self._closing.set()
            self._registered.set()
            with self._cache_lock:
                outstanding = list(self._requests.values())
            for request in outstanding:
                request.error = "server connection closed"
                request.event.set()

    def _dispatch(self, packet: dict[str, Any]) -> None:
        packet_type = packet.get("type")
        if packet_type == "registered":
            self._registered.set()
        elif packet_type == "online_users":
            users = packet.get("users")
            if isinstance(users, list) and all(isinstance(user, str) for user in users):
                self.online_users = users
                self._print("[online] " + ", ".join(users))
        elif packet_type == "key_response":
            self._handle_key_response(packet)
        elif packet_type == "chat":
            self._handle_chat(packet)
        elif packet_type == "error":
            self._handle_error(packet)
        elif packet_type == "attack_armed":
            target = f" -> {packet.get('target')}" if packet.get("target") else ""
            self._print(
                f"[malicious server] {packet.get('action')}{target} armed for the next message"
            )
        elif packet_type == "attack_applied":
            self._print(f"[malicious server] applied {packet.get('action')}")
        else:
            self._print("[packet rejected] unknown server packet type")

    def _handle_key_response(self, packet: dict[str, Any]) -> None:
        request_id = packet.get("request_id")
        username = packet.get("username")
        with self._cache_lock:
            request = self._requests.get(request_id)
        if request is None or username != request.username:
            self._print("[key rejected] unsolicited or mismatched key response")
            return
        try:
            self._cache_public_key(username, packet.get("public_key"))
        except (KeyFileError, OSError, UnicodeError) as exc:
            request.error = f"public key for {username} rejected: {exc}"
        finally:
            with self._cache_lock:
                self._requests.pop(request.request_id, None)
                if self._requests_by_user.get(username) is request:
                    self._requests_by_user.pop(username, None)
            request.event.set()

        with self._cache_lock:
            pending = self._pending_messages.pop(username, [])
        if request.error is None:
            for message in pending:
                self._handle_chat(message)
        else:
            for _message in pending:
                self._print(f"[message rejected from {username}] {request.error}")

    def _cache_public_key(self, username: str, pem: Any) -> None:
        if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
            raise KeyFileError("invalid peer username")
        if not isinstance(pem, str):
            raise KeyFileError("server did not return PEM text")
        key = load_public_key(pem)
        received_fingerprint = public_key_fingerprint(key)
        pin_path = self.trusted_directory / f"{username}.pem"
        if pin_path.exists():
            pinned = load_public_key(pin_path.read_bytes())
            pinned_fingerprint = public_key_fingerprint(pinned)
            if received_fingerprint != pinned_fingerprint:
                raise KeyFileError(
                    "key changed from the pinned fingerprint; verify out of band before replacing it"
                )
        else:
            temporary_path = pin_path.with_suffix(".pem.tmp")
            temporary_path.write_text(public_key_to_pem(key), encoding="ascii")
            os.replace(temporary_path, pin_path)
            self._print(
                f"[key pinned] {username} SHA-256 {received_fingerprint}"
            )
        with self._cache_lock:
            self._public_keys[username] = key

    def _handle_chat(self, packet: dict[str, Any]) -> None:
        sender = packet.get("from")
        number = packet.get("message_number")
        if not isinstance(sender, str) or not USERNAME_RE.fullmatch(sender):
            self._print("[message rejected] invalid sender field")
            return
        if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
            self._print(f"[message rejected from {sender}] invalid message number")
            return

        with self._state_lock:
            highest = self._highest_received.get(sender, 0)
        if number <= highest:
            self._print(
                f"[replay rejected from {sender}] message #{number} is not newer than #{highest}"
            )
            return

        with self._cache_lock:
            sender_key = self._public_keys.get(sender)
            if sender_key is None:
                self._pending_messages.setdefault(sender, []).append(packet)
        if sender_key is None:
            try:
                self._request_public_key(sender)
            except (OSError, ValueError) as exc:
                self._print(f"[message rejected from {sender}] key lookup failed: {exc}")
            return

        try:
            plaintext = decrypt_and_verify(packet, self.private_key, sender_key)
        except SignatureVerificationError as exc:
            self._print(f"[message rejected from {sender}] {exc}")
            return
        except (DecryptionError, MessageFormatError, KeyFileError) as exc:
            self._print(f"[message rejected from {sender}] {exc}")
            return

        if packet.get("to") != self.username:
            self._print(
                f"[message rejected from {sender}] verified packet was addressed to {packet.get('to')}"
            )
            return
        with self._state_lock:
            highest = self._highest_received.get(sender, 0)
            if number <= highest:
                self._print(f"[replay rejected from {sender}] message #{number} was already accepted")
                return
            self._highest_received[sender] = number
            self._save_message_state()
        self._print(f"[verified signature] {sender} #{number}: {plaintext}")

    def _handle_error(self, packet: dict[str, Any]) -> None:
        message = str(packet.get("message", "server rejected the request"))
        request_id = packet.get("request_id")
        request: KeyRequest | None = None
        if isinstance(request_id, str):
            with self._cache_lock:
                request = self._requests.pop(request_id, None)
                if request and self._requests_by_user.get(request.username) is request:
                    self._requests_by_user.pop(request.username, None)
            if request:
                request.error = message
                request.event.set()
                with self._cache_lock:
                    pending = self._pending_messages.pop(request.username, [])
                for _message in pending:
                    self._print(
                        f"[message rejected from {request.username}] key lookup failed: {message}"
                    )
        if not self._registered.is_set():
            self._registration_error = message
            self._registered.set()
        if request is None:
            self._print(f"[server error: {packet.get('code', 'unknown')}] {message}")

    def _send(self, packet: dict[str, Any]) -> None:
        if self.sock is None or self._closing.is_set():
            raise ConnectionError("not connected")
        encoded = (json.dumps(packet, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MAX_PACKET_BYTES:
            raise ValueError("packet exceeds 1 MiB")
        with self._send_lock:
            self.sock.sendall(encoded)

    def _next_message_number(self) -> int:
        with self._state_lock:
            self._outgoing_number += 1
            self._save_message_state()
            return self._outgoing_number

    def _load_message_state(self) -> None:
        if not self._state_path.exists():
            return
        try:
            state = json.loads(self._state_path.read_text(encoding="utf-8"))
            if state.get("key_fingerprint") != self._own_fingerprint:
                return
            outgoing = state.get("outgoing", 0)
            received = state.get("highest_received", {})
            if isinstance(outgoing, int) and outgoing >= 0:
                self._outgoing_number = outgoing
            if isinstance(received, dict):
                self._highest_received = {
                    name: value
                    for name, value in received.items()
                    if isinstance(name, str)
                    and USERNAME_RE.fullmatch(name)
                    and isinstance(value, int)
                    and not isinstance(value, bool)
                    and value > 0
                }
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            self._print("[warning] message state was unreadable; starting with empty replay state")

    def _save_message_state(self) -> None:
        state = {
            "key_fingerprint": self._own_fingerprint,
            "outgoing": self._outgoing_number,
            "highest_received": self._highest_received,
        }
        temporary_path = self._state_path.with_suffix(".json.tmp")
        temporary_path.write_text(
            json.dumps(state, indent=2, sort_keys=True), encoding="utf-8"
        )
        os.replace(temporary_path, self._state_path)

    def _print(self, message: str) -> None:
        with self._print_lock:
            print(message, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="End-to-end encrypted chat client")
    parser.add_argument("username", help="chat username")
    parser.add_argument("--host", default="127.0.0.1", help="relay server host")
    parser.add_argument("--port", type=int, default=5050, help="relay server TCP port")
    parser.add_argument("--key-dir", default="keys", help="private/public key directory")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not USERNAME_RE.fullmatch(args.username):
        raise SystemExit(
            "Username must use 1-32 letters, numbers, dots, dashes, or underscores."
        )
    private_path = Path(args.key_dir) / f"{args.username}_private.pem"
    password = getpass.getpass(f"Password for {args.username}'s private key: ")
    if not private_path.exists():
        confirmation = getpass.getpass("Confirm new private-key password: ")
        if password != confirmation:
            raise SystemExit("Passwords did not match; no key was created.")
    try:
        private_key, public_key = load_or_create_keypair(
            args.username, password, args.key_dir
        )
    except KeyFileError as exc:
        raise SystemExit(f"Key error: {exc}") from exc

    client = SecureChatClient(
        args.username,
        private_key,
        public_key,
        args.host,
        args.port,
        args.key_dir,
    )
    try:
        client.connect()
        client.run_interactive()
    except (ConnectionError, OSError) as exc:
        raise SystemExit(f"Connection failed: {exc}") from exc
    finally:
        client.close()


if __name__ == "__main__":
    main()
