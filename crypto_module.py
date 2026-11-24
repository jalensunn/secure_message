"""
Only clients import this module.  The relay server never receives a private
key or a plaintext AES key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SEPARATOR = "|"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)
PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


class SecureChatError(Exception):
    """for user-displayable secure-chat errors."""
class MessageFormatError(SecureChatError):
    """The packet is missing or contains malformed data."""
class SignatureVerificationError(SecureChatError):
    """The RSA signature does not match the signed packet fields."""
class DecryptionError(SecureChatError):
    """The AES key or ciphertext could not be decrypted."""
class KeyFileError(SecureChatError):
    """A local key file could not be loaded or created."""

def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")

def _b64decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise MessageFormatError(f"{field} must be base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MessageFormatError(f"{field} is not valid base64") from exc

def _validate_rsa_private_key(key: Any) -> rsa.RSAPrivateKey:
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise KeyFileError("private key must be an RSA key of at least 2048 bits")
    return key

def _validate_rsa_public_key(key: Any) -> rsa.RSAPublicKey:
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise KeyFileError("public key must be an RSA key of at least 2048 bits")
    return key

def _header_values(message: Mapping[str, Any]) -> list[str]:
    sender = message.get("from")
    recipient = message.get("to")
    message_number = message.get("message_number")
    timestamp = message.get("timestamp")

    if not isinstance(sender, str) or not USERNAME_RE.fullmatch(sender):
        raise MessageFormatError("invalid sender username")
    if not isinstance(recipient, str) or not USERNAME_RE.fullmatch(recipient):
        raise MessageFormatError("invalid recipient username")
    if isinstance(message_number, bool) or not isinstance(message_number, int):
        raise MessageFormatError("message_number must be an integer")
    if message_number <= 0:
        raise MessageFormatError("message_number must be positive")
    if not isinstance(timestamp, str) or not timestamp or len(timestamp) > 64:
        raise MessageFormatError("invalid timestamp")
    if SEPARATOR in timestamp:
        raise MessageFormatError("timestamp contains the reserved separator")

    return [sender, recipient, str(message_number), timestamp]

def _associated_data(message: Mapping[str, Any]) -> bytes:
    """Authenticate the clear routing header with AES-GCM as defense in depth."""
    return SEPARATOR.join(_header_values(message)).encode("utf-8")

def _signature_digest(message: Mapping[str, Any]) -> bytes:
    """Hash the seven assignment-required fields in their required order."""
    values = _header_values(message)
    for field in ("encrypted_key", "nonce", "ciphertext"):
        value = message.get(field)
        if not isinstance(value, str) or not value:
            raise MessageFormatError(f"missing {field}")
        if SEPARATOR in value:
            raise MessageFormatError(f"{field} contains the reserved separator")
        values.append(value)
    return hashlib.sha256(SEPARATOR.join(values).encode("utf-8")).digest()

def encrypt_and_sign(
    plaintext: str,
    sender_private_key: rsa.RSAPrivateKey,
    recipient_public_key: rsa.RSAPublicKey,
    header: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(plaintext, str):
        raise TypeError("plaintext must be a string")
    sender_private_key = _validate_rsa_private_key(sender_private_key)
    recipient_public_key = _validate_rsa_public_key(recipient_public_key)

    packet: dict[str, Any] = {
        "type": "chat",
        "from": header.get("from"),
        "to": header.get("to"),
        "message_number": header.get("message_number"),
        "timestamp": header.get("timestamp"),
    }
    aad = _associated_data(packet)
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    encrypted_key = recipient_public_key.encrypt(aes_key, OAEP)

    packet.update(
        encrypted_key=_b64encode(encrypted_key),
        nonce=_b64encode(nonce),
        ciphertext=_b64encode(ciphertext),
    )
    digest = _signature_digest(packet)
    packet["signature"] = _b64encode(
        sender_private_key.sign(digest, PSS, utils.Prehashed(hashes.SHA256()))
    )
    return packet


def decrypt_and_verify(
    encrypted_message: Mapping[str, Any],
    recipient_private_key: rsa.RSAPrivateKey,
    sender_public_key: rsa.RSAPublicKey,
) -> str:
    recipient_private_key = _validate_rsa_private_key(recipient_private_key)
    sender_public_key = _validate_rsa_public_key(sender_public_key)

    encrypted_key = _b64decode(encrypted_message.get("encrypted_key"), "encrypted_key")
    nonce = _b64decode(encrypted_message.get("nonce"), "nonce")
    ciphertext = _b64decode(encrypted_message.get("ciphertext"), "ciphertext")
    signature = _b64decode(encrypted_message.get("signature"), "signature")
    if len(nonce) != 12:
        raise MessageFormatError("nonce must be exactly 12 bytes")

    digest = _signature_digest(encrypted_message)
    try:
        sender_public_key.verify(
            signature, digest, PSS, utils.Prehashed(hashes.SHA256())
        )
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "signature invalid; the sender or signed packet fields were altered"
        ) from exc

    try:
        aes_key = recipient_private_key.decrypt(encrypted_key, OAEP)
    except ValueError as exc:
        raise DecryptionError(
            "AES key could not be decrypted; this message was not encrypted for this client"
        ) from exc
    if len(aes_key) != 32:
        raise DecryptionError("decrypted AES key is not 256 bits")

    try:
        plaintext = AESGCM(aes_key).decrypt(
            nonce, ciphertext, _associated_data(encrypted_message)
        )
    except InvalidTag as exc:
        raise DecryptionError("AES-GCM authentication failed; ciphertext was altered") from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecryptionError("decrypted message is not valid UTF-8 text") from exc


def public_key_to_pem(public_key: rsa.RSAPublicKey) -> str:
    public_key = _validate_rsa_public_key(public_key)
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_public_key(pem: str | bytes) -> rsa.RSAPublicKey:
    if isinstance(pem, str):
        pem = pem.encode("ascii")
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise KeyFileError("invalid public-key PEM") from exc
    return _validate_rsa_public_key(key)


def public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = _validate_rsa_public_key(public_key).public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def load_or_create_keypair(
    username: str, password: str, key_directory: str | Path = "keys"
) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    if not USERNAME_RE.fullmatch(username):
        raise KeyFileError("username must use 1-32 letters, numbers, dots, dashes, or underscores")
    if not password:
        raise KeyFileError("private-key password must not be empty")

    directory = Path(key_directory)
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / f"{username}_private.pem"
    public_path = directory / f"{username}_public.pem"
    password_bytes = password.encode("utf-8")

    if private_path.exists():
        try:
            private_key = serialization.load_pem_private_key(
                private_path.read_bytes(), password=password_bytes
            )
        except (ValueError, TypeError) as exc:
            raise KeyFileError("could not unlock the private key (wrong password or damaged file)") from exc
        private_key = _validate_rsa_private_key(private_key)
    else:
        if public_path.exists():
            raise KeyFileError(
                f"{public_path} exists without its private key; move it aside before regenerating"
            )
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password_bytes),
        )
        temporary_path = private_path.with_suffix(".pem.tmp")
        with open(temporary_path, "wb") as stream:
            stream.write(private_bytes)
        try:
            os.chmod(temporary_path, 0o600)
        except OSError:
            pass
        os.replace(temporary_path, private_path)

    public_key = private_key.public_key()
    public_path.write_text(public_key_to_pem(public_key), encoding="ascii")
    return private_key, public_key
