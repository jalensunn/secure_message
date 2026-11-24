"""
Secure message demo (single machine, no network).

User A (sender) -> User B (receiver)

SENDER (User A):
  1. Type a message
  2. Generate a random AES-256 key and encrypt the message (AES-GCM)
  3. Encrypt the AES key with User B's PUBLIC key (RSA-OAEP)
  4. Hash the message (SHA-256)
  5. Sign the hash with User A's PRIVATE key (RSA-PSS)

RECEIVER (User B):
  1. Decrypt the AES key with User B's PRIVATE key
  2. Decrypt the message with the AES key
  3. Hash the decrypted message (SHA-256)
  4. Verify the signature with User A's PUBLIC key

Requires:  pip install cryptography
Run:       python secure_message.py
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto_module import SecureChatError, decrypt_and_verify, encrypt_and_sign


def new_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def main() -> None:
    alice_private = new_private_key()
    bob_private = new_private_key()
    header = {
        "from": "Alice",
        "to": "Bob",
        "message_number": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
    }
    plaintext = input("Message from Alice to Bob: ")
    packet = encrypt_and_sign(
        plaintext, alice_private, bob_private.public_key(), header
    )
    recovered = decrypt_and_verify(packet, bob_private, alice_private.public_key())
    print(f"Verified and decrypted: {recovered}")

    tampered = copy.deepcopy(packet)
    tampered["message_number"] += 1
    try:
        decrypt_and_verify(tampered, bob_private, alice_private.public_key())
    except SecureChatError as exc:
        print(f"Tamper demonstration correctly rejected: {exc}")


if __name__ == "__main__":
    main()
