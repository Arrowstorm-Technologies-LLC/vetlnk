"""Encrypted export/import of stored API keys, for moving them between devices
without ever pasting a bare key or shipping a plaintext file around.

File layout (binary): magic(5) + version(1) + salt(16) + nonce(12) + ciphertext.
The plaintext inside the ciphertext is a small JSON payload of
{"version": 1, "keys": {provider_id: key}}. AES-256-GCM gives both
confidentiality and integrity, so a wrong passphrase or a tampered/corrupted
file fails decryption outright instead of silently returning garbage.
"""

from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_MAGIC = b"VLNK1"
_VERSION = 1
_SALT_LEN = 16
_NONCE_LEN = 12
_KEY_LEN = 32
# scrypt cost parameters for a passphrase-derived key: N=2**15 lands around
# 100-300ms on typical hardware for this one small file, well past the
# brute-force-resistance floor recommended for interactive password KDFs.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1


class KeyFileError(ValueError):
    """Malformed file, wrong passphrase, or unsupported version."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=_KEY_LEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_export(keys: dict[str, str], passphrase: str) -> bytes:
    """Serialize `keys` (provider_id -> API key) into an encrypted file's bytes."""
    payload = json.dumps({"version": _VERSION, "keys": keys}).encode("utf-8")
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    derived = _derive_key(passphrase, salt)
    ciphertext = AESGCM(derived).encrypt(nonce, payload, None)
    return _MAGIC + bytes([_VERSION]) + salt + nonce + ciphertext


def decrypt_import(data: bytes, passphrase: str) -> dict[str, str]:
    """Recover the provider_id -> API key mapping from an exported file's bytes."""
    header_len = len(_MAGIC) + 1 + _SALT_LEN + _NONCE_LEN
    if len(data) < header_len or data[: len(_MAGIC)] != _MAGIC:
        raise KeyFileError("Not a vetlnk key file.")

    offset = len(_MAGIC)
    version = data[offset]
    offset += 1
    if version != _VERSION:
        raise KeyFileError(f"Unsupported key file version: {version}.")

    salt = data[offset : offset + _SALT_LEN]
    offset += _SALT_LEN
    nonce = data[offset : offset + _NONCE_LEN]
    offset += _NONCE_LEN
    ciphertext = data[offset:]

    derived = _derive_key(passphrase, salt)
    try:
        payload = AESGCM(derived).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise KeyFileError("Incorrect passphrase, or the file is corrupted/tampered.") from exc

    try:
        parsed = json.loads(payload)
        keys = parsed["keys"]
        if not isinstance(keys, dict) or not all(isinstance(v, str) for v in keys.values()):
            raise TypeError
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise KeyFileError("Key file content is malformed.") from exc

    return keys
