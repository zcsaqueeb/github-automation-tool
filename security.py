"""
security.py — Encrypt-at-rest helpers for sensitive user data.

GitHub tokens and AI API keys are never stored in plaintext on disk.
This module wraps the ``cryptography`` package's Fernet symmetric cipher
(AES-128-CBC + HMAC-SHA256) so the rest of the application can call
``encrypt()`` / ``decrypt()`` without coupling to any key-management detail.

Setup
-----
Generate a key once and store it in your ``.env`` as ``DATA_ENCRYPTION_KEY``:

    python -c "from security import generate_key; print(generate_key())"

If the variable is absent the bot will start but warn loudly, and secrets
will be stored in plaintext — always set it in production.

Backward compatibility
----------------------
Values that do not carry the ``enc:`` prefix are returned as-is.  This means
existing plaintext records (from installs before encryption was added) keep
working after you enable the key.
"""

from __future__ import annotations

from functools import lru_cache
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

import config


def _provision_key() -> str:
    """Return the configured key or create an installation-local key safely.

    Production deployments can still inject ``DATA_ENCRYPTION_KEY`` through a
    secrets manager.  Local installations do not need an admin to generate,
    copy, or know a key: a random key is created once in a private sidecar
    file. It is intentionally separate from ``users.json`` and never exposed
    through bot commands or logs.
    """
    if config.DATA_ENCRYPTION_KEY:
        return config.DATA_ENCRYPTION_KEY
    key_path = f"{config.DB_FILE}.key"
    try:
        if os.path.exists(key_path):
            with open(key_path, "r", encoding="ascii") as key_file:
                return key_file.read().strip()
        key = Fernet.generate_key().decode("ascii")
        # O_EXCL prevents two concurrent bot processes from replacing a key.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as key_file:
            key_file.write(key)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass  # Windows ACLs control access instead of POSIX permissions.
        return key
    except FileExistsError:
        with open(key_path, "r", encoding="ascii") as key_file:
            return key_file.read().strip()
    except OSError as exc:
        raise RuntimeError(f"Could not provision the database encryption key: {exc}") from exc


# Resolve before config.validate() runs in bot.py. This lets a local install
# be secure by default while managed deployments retain their secret-manager
# supplied key.
config.DATA_ENCRYPTION_KEY = _provision_key()


# ── Key management ───────────────────────────────────────────────────────

def generate_key() -> str:
    """Return a new URL-safe base64-encoded 32-byte Fernet key as a string.

    Call this **once** per installation, then store the output in ``.env``
    as ``DATA_ENCRYPTION_KEY``.  Changing the key after data has been written
    will permanently break decryption of existing records.
    """
    return Fernet.generate_key().decode()


@lru_cache(maxsize=1)
def _cipher() -> Optional[Fernet]:
    """Lazily build and cache the Fernet cipher from the configured key.

    Returns *None* when ``DATA_ENCRYPTION_KEY`` is absent or malformed,
    which causes the encrypt/decrypt helpers to degrade gracefully instead
    of crashing the bot.
    """
    if not config.DATA_ENCRYPTION_KEY:
        return None
    try:
        return Fernet(config.DATA_ENCRYPTION_KEY.encode())
    except Exception:
        return None


def is_enabled() -> bool:
    """Return ``True`` when a valid encryption key is configured and active."""
    return _cipher() is not None


# ── Public helpers ────────────────────────────────────────────────────────

def encrypt(plaintext: Optional[str]) -> Optional[str]:
    """Encrypt *plaintext* and return an ``enc:``-prefixed ciphertext string.

    Behaviour:
    - Falsy values (``None``, ``""``) are returned unchanged.
    - If no key is configured the value is returned in plaintext (with a
      startup warning emitted by ``config.validate()``).
    """
    if not plaintext:
        return plaintext
    cipher = _cipher()
    if cipher is None:
        return plaintext
    return "enc:" + cipher.encrypt(plaintext.encode()).decode()


def decrypt(value: Optional[str]) -> Optional[str]:
    """Decrypt a value produced by :func:`encrypt`.

    Behaviour:
    - Falsy values are returned unchanged.
    - Values **without** the ``enc:`` prefix are returned as-is (backward
      compatibility with plaintext records from older installs).
    - Returns ``None`` if the ciphertext is invalid or the key has changed.
    """
    if not value:
        return value
    if not value.startswith("enc:"):
        # Legacy plaintext record — pass through so old installs keep working.
        return value
    cipher = _cipher()
    if cipher is None:
        # Encrypted value present but no key available — cannot recover.
        return None
    try:
        return cipher.decrypt(value[4:].encode()).decode()
    except InvalidToken:
        return None
