import os
import re
import base64
import hashlib
import secrets
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from django.conf import settings

# Prefix to identify encrypted strings
ENC_PREFIX = "enc:fernet:"


def get_encryption_key() -> bytes:
    """
    Derive a 32-byte URL-safe base64 Fernet key from settings.SECRET_KEY
    or a dedicated ENCRYPTION_KEY environment variable.
    """
    custom_key = os.environ.get("ENCRYPTION_KEY")
    if custom_key:
        return custom_key.strip().encode("utf-8")
    
    # Derive deterministic key from SECRET_KEY
    secret = getattr(settings, "SECRET_KEY", "fallback-secret-for-dev-only")
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(plaintext: Optional[str]) -> str:
    """
    Encrypt sensitive plaintext credentials at rest.
    Idempotent: if already encrypted, returns as-is.
    """
    if not plaintext:
        return ""
    
    # Do not re-encrypt environment variable or profile references
    if plaintext.startswith("env:") or plaintext.startswith("profile:"):
        return plaintext
    
    if plaintext.startswith(ENC_PREFIX):
        return plaintext

    fernet = Fernet(get_encryption_key())
    encrypted = fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    return f"{ENC_PREFIX}{encrypted}"


def decrypt_secret(ciphertext: Optional[str]) -> str:
    """
    Decrypt credentials encrypted with encrypt_secret().
    If not encrypted (e.g. legacy plain text or env:/profile:), returns plaintext.
    """
    if not ciphertext:
        return ""
    
    if ciphertext.startswith("env:") or ciphertext.startswith("profile:"):
        return ciphertext
    
    if not ciphertext.startswith(ENC_PREFIX):
        return ciphertext

    raw_token = ciphertext[len(ENC_PREFIX):]
    try:
        fernet = Fernet(get_encryption_key())
        return fernet.decrypt(raw_token.encode("utf-8")).decode("utf-8")
    except Exception as e:
        # Log decryption error and return original (safe fallback)
        import logging
        logging.getLogger("core_security").error(f"Failed to decrypt secret: {e}")
        return ciphertext


def mask_connection_string(conn_str: Optional[str]) -> str:
    """
    Mask passwords in connection strings for safe display in UI and API responses.
    e.g. postgresql://user:password@host:5432/db -> postgresql://user:****@host:5432/db
    """
    if not conn_str:
        return ""
    
    if conn_str.startswith("profile:"):
        return conn_str
    
    if conn_str.startswith("env:"):
        return conn_str

    # Decrypt if encrypted before masking
    raw = decrypt_secret(conn_str)

    # Standard URI pattern: scheme://user:password@host
    pattern = r"(://[^:]+:)([^@]+)(@)"
    masked = re.sub(pattern, r"\1****\3", raw)
    return masked


def sanitize_sql_identifier(identifier: str, dialect: str = "postgres") -> str:
    """
    Sanitize and safely quote table, schema, and column names to prevent SQL injection.
    Only allows valid alphanumeric identifiers containing letters, numbers, and underscores.
    """
    if not identifier:
        raise ValueError("SQL identifier cannot be empty.")
    
    # Strip any accidental whitespace
    ident = identifier.strip()
    
    # Strict regex check for identifier names
    if not re.match(r"^[a-zA-Z0-9_]+$", ident):
        raise ValueError(
            f"Invalid SQL identifier {ident!r}. Identifiers must only contain letters, numbers, and underscores."
        )
    
    d = dialect.lower() if dialect else "postgres"
    if d in ("mysql", "sqlite"):
        return f"`{ident}`"
    # Postgres, Snowflake, Oracle, SQL Server standard ANSI quoting
    return f'"{ident}"'


def generate_api_key(prefix: str = "sg_live") -> Tuple[str, str, str]:
    """
    Generate a cryptographically secure API key for CI/CD and programmatic access.
    Returns:
        (raw_key, key_id, key_hash)
        - raw_key: Sent to user once (e.g. sg_live_32hexchars)
        - key_id: Public identifier (e.g. sg_live_8hexchars)
        - key_hash: Stored in DB (SHA-256)
    """
    rand = secrets.token_hex(24)
    raw_key = f"{prefix}_{rand}"
    key_id = raw_key[:16]
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return raw_key, key_id, key_hash


def hash_api_key(raw_key: str) -> str:
    """Hash an API key with SHA-256 for database lookup."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()
