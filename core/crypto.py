"""
BreachScope — Crypto Utils
Hashing, OTP generation, JWT tokens
"""
import hashlib
import secrets
import string
import json
from datetime import datetime, timezone, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import jwt
from .config import settings

# Argon2 hasher
ph = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
)


def sha256_hash(data: str) -> str:
    """SHA-256 hash of a string."""
    return hashlib.sha256(data.encode()).hexdigest()


def sha1_hash(data: str) -> str:
    """SHA-1 hash — HIBP-style for password cross-checking."""
    return hashlib.sha1(data.encode()).hexdigest()


def argon2_hash(password: str) -> str:
    """Argon2 hash of a password."""
    return ph.hash(password)


def verify_argon2(hashed: str, password: str) -> bool:
    """Verify an Argon2 hash against a plaintext password."""
    try:
        return ph.verify(hashed, password)
    except VerifyMismatchError:
        return False


def generate_otp(length: int = None) -> str:
    """Generate a numeric OTP code."""
    length = length or settings.otp_length
    digits = string.digits
    return "".join(secrets.choice(digits) for _ in range(length))


def generate_api_key() -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)


def create_jwt_token(data: dict, ttl: int = None) -> str:
    """Create a JWT token."""
    ttl = ttl or settings.jwt_ttl_seconds
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    payload["iat"] = datetime.now(timezone.utc)
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def verify_jwt_token(token: str) -> dict:
    """Verify and decode a JWT token."""
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


def normalize_email(email: str) -> str:
    """Normalize email — lowercase, strip whitespace."""
    return email.strip().lower()


def normalize_phone(phone: str) -> str:
    """Normalize phone — strip non-digits."""
    return "".join(c for c in phone if c.isdigit())


def normalize_username(username: str) -> str:
    """Normalize username — lowercase, strip."""
    return username.strip().lower()


def record_hash(email: str = "", username: str = "", phone: str = "",
                password: str = "", extra: dict = None) -> str:
    """Create a hash of a complete record for deduplication."""
    data = json.dumps({
        "e": email or "",
        "u": username or "",
        "p": phone or "",
        "pw": sha1_hash(password) if password else "",
        "x": extra or {}
    }, sort_keys=True)
    return sha256_hash(data)
