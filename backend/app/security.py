"""Password hashing and JWT access tokens."""

from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash

from app.config import ACCESS_TOKEN_MINUTES, SECRET_KEY

ALGORITHM = "HS256"

# Argon2 is a modern password-hashing algorithm: deliberately slow and salted,
# so stolen hashes are very hard to crack.
_password_hasher = PasswordHash.recommended()

# Used to keep login timing similar whether or not the email exists.
DUMMY_HASH: str = _password_hasher.hash("not-a-real-password")


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return _password_hasher.verify(password, password_hash)


def create_access_token(user_id: int) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode({"sub": str(user_id), "exp": expires}, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> int | None:
    """Return the user id inside a valid token, or None if invalid or expired."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        return None