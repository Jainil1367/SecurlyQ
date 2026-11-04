"""Password hashing and JSON Web Tokens.

Lessons:
* NEVER store passwords. Store a slow, salted hash (Argon2). "Slow" is the point:
  it makes brute-forcing a stolen database very expensive.
* A JWT is a signed note saying "this is user 42, valid until 3:00pm". The server
  can verify the signature without a database lookup, but cannot revoke it early,
  so we keep lifetimes short and re-load the user (and their role) from the
  database on every request.
"""

from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import get_settings

_hasher = PasswordHasher()
# Used to burn the same CPU time when a login names an unknown email, so response
# timing doesn't reveal which emails are registered.
_DUMMY_HASH = _hasher.hash("securlyq-dummy-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except (VerificationError, InvalidHashError):
        return False


def burn_password_check(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def create_access_token(user_id: int, now: datetime | None = None) -> str:
    settings = get_settings()
    issued = now or datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "iat": issued,
        "exp": issued + timedelta(minutes=settings.access_token_minutes),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> int:
    """Return the user id, or raise jwt.PyJWTError for any invalid/expired token."""
    settings = get_settings()
    payload = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],  # pin the algorithm; never trust the token's header
        options={"require": ["exp", "sub"]},
    )
    return int(payload["sub"])
