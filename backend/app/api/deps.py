"""Reusable FastAPI dependencies: who is calling, and are they allowed?

RBAC lesson: authentication = "who are you?", authorization = "what may you do?".
`require_roles("analyst", "admin")` turns that policy into one line per route.
"""

from collections.abc import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        user_id = decode_access_token(token)
    except (jwt.PyJWTError, ValueError):
        raise _UNAUTHENTICATED from None
    user = db.get(User, user_id)
    if user is None:
        raise _UNAUTHENTICATED
    # The role comes from the database, not the token, so demotions apply immediately.
    return user


def require_roles(*allowed: str) -> Callable[[User], User]:
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return checker


# Readable names for the three permission levels used across routes.
any_user = get_current_user
analyst_or_admin = require_roles("analyst", "admin")
admin_only = require_roles("admin")
