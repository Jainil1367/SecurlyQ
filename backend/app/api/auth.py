import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.core.rate_limit import SlidingWindowRateLimiter
from app.core.security import (
    burn_password_check,
    create_access_token,
    hash_password,
    verify_password,
)
from app.db.session import get_db
from app.models import User
from app.schemas.user import RegisterIn, TokenOut, UserOut

logger = logging.getLogger("securlyq.auth")
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

_settings = get_settings()
login_limiter = SlidingWindowRateLimiter(
    max_events=_settings.login_max_failures, window_seconds=_settings.login_window_seconds
)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, db: Session = Depends(get_db)) -> User:
    """Create an account. The very first account becomes the admin; the rest are analysts.

    With OPEN_REGISTRATION=false (production) only that first bootstrap account can self-register.
    """
    is_first = (db.scalar(select(func.count(User.id))) or 0) == 0
    if not is_first and not get_settings().open_registration:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Registration is closed. Ask an administrator for an account.")
    user = User(
        email=body.email.lower(),
        hashed_password=hash_password(body.password),
        role="admin" if is_first else "analyst",
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered") from None
    logger.info("user registered id=%s role=%s", user.id, user.role)
    return user


@router.post("/login", response_model=TokenOut)
def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> TokenOut:
    email = form.username.lower()
    client_ip = request.client.host if request.client else "unknown"
    key = f"{client_ip}:{email}"

    if login_limiter.is_blocked(key):
        logger.warning("login rate-limited key=%s", key)
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed attempts. Try again later.",
            headers={"Retry-After": str(login_limiter.retry_after(key))},
        )

    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        burn_password_check(form.password)  # equalize timing with the "wrong password" path
    if user is None or not verify_password(form.password, user.hashed_password):
        login_limiter.record(key)
        logger.warning("login failed email=%s ip=%s", email, client_ip)
        # One generic message: don't reveal whether the email exists.
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    login_limiter.reset(key)
    return TokenOut(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
