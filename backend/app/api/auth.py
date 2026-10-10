"""Registration and login endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import orm
from app.database import get_db
from app.deps import get_current_user
from app.schemas import Token, UserCreate, UserOut
from app.security import DUMMY_HASH, create_access_token, hash_password, verify_password
from app.services.throttle import clear_failures, record_failure, seconds_until_allowed

logger = logging.getLogger("cybersentinel.auth")
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    user = orm.User(email=payload.email.lower(), password_hash=hash_password(payload.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:  # the email column is unique
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered.")
    db.refresh(user)
    logger.info("Registered user id=%d", user.id)
    return user


@router.post("/login", response_model=Token)
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """The form's 'username' field holds the email address."""
    email = form.username.strip().lower()[:255]
    ip = request.client.host if request.client else "unknown"

    # Check BEFORE verifying the password, so a locked-out client can't keep testing guesses.
    wait = seconds_until_allowed(db, email, ip)
    if wait:
        logger.warning("Login throttled for %d seconds (ip=%s)", wait, ip)
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(wait)},
        )

    user = db.scalar(select(orm.User).where(orm.User.email == email))
    # Always run one hash check, so response time doesn't reveal whether the email exists.
    password_ok = verify_password(form.password, user.password_hash if user else DUMMY_HASH)
    if user is None or not password_ok:
        record_failure(db, email, ip)
        logger.warning("Failed login attempt (ip=%s)", ip)
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    clear_failures(db, email, ip)
    return Token(access_token=create_access_token(user.id))

@router.get("/me", response_model=UserOut)
def me(current_user: orm.User = Depends(get_current_user)):
    return current_user