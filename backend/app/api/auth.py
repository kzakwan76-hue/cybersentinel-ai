"""Registration and login endpoints."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import orm
from app.database import get_db
from app.deps import get_current_user
from app.schemas import Token, UserCreate, UserOut
from app.security import DUMMY_HASH, create_access_token, hash_password, verify_password

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
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """The form's 'username' field holds the email address."""
    user = db.scalar(select(orm.User).where(orm.User.email == form.username.lower()))
    # Always run one hash check, so response time doesn't reveal whether the email exists.
    password_ok = verify_password(form.password, user.password_hash if user else DUMMY_HASH)
    if user is None or not password_ok:
        logger.warning("Failed login attempt")
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Token(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
def me(current_user: orm.User = Depends(get_current_user)):
    return current_user