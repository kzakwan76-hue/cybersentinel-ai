"""Shared FastAPI dependencies."""

from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app import orm
from app.database import get_db
from app.security import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> orm.User:
    """Return the logged-in user, or reply 401 if the token is missing, bad or expired."""
    user_id = decode_access_token(token)
    user = db.get(orm.User, user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user