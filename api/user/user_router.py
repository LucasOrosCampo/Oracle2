from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from services.auth import Auth, get_auth
from sqlalchemy.orm import Session
from data.database import get_db_session
from data.models.user import User

user_router = APIRouter(prefix="/user")


class LoginPayload(BaseModel):
    username_or_email: str
    password: str


@user_router.post("/login")
def login(
    loginPayload: LoginPayload,
    auth: Auth = Depends(get_auth),
    sesh: Session = Depends(get_db_session),
):
    user = (
        sesh.query(User).filter(User.username == loginPayload.username_or_email).all()
    )
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user
