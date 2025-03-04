from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from services.auth import Auth, UserAuthData, get_auth, HashHelper
from sqlmodel import Session, select
from data.models.user import User
from data.database import get_db, engine
from typing import Sequence
import re

user_router = APIRouter(prefix="/user")


class LoginPayload(BaseModel):
    username_or_email: str
    password: str


@user_router.get("/")
def get_users(sesh: Session = Depends(get_db)) -> Sequence[User]:
    return sesh.exec(select(User)).all()


@user_router.post("/login")
def login(
        loginPayload: LoginPayload,
        auth: Auth = Depends(get_auth),
        sesh: Session = Depends(get_db),
) -> str:
    user = sesh.exec(
        select(User).where(
            (User.username == loginPayload.username_or_email)
            | (User.email == loginPayload.username_or_email)
        )
    ).first()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if HashHelper.verify(loginPayload.password, user.password_hash) is False:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    user_data = UserAuthData(username=user.username, user_id=user.id, role=user.role)

    token = auth.create_token(user_data, False)

    return token


class NewUserPayload(BaseModel):
    username: str
    email: str
    password: str


@user_router.post("/create")
def create_user(
        new_user_data: NewUserPayload,
        sesh: Session = Depends(get_db),
):
    errors = []
    if sesh.exec(select(User).where(User.username == new_user_data.username)).first() is not None:
        errors.append("Username already exists")

    if sesh.exec(select(User).where(User.email == new_user_data.email)).first() is not None:
        errors.append("Email already exists")

    def is_valid_email(email: str) -> bool:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

    if not is_valid_email(new_user_data.email):
        errors.append("Invalid email. Email must be in the format of 1Dlq9@example.com")

    if is_valid_email(new_user_data.username):
        errors.append("Username cannot be an email address")

    def is_valid_username(username: str) -> bool:
        username_pattern = r"^[a-zA-Z0-9_]{3,20}$"
        return bool(re.match(username_pattern, username))

    if not is_valid_username(new_user_data.username):
        errors.append(
            "Invalid username. Username must be between 3 and 20 characters and can only contain letters, numbers, and underscores."
        )

    def is_valid_password(password: str) -> list[str]:
        issues = []

        if len(password) < 8:
            issues.append("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", password):
            issues.append("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", password):
            issues.append("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", password):
            issues.append("Password must contain at least one digit.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            issues.append(
                'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>).'
            )

        return issues

    errors = errors + is_valid_password(new_user_data.password)

    if len(errors) > 0:
        raise HTTPException(status_code=400, detail=errors)

    user = User(
        username=new_user_data.username,
        email=new_user_data.email,
        password_hash=HashHelper.hash(new_user_data.password),
    )

    sesh.add(user)
    sesh.commit()
