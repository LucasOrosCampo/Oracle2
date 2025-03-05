from time import sleep
from data.database import get_db
from data.models.user import User
from sqlmodel import Session
from fastapi import HTTPException, security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from services.environment_manager import get_environment, Environment
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi import Depends, Header
from passlib.context import CryptContext
from dataclasses import dataclass, asdict


class HashHelper:

    HASHER: CryptContext = CryptContext(
        schemes=["argon2"],
        deprecated="auto",
        argon2__time_cost=6,
        argon2__memory_cost=1024,
    )

    @staticmethod
    def hash(password: str) -> str:
        return HashHelper.HASHER.hash(password)

    @staticmethod
    def verify(plain_password: str, hashed_password: str) -> bool:
        return HashHelper.HASHER.verify(plain_password, hashed_password)


@dataclass
class UserAuthData:
    username: str
    user_id: int


@dataclass
class AuthData:
    user_auth_data: UserAuthData
    exp: int = 0
    iat: int = 0


TRUSTED_CLIENT_EXPIRATION_MINUTES = 10080
UNTRUSTED_CLIENT_EXPIRATION_MINUTES = 120


class Auth:

    Algorithm: str = "HS256"

    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def create_token(self, data: UserAuthData, trusted_client: bool) -> str:

        token_expire_minutes = (
            TRUSTED_CLIENT_EXPIRATION_MINUTES
            if trusted_client
            else UNTRUSTED_CLIENT_EXPIRATION_MINUTES
        )

        expire = datetime.now() + timedelta(minutes=token_expire_minutes)
        expire = int(expire.timestamp())

        token_data = AuthData(data, expire, int(datetime.now().timestamp()))

        return jwt.encode(asdict(token_data), self.secret_key, algorithm=Auth.Algorithm)

    def decode_token(self, token: str) -> UserAuthData:
        """Check if the token is valid and if it belongs to the user"""

        try:
            data = jwt.decode(token, self.secret_key, algorithms=[Auth.Algorithm])
            return UserAuthData(**data["user_auth_data"])

        except JWTError:
            raise HTTPException(
                status_code=401,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )


def get_auth(environment: Environment = Depends(get_environment)) -> Auth:
    return Auth(environment.secret_key)

security = HTTPBearer()

def get_user(authorization: HTTPAuthorizationCredentials = Depends(security), auth: Auth = Depends(get_auth), db: Session = Depends(get_db)) -> User:
    token = authorization.credentials
    user_auth_data = auth.decode_token(token)

    user = db.get(User, user_auth_data.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return user

def get_admin(user: User = Depends(get_user)) -> User:
    if not user.admin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return user
