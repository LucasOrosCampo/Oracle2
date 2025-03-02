from time import sleep
from services.environment_manager import get_environment, Environment
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi import Depends
from passlib.context import CryptContext
from dataclasses import dataclass, asdict

class HashHelper:
    def __init__(self):
        self.pwd_context = CryptContext(
            schemes=["argon2"],
            deprecated="auto",
            argon2__time_cost=6,
            argon2__memory_cost=1024,
        )

    def hash(self, password: str) -> str:
        return self.pwd_context.hash(password)

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        return self.pwd_context.verify(plain_password, hashed_password)

def get_hash_helper() -> HashHelper:
    return HashHelper()

@dataclass
class UserAuthData:
    username: str
    user_id: int
    role: int


@dataclass
class AuthData:
    user_auth_data: UserAuthData
    exp: int = 0
    iat: int = 0


TRUSTED_CLIENT_EXPIRATION_MINUTES = 10080
UNTRUSTED_CLIENT_EXPIRATION_MINUTES = 120


class Auth:
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

        return jwt.encode(asdict(token_data), self.secret_key, algorithm="HS256")

    def decode_token(self, user: UserAuthData, token: str) -> UserAuthData | None:
        """Check if the token is valid and if it belongs to the user"""

        try:
            data = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            return UserAuthData(**data["user_auth_data"])

        except JWTError:
            return None


def get_auth(environment: Environment = Depends(get_environment)) -> Auth:
    return Auth(environment.secret_key)

