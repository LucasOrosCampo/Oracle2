from dataclasses import dataclass
from dotenv import load_dotenv
from os import getenv


# todo lucas install dotenv
@dataclass
class Environment:
    secret_key: str


class EnvirontmentManager:
    def __init__(self):
        load_dotenv()
        secret_key = getenv("SECRET_KEY")

        if secret_key is None:
            raise Exception("SECRET_KEY not found in .env file")
        self.environment = Environment(secret_key=secret_key)

    def get_environment(self) -> Environment:
        return self.environment


environment_manager = EnvirontmentManager()


def get_environment_manager() -> EnvirontmentManager:
    return environment_manager


def get_environment() -> Environment:
    return environment_manager.get_environment()
