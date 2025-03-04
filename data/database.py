from contextlib import contextmanager
from enum import Enum
from sqlmodel import create_engine, Session, SQLModel
from typing import Generator
import os


class EnvironmentType(Enum):
    DEVELOPMENT = "development"
    PROD = "prod"
    TEST = "test"


# Construct the database URL for the database in Oracle/data/oracle.db
PROD_DATABASE_URL = f"sqlite:///{os.path.join(os.path.expanduser("~"), 'oracle.db')}"
TEST_DATABASE_URL = f"sqlite:///{os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), 'data', 'test_oracle.db')}"
DEV_DATABASE_URL = f"sqlite:///{os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), 'data', 'dev_oracle.db')}"

environment_type = os.getenv("ENVIRONMENT_TYPE")
database_url = {
    "development": DEV_DATABASE_URL,
    "prod": PROD_DATABASE_URL,
    "test": TEST_DATABASE_URL
}.get(environment_type, DEV_DATABASE_URL)

engine = create_engine(database_url, connect_args={"check_same_thread": False})


def init_db(drop_existing: bool=False):
    """
    Initialize the database.

    This function creates all tables defined in the SQLModel metadata.
    If `drop_existing` is set to True, it will first drop all existing tables.

    Args:
        drop_existing (bool): If True, drop all existing tables before creating new ones.
    """
    if drop_existing:
        SQLModel.metadata.drop_all(bind=engine)

    SQLModel.metadata.create_all(bind=engine)

def get_db():
    """
    Provide a transactional scope around a series of operations.

    This context manager yields a SQLAlchemy session that is automatically
    committed if no exceptions occur, or rolled back if an exception is raised.

    Yields:
        Session: A SQLAlchemy session object.
    """
    with Session(engine) as session:
        try:
            yield session
        finally:
            session.close()
