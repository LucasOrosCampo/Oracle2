from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from data.models.base import Base
from data.models.user import User
from sqlalchemy.orm import Session
from typing import Generator
import os

# Get the directory two levels up from the current file (Oracle directory)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Construct the database URL for the database in Oracle/data/oracle.db
DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'data', 'oracle.db')}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
app_session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

metadata = Base.metadata


def init_db(drop_existing=False):
    """
    Initialize the database by creating all tables.

    :param drop_existing: If True, drops all existing tables before creating them.
    """
    if drop_existing:
        metadata.drop_all(bind=engine)
        print("Dropped all existing tables.")

    metadata.create_all(bind=engine)
    print("Created all tables.")


@contextmanager
def get_db() -> Generator[Session, None, None]:
    db = app_session_factory()
    try:
        yield db
    finally:
        db.close()


def get_db_session():
    with get_db() as session:
        yield session
