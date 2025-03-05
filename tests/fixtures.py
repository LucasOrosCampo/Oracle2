import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session
from data.database import engine, init_db
from main import app

@pytest.fixture(scope="function")
def test_client():
    init_db(drop_existing=True)
    with TestClient(app) as client:
        yield client

@pytest.fixture(scope="function")
def test_db_session():
    with Session(engine) as session:
        yield session