import pytest
from data.database import app_session_factory, init_db
from fastapi.testclient import TestClient
from main import app  # Import your FastAPI app

@pytest.fixture(scope="module")
def test_client():
    # Setup: Initialize the TestClient
    with TestClient(app) as client:
        yield client
        init_db(drop_existing=True)
        # Teardown: Add any cleanup here

@pytest.fixture(scope="function")
def db_context():
    db = app_session_factory()
    try:
        yield db
    finally:
        db.close()