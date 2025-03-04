import pytest
from fastapi.testclient import TestClient
from data.database import init_db
from main import app

@pytest.fixture(scope="module")
def test_client():
    init_db(drop_existing=True)
    with TestClient(app) as client:
        yield client