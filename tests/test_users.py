from api.user.user_router import NewUserPayload
from data.models.user import User
from fixtures import test_client, db_context
import json

def test_user_should_be_created(test_client, db_context):
    payload = NewUserPayload(username="test", email="mail@gmail.com", password="TestPa$$w0rd")
    result = test_client.post("/user/create", json=payload.model_dump())
    assert result.status_code == 200
    user = db_context.query(User).filter(User.username == "test").first()
    assert user is not None
    assert user.username == "test"
    assert user.email == "mail@gmail.com"
    assert user.password_hash is not None


def test_duplicate_username(test_client):
    # Create first user
    payload = NewUserPayload(username="duplicate", email="first@example.com", password="Test1234!")
    test_client.post("/user/create", json=payload.model_dump())

    # Try to create user with same username
    payload = NewUserPayload(username="duplicate", email="second@example.com", password="Test1234!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Username already exists" in result_as_dict["detail"]


def test_duplicate_email(test_client):
    # Create first user
    payload = NewUserPayload(username="user1", email="duplicate@example.com", password="Test1234!")
    test_client.post("/user/create", json=payload.model_dump())

    # Try to create user with same email
    payload = NewUserPayload(username="user2", email="duplicate@example.com", password="Test1234!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Email already exists" in result_as_dict["detail"]


def test_invalid_email_format(test_client):
    payload = NewUserPayload(username="testuser", email="invalid-email", password="Test1234!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Invalid email" in result_as_dict["detail"]


def test_username_as_email(test_client):
    payload = NewUserPayload(username="user@example.com", email="valid@example.com", password="Test1234!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Username cannot be an email address" in result_as_dict["detail"]


def test_invalid_username_format(test_client):
    # Too short
    payload = NewUserPayload(username="ab", email="valid@example.com", password="Test1234!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Invalid username" in result_as_dict["detail"]

    # Invalid characters
    payload = NewUserPayload(username="test-user!", email="valid@example.com", password="Test1234!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Invalid username" in result_as_dict["detail"]


def test_password_validations(test_client):
    # Too short
    payload = NewUserPayload(username="testuser", email="valid@example.com", password="Short1!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Password must be at least 8 characters" in result_as_dict["detail"]

    # No uppercase
    payload = NewUserPayload(username="testuser", email="valid@example.com", password="lowercase123!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "uppercase letter" in result_as_dict["detail"]

    # No lowercase
    payload = NewUserPayload(username="testuser", email="valid@example.com", password="UPPERCASE123!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "lowercase letter" in result_as_dict["detail"]

    # No digit
    payload = NewUserPayload(username="testuser", email="valid@example.com", password="TestNoDigit!")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "digit" in result_as_dict["detail"]

    # No special character
    payload = NewUserPayload(username="testuser", email="valid@example.com", password="TestUser123")
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "special character" in result_as_dict["detail"]