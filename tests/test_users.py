import json

from sqlmodel import select
from services.auth import HashHelper
from api.user.user_router import NewUserPayload, LoginPayload
from data.models.user import User
from tests.fixtures import test_client, test_db_session


def test_user_should_be_created(test_client, test_db_session):
    payload = NewUserPayload(
        username="test", email="mail@gmail.com", password="TestPa$$w0rd"
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    assert result.status_code == 200

    response = test_db_session.get(User, 1)
    assert response is not None
    assert response.username == "test"
    assert response.email == "mail@gmail.com"
    assert HashHelper.verify(
        plain_password="TestPa$$w0rd", hashed_password=response.password_hash
    )


def test_duplicate_username(test_client):
    # Create first user
    payload = NewUserPayload(
        username="duplicate", email="first@example.com", password="Test1234!"
    )
    result_1 = test_client.post("/user/create", json=payload.model_dump())
    assert result_1.status_code == 200

    # Try to create user with same username
    payload = NewUserPayload(
        username="duplicate", email="second@example.com", password="Test1234!"
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Username already exists" in "".join(result_as_dict["detail"])


def test_duplicate_email(test_client):
    # Create first user
    payload = NewUserPayload(
        username="user1", email="duplicate@example.com", password="Test1234!"
    )
    result_1 = test_client.post("/user/create", json=payload.model_dump())
    assert result_1.status_code == 200

    # Try to create user with same email
    payload = NewUserPayload(
        username="user2", email="duplicate@example.com", password="Test1234!"
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Email already exists" in "".join(result_as_dict["detail"])


def test_invalid_username_format(test_client):
    payload = NewUserPayload(
        username="invalid username", email="valid@example.com", password="ValidPa$$w0rd"
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Invalid username" in "".join(result_as_dict["detail"])


def test_username_as_email(test_client):
    payload = NewUserPayload(
        username="email@example.org",
        email="valid@example.org",
        password="ValidPa$$w0rd",
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Username cannot be an email address" in "".join(result_as_dict["detail"])


def test_invalid_email_format(test_client):
    payload = NewUserPayload(
        username="validusername",
        email="invalid-email@example",
        password="ValidPa$$w0rd",
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Invalid email" in "".join(result_as_dict["detail"])


def test_short_password(test_client):
    payload = NewUserPayload(
        username="validusername", email="valid@example.com", password="Short1!"
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Password must be at least 8 characters long." in "".join(
        result_as_dict["detail"]
    )


def test_password_missing_uppercase(test_client):
    payload = NewUserPayload(
        username="validusername", email="valid@example.com", password="lowercase1!"
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Password must contain at least one uppercase letter." in "".join(
        result_as_dict["detail"]
    )


def test_password_missing_lowercase(test_client):
    payload = NewUserPayload(
        username="validusername", email="valid@example.com", password="UPPERCASE1!"
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Password must contain at least one lowercase letter." in "".join(
        result_as_dict["detail"]
    )


def test_password_missing_digit(test_client):
    payload = NewUserPayload(
        username="validusername", email="valid@example.com", password="NoDigits!"
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Password must contain at least one digit." in "".join(
        result_as_dict["detail"]
    )


def test_password_missing_special_character(test_client):
    payload = NewUserPayload(
        username="validusername", email="valid@example.com", password="NoSpecial1"
    )
    result = test_client.post("/user/create", json=payload.model_dump())
    result_as_dict = json.loads(result.text)

    assert result.status_code == 400
    assert "Password must contain at least one special character" in "".join(
        result_as_dict["detail"]
    )


def test_user_login(test_client):
    # Create a new user
    payload = NewUserPayload(
        username="testuser", email="testuser@example.com", password="TestPa$$w0rd"
    )
    test_client.post("/user/create", json=payload.model_dump())

    # Login with the created user
    login_payload = LoginPayload(username_or_email="testuser", password="TestPa$$w0rd")
    result = test_client.post("/user/login", json=login_payload.model_dump())
    assert result.status_code == 200
    token = result.json()
    assert token is not None


def test_invalid_login(test_client):
    # Attempt to login with invalid credentials
    login_payload = LoginPayload(
        username_or_email="nonexistentuser", password="WrongPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())
    assert result.status_code == 404
    assert "User not found" in result.json()["detail"]


def test_wrong_password(test_client):
    # Create a new user
    payload = NewUserPayload(
        username="testuser2", email="testuser2@example.com", password="CorrectPa$$w0rd"
    )
    test_client.post("/user/create", json=payload.model_dump())

    # Attempt to login with the wrong password
    login_payload = LoginPayload(
        username_or_email="testuser2", password="WrongPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())
    assert result.status_code == 401
    assert "Invalid credentials" in "".join(result.json()["detail"])


def test_admin_access(test_client, test_db_session):
    # Create a new admin user
    admin = User(
        username="adminuser",
        email="adminuser@example.com",
        password_hash=HashHelper.hash("AdminPa$$w0rd"),
        admin=True,
    )
    test_db_session.add(admin)
    test_db_session.commit()

    # Login with the admin user
    login_payload = LoginPayload(
        username_or_email="adminuser", password="AdminPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())
    assert result.status_code == 200
    token = result.json()
    assert token is not None

    # Access admin route
    headers = {"Authorization": f"Bearer {token}"}
    result = test_client.get("/user", headers=headers)
    assert result.status_code == 200
    assert len(json.loads(result.text)) == 1


def test_non_admin_access(test_client):
    # Create a new non-admin user
    payload = NewUserPayload(
        username="regularuser", email="regularuser@example.com", password="UserPa$$w0rd"
    )
    test_client.post("/user/create", json=payload.model_dump())

    # Login with the non-admin user
    login_payload = LoginPayload(
        username_or_email="regularuser", password="UserPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())
    assert result.status_code == 200
    token = result.json()
    assert token is not None

    # Attempt to access admin route
    headers = {"Authorization": f"Bearer {token}"}
    result = test_client.get("/user", headers=headers)
    assert result.status_code == 403
    assert "Forbidden" in result.json()["detail"]


def test_upgrade_user_to_admin(test_client, test_db_session):
    # Create a new admin user
    admin = User(
        username="adminuser",
        email="adminuser@example.com",
        password_hash=HashHelper.hash("AdminPa$$w0rd"),
        admin=True,
    )
    test_db_session.add(admin)
    test_db_session.commit()

    # Create another admin user
    admin2 = User(
        username="adminuser2",
        email="adminuser2@example.com",
        password_hash=HashHelper.hash("AdminPa$$w0rd"),
        admin=True,
    )
    test_db_session.add(admin2)
    test_db_session.commit()

    # Create a new non-admin user
    payload = NewUserPayload(
        username="regularuser", email="regularuser@example.com", password="UserPa$$w0rd"
    )
    test_client.post("/user/create", json=payload.model_dump())

    user = test_db_session.exec(select(User).where(User.username == payload.username)).one()
    assert not user.admin

    # Login with the admin user
    login_payload = LoginPayload(
        username_or_email="adminuser", password="AdminPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())

    # Attempt to upgrade non existing user
    token = result.json()
    headers = {"Authorization": f"Bearer {token}"}
    result = test_client.post("/user/nonexistentuser/admin", headers=headers)
    assert result.status_code == 404
    assert "User not found" in ''.join(result.json()["detail"])

    # Attempt to upgrade admin user
    result = test_client.post("/user/adminuser2/admin", headers=headers)
    assert result.status_code == 400
    assert "User is already admin" in ''.join(result.json()["detail"])

    # Upgrade the non-admin user to admin
    result = test_client.post(f"/user/{payload.username}/admin", headers=headers)
    assert result.status_code == 200

    # Check if the user is an admin
    user = test_db_session.exec(select(User).where(User.username == payload.username)).one()
    test_db_session.refresh(user)
    assert user.admin

    # Attempt to access admin route
    login_payload = LoginPayload(
        username_or_email="regularuser", password="UserPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())
    token = result.json()
    headers = {"Authorization": f"Bearer {token}"}
    result = test_client.get("/user", headers=headers)
    assert result.status_code == 200
    assert len(json.loads(result.text)) == 3

def test_upgrade_denied(test_client, test_db_session):
    # Create a new non-admin user
    payload = NewUserPayload(
        username="regularuser", email="regularuser@example.com", password="UserPa$$w0rd"
    )
    test_client.post("/user/create", json=payload.model_dump())

    # Create another non-admin user
    payload = NewUserPayload(
        username="anotheruser", email="anotheruser@example.com", password="UserPa$$w0rd"
    )
    test_client.post("/user/create", json=payload.model_dump())

    # Login with the non-admin user
    login_payload = LoginPayload(
        username_or_email="regularuser", password="UserPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())
    token = result.json()
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to upgrade another user
    result = test_client.post(f"/user/anotheruser/admin", headers=headers)
    assert result.status_code == 403
    assert "Forbidden" in ''.join(result.json()["detail"])

def test_downgrade_user_denied(test_client, test_db_session):
    # Create a new admin user
    admin = User(
        username="adminuser",
        email="adminuser@example.com",
        password_hash=HashHelper.hash("AdminPa$$w0rd"),
        admin=True,
    )
    test_db_session.add(admin)
    test_db_session.commit()

    # Create a new non-admin user
    payload = NewUserPayload(
        username="regularuser", email="regularuser@example.com", password="UserPa$$w0rd"
    )
    test_client.post("/user/create", json=payload.model_dump())

    # Login with the non-admin user
    login_payload = LoginPayload(
        username_or_email="regularuser", password="UserPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())
    token = result.json()
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to downgrade admin user
    result = test_client.delete(f"/user/adminuser/admin", headers=headers)
    assert result.status_code == 403
    assert "Forbidden" in ''.join(result.json()["detail"])

def test_downgrade_admin(test_client, test_db_session):
    # Create a new admin user
    admin = User(
        username="adminuser",
        email="adminuser@example.com",
        password_hash=HashHelper.hash("AdminPa$$w0rd"),
        admin=True,
    )
    test_db_session.add(admin)
    test_db_session.commit()

    # Create 2nd admin user
    admin2 = User(
        username="adminuser2",
        email="adminuser2@example.com",
        password_hash=HashHelper.hash("AdminPa$$w0rd"),
        admin=True,
    )
    test_db_session.add(admin2)
    test_db_session.commit()

    # Create 3rd admin user
    admin3 = User(
        username="adminuser3",
        email="adminuser3@example.com",
        password_hash=HashHelper.hash("AdminPa$$w0rd"),
        admin=True,
    )
    test_db_session.add(admin3)
    test_db_session.commit()

    # Login with the admin user
    login_payload = LoginPayload(
        username_or_email="adminuser", password="AdminPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())
    token = result.json()
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to downgrade admin user
    result = test_client.delete(f"/user/adminuser/admin", headers=headers)
    assert result.status_code == 200

    # Check that the admin user is no longer an admin
    user = test_db_session.exec(select(User).where(User.username == "adminuser")).one()
    assert not user.admin

    # Attempt to access admin route
    result = test_client.get("/user", headers=headers)
    assert result.status_code == 403
    assert "Forbidden" in ''.join(result.json()["detail"])

    # Attempt to downgrade 2nd admin user
    result = test_client.delete(f"/user/adminuser2/admin", headers=headers)
    assert result.status_code == 403
    assert "Forbidden" in ''.join(result.json()["detail"])

    # Login with 2nd admin user
    login_payload = LoginPayload(
        username_or_email="adminuser2", password="AdminPa$$w0rd"
    )
    result = test_client.post("/user/login", json=login_payload.model_dump())
    token = result.json()
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to downgrade 1st admin user
    result = test_client.delete(f"/user/adminuser/admin", headers=headers)
    assert result.status_code == 400
    assert "User is not an admin" in ''.join(result.json()["detail"])

    # Attempt to downgrade 3rd admin user
    result = test_client.delete(f"/user/adminuser3/admin", headers=headers)
    assert result.status_code == 200

    # Check that the 3rd admin user is no longer an admin
    user = test_db_session.exec(select(User).where(User.username == "adminuser3")).one()
    assert not user.admin

    # Attemp to downgrade oneself as last admin
    result = test_client.delete(f"/user/adminuser2/admin", headers=headers)
    assert result.status_code == 400
    assert "Can't downgrade the last admin" in ''.join(result.json()["detail"])

    # Check we are still an admin
    user = test_db_session.exec(select(User).where(User.username == "adminuser2")).one()
    assert user.admin