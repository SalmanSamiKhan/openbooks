import pytest
from allauth.account.models import EmailAddress
from django.contrib.auth import authenticate, get_user_model
from django.core import mail
from io import BytesIO
from PIL import Image
from rest_framework.test import APIClient

User = get_user_model()

BASE_URL = "/api/auth/browser/v1"


# Creates a verified user for authentication tests.
@pytest.fixture
def verified_user():
    user = User.objects.create_user(
        email="user@example.com",
        password="test-password-123",
    )

    EmailAddress.objects.create(
        user=user,
        email=user.email,
        primary=True,
        verified=True,
    )

    return user


# Creates a regular user with an email and password.
@pytest.mark.django_db
def test_create_user_with_email():
    user = User.objects.create_user(
        email="user@example.com",
        password="test-password-123",
    )

    assert user.email == "user@example.com"
    assert user.check_password("test-password-123")


# Ensures passwords are stored as hashes.
@pytest.mark.django_db
def test_password_is_hashed():
    password = "test-password-123"

    user = User.objects.create_user(
        email="user@example.com",
        password=password,
    )

    assert user.password != password
    assert user.check_password(password)


# Ensures email addresses are normalized.
@pytest.mark.django_db
def test_email_is_normalized():
    user = User.objects.create_user(
        email="User@EXAMPLE.COM",
        password="test-password-123",
    )

    assert user.email == "User@example.com"


# Ensures duplicate email addresses are rejected.
@pytest.mark.django_db
def test_duplicate_email_is_rejected():
    User.objects.create_user(
        email="user@example.com",
        password="test-password-123",
    )

    with pytest.raises(Exception):
        User.objects.create_user(
            email="user@example.com",
            password="another-password",
        )


# Ensures users can authenticate with email and password.
@pytest.mark.django_db
def test_user_can_authenticate_with_email():
    password = "test-password-123"

    User.objects.create_user(
        email="user@example.com",
        password=password,
    )

    user = authenticate(
        email="user@example.com",
        password=password,
    )

    assert user is not None
    assert user.email == "user@example.com"


# Ensures authentication fails with the wrong password.
@pytest.mark.django_db
def test_wrong_password_fails_authentication():
    User.objects.create_user(
        email="user@example.com",
        password="correct-password",
    )

    user = authenticate(
        email="user@example.com",
        password="wrong-password",
    )

    assert user is None


# Ensures authentication fails for an unknown email.
@pytest.mark.django_db
def test_nonexistent_user_fails_authentication():
    user = authenticate(
        email="unknown@example.com",
        password="test-password-123",
    )

    assert user is None


# Ensures inactive users cannot authenticate.
@pytest.mark.django_db
def test_inactive_user_cannot_authenticate():
    password = "test-password-123"

    User.objects.create_user(
        email="inactive@example.com",
        password=password,
        is_active=False,
    )

    user = authenticate(
        email="inactive@example.com",
        password=password,
    )

    assert user is None


# Ensures users without passwords cannot authenticate.
@pytest.mark.django_db
def test_unusable_password_cannot_authenticate():
    user = User.objects.create_user(
        email="nopassword@example.com",
    )

    assert not user.has_usable_password()

    authenticated_user = authenticate(
        email=user.email,
        password="anything",
    )

    assert authenticated_user is None


# Ensures a superuser has the correct permissions.
@pytest.mark.django_db
def test_create_superuser():
    user = User.objects.create_superuser(
        email="admin@example.com",
        password="admin-password-123",
    )

    assert user.email == "admin@example.com"
    assert user.is_active is True
    assert user.is_staff is True
    assert user.is_superuser is True
    assert user.check_password("admin-password-123")


# Ensures a superuser can authenticate.
@pytest.mark.django_db
def test_superuser_can_authenticate():
    password = "admin-password-123"

    User.objects.create_superuser(
        email="admin@example.com",
        password=password,
    )

    user = authenticate(
        email="admin@example.com",
        password=password,
    )

    assert user is not None
    assert user.is_superuser is True


# Ensures the initial session response provides a CSRF cookie.
@pytest.mark.django_db
def test_session_sets_csrf_cookie(client):
    response = client.get(f"{BASE_URL}/auth/session")

    assert response.status_code == 401
    assert "csrftoken" in response.cookies


# Ensures an unauthenticated session reports no authenticated user.
@pytest.mark.django_db
def test_session_is_unauthenticated(client):
    response = client.get(f"{BASE_URL}/auth/session")

    assert response.status_code == 401
    assert response.json()["meta"]["is_authenticated"] is False


# Ensures a verified user can log in through the headless API.
@pytest.mark.django_db
def test_headless_login(client, verified_user):
    csrf_token = client.get(f"{BASE_URL}/auth/session").cookies["csrftoken"].value

    response = client.post(
        f"{BASE_URL}/auth/login",
        data={
            "email": verified_user.email,
            "password": "test-password-123",
        },
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["meta"]["is_authenticated"] is True
    assert data["data"]["user"]["email"] == verified_user.email
    assert "sessionid" in response.cookies


# Ensures login fails with an incorrect password.
@pytest.mark.django_db
def test_headless_login_wrong_password(client, verified_user):
    csrf_token = client.get(f"{BASE_URL}/auth/session").cookies["csrftoken"].value

    response = client.post(
        f"{BASE_URL}/auth/login",
        data={
            "email": verified_user.email,
            "password": "wrong-password",
        },
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code == 400

    data = response.json()

    assert "errors" in data


# Ensures an unverified user cannot complete login.
@pytest.mark.django_db
def test_headless_login_requires_email_verification(client):
    user = User.objects.create_user(
        email="unverified@example.com",
        password="test-password-123",
    )

    csrf_token = client.get(f"{BASE_URL}/auth/session").cookies["csrftoken"].value

    response = client.post(
        f"{BASE_URL}/auth/login",
        data={
            "email": user.email,
            "password": "test-password-123",
        },
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code == 401

    data = response.json()

    assert data["meta"]["is_authenticated"] is False


# Ensures an authenticated session returns the logged-in user.
@pytest.mark.django_db
def test_headless_authenticated_session(client, verified_user):
    csrf_token = client.get(f"{BASE_URL}/auth/session").cookies["csrftoken"].value

    response = client.post(
        f"{BASE_URL}/auth/login",
        data={
            "email": verified_user.email,
            "password": "test-password-123",
        },
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code == 200

    response = client.get(f"{BASE_URL}/auth/session")

    assert response.status_code == 200

    data = response.json()

    assert data["meta"]["is_authenticated"] is True
    assert data["data"]["user"]["email"] == verified_user.email


# Ensures logout ends the authenticated session.
@pytest.mark.django_db
def test_headless_logout(client, verified_user):
    csrf_token = client.get(f"{BASE_URL}/auth/session").cookies["csrftoken"].value

    response = client.post(
        f"{BASE_URL}/auth/login",
        data={
            "email": verified_user.email,
            "password": "test-password-123",
        },
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code == 200

    response = client.delete(
        f"{BASE_URL}/auth/session",
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code == 401


# Ensures signup creates a new user.
@pytest.mark.django_db
def test_headless_signup(client):
    csrf_token = client.get(f"{BASE_URL}/auth/session").cookies["csrftoken"].value

    response = client.post(
        f"{BASE_URL}/auth/signup",
        data={
            "email": "signup@example.com",
            "password": "test-password-123",
        },
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code in (200, 401)

    user = User.objects.get(email="signup@example.com")

    assert user.has_usable_password()


# Ensures duplicate signup is rejected.
@pytest.mark.django_db
def test_headless_signup_duplicate_email(client):
    User.objects.create_user(
        email="existing@example.com",
        password="existing-password",
    )

    csrf_token = client.get(f"{BASE_URL}/auth/session").cookies["csrftoken"].value

    response = client.post(
        f"{BASE_URL}/auth/signup",
        data={
            "email": "existing@example.com",
            "password": "another-password",
        },
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf_token,
    )

    assert response.status_code == 401


# Ensures password reset requests succeed without revealing account existence.
@pytest.mark.django_db
def test_headless_password_reset_request(client):
    User.objects.create_user(
        email="reset@example.com",
        password="old-password",
    )

    response = client.post(
        f"{BASE_URL}/auth/password/request",
        data={
            "email": "reset@example.com",
        },
        content_type="application/json",
    )

    assert response.status_code == 200
    assert len(mail.outbox) == 1


# Ensures password reset does not reveal whether an account exists.
@pytest.mark.django_db
def test_headless_password_reset_unknown_email(client):
    response = client.post(
        f"{BASE_URL}/auth/password/request",
        data={
            "email": "unknown@example.com",
        },
        content_type="application/json",
    )

    assert response.status_code == 200
    assert len(mail.outbox) == 1


# Ensures unauthenticated users cannot retrieve a profile.
@pytest.mark.django_db
def test_get_me_requires_authentication(client):
    response = client.get("/api/users/me/")

    assert response.status_code == 403


# Ensures an authenticated user can call the profile update endpoint.
@pytest.mark.django_db
def test_patch_me(client, verified_user):
    client.force_login(verified_user)

    response = client.patch(
        "/api/users/me/",
        data={},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["email"] == verified_user.email


# Ensures profile updates require authentication.
@pytest.mark.django_db
def test_patch_me_requires_authentication(client):
    response = client.patch(
        "/api/users/me/",
        data={},
        content_type="application/json",
    )

    assert response.status_code == 403


# Ensures the login email cannot be changed through the profile endpoint.
@pytest.mark.django_db
def test_patch_me_cannot_change_email(client, verified_user):
    client.force_login(verified_user)

    response = client.patch(
        "/api/users/me/",
        data={"email": "new@example.com"},
        content_type="application/json",
    )

    assert response.status_code == 200
    assert response.json()["email"] == verified_user.email

    verified_user.refresh_from_db()

    assert verified_user.email == "user@example.com"


# Ensures an authenticated user can deactivate their account.
@pytest.mark.django_db
def test_delete_me(client, verified_user):
    client.force_login(verified_user)

    response = client.delete("/api/users/me/")

    assert response.status_code == 204

    verified_user.refresh_from_db()

    assert verified_user.is_active is False


# Ensures account deletion requires authentication.
@pytest.mark.django_db
def test_delete_me_requires_authentication(client):
    response = client.delete("/api/users/me/")

    assert response.status_code == 403


# Ensures the complete profile is returned.
@pytest.mark.django_db
def test_get_me_returns_profile(client, verified_user):
    client.force_login(verified_user)

    response = client.get("/api/users/me/")

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == verified_user.id
    assert data["email"] == verified_user.email
    assert data["first_name"] == verified_user.first_name
    assert data["last_name"] == verified_user.last_name
    assert data["bio"] == verified_user.bio
    assert "date_joined" in data


# Ensures profile fields can be updated.
@pytest.mark.django_db
def test_patch_me_updates_profile(client, verified_user):
    client.force_login(verified_user)

    response = client.patch(
        "/api/users/me/",
        data={
            "first_name": "John",
            "last_name": "Doe",
            "bio": "Book lover",
        },
        content_type="application/json",
    )

    assert response.status_code == 200

    verified_user.refresh_from_db()

    assert verified_user.first_name == "John"
    assert verified_user.last_name == "Doe"
    assert verified_user.bio == "Book lover"


# Ensures PATCH does not replace unspecified fields.
@pytest.mark.django_db
def test_patch_me_is_partial(client, verified_user):
    verified_user.first_name = "Existing"
    verified_user.last_name = "Name"
    verified_user.save()

    client.force_login(verified_user)

    response = client.patch(
        "/api/users/me/",
        data={"bio": "New bio"},
        content_type="application/json",
    )

    assert response.status_code == 200

    verified_user.refresh_from_db()

    assert verified_user.first_name == "Existing"
    assert verified_user.last_name == "Name"
    assert verified_user.bio == "New bio"


# Ensures account identity fields cannot be changed here.
@pytest.mark.django_db
def test_patch_me_protected_fields(client, verified_user):
    client.force_login(verified_user)

    response = client.patch(
        "/api/users/me/",
        data={
            "email": "new@example.com",
            "date_joined": "2020-01-01T00:00:00Z",
        },
        content_type="application/json",
    )

    assert response.status_code == 200

    verified_user.refresh_from_db()

    assert verified_user.email == "user@example.com"


def make_test_image():
    image = Image.new("RGB", (100, 100))
    image_file = BytesIO()
    image.save(image_file, format="JPEG")
    image_file.seek(0)
    image_file.name = "avatar.jpg"
    return image_file


@pytest.mark.django_db
def test_patch_me_uploads_avatar(verified_user):
    client = APIClient()
    client.force_authenticate(user=verified_user)

    response = client.patch(
        "/api/users/me/",
        {"avatar": make_test_image()},
        format="multipart",
    )

    assert response.status_code == 200

    verified_user.refresh_from_db()

    assert verified_user.avatar
    assert verified_user.avatar.name.startswith("avatars/")


@pytest.mark.django_db
def test_patch_me_replaces_avatar(verified_user):
    client = APIClient()
    client.force_authenticate(user=verified_user)

    response = client.patch(
        "/api/users/me/",
        {"avatar": make_test_image()},
        format="multipart",
    )

    assert response.status_code == 200

    verified_user.refresh_from_db()
    first_avatar = verified_user.avatar.name

    response = client.patch(
        "/api/users/me/",
        {"avatar": make_test_image()},
        format="multipart",
    )

    assert response.status_code == 200

    verified_user.refresh_from_db()

    assert verified_user.avatar
    assert verified_user.avatar.name != first_avatar


@pytest.mark.django_db
def test_patch_me_rejects_invalid_avatar(verified_user):
    client = APIClient()
    client.force_authenticate(user=verified_user)

    invalid_file = BytesIO(b"this is not an image")
    invalid_file.name = "avatar.txt"

    response = client.patch(
        "/api/users/me/",
        {"avatar": invalid_file},
        format="multipart",
    )

    assert response.status_code == 400
    assert "avatar" in response.json()


@pytest.mark.django_db
def test_patch_me_avatar_requires_authentication():
    client = APIClient()

    response = client.patch(
        "/api/users/me/",
        {"avatar": make_test_image()},
        format="multipart",
    )

    assert response.status_code == 403
