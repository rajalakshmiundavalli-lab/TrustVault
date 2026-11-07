
import os
import sqlite3
import io

# Use a separate key for automated tests.
os.environ.setdefault("TRUSTVAULT_SECRET_KEY", "test-secret-key-for-testing-only")

import pytest
import app as trustvault


def connect_test_db(database_path):
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    return conn


@pytest.fixture
def client(tmp_path, monkeypatch):
    database_path = str(tmp_path / "test.db")
    upload_path = tmp_path / "uploads"
    upload_path.mkdir()

    monkeypatch.setattr(
        trustvault,
        "get_db",
        lambda: connect_test_db(database_path)
    )

    trustvault.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        UPLOAD_FOLDER=str(upload_path),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024
    )

    trustvault.create_table()

    with trustvault.app.test_client() as test_client:
        yield test_client


def register_user(client, email="test@example.com"):
    return client.post("/register", data={
        "full_name": "Test User",
        "email": email,
        "password": "testpassword123",
        "confirm_password": "testpassword123"
    })


def login_user(client, email="test@example.com"):
    return client.post("/login", data={
        "email": email,
        "password": "testpassword123"
    })


def test_home_page(client):
    response = client.get("/")
    assert response.status_code == 200


def test_register_and_login(client):
    register_response = register_user(client)
    assert register_response.status_code == 302

    login_response = login_user(client)
    assert login_response.status_code == 302

    dashboard_response = client.get("/dashboard")
    assert dashboard_response.status_code == 200
def test_duplicate_registration(client):
    register_user(client)
    response = register_user(client)

    assert response.status_code == 200

    conn = trustvault.get_db()
    count = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]
    conn.close()

    assert count == 1
def test_dashboard_requires_login(client):
    response = client.get("/dashboard")

    assert response.status_code == 302
    assert "/login" in response.location


def test_upload_download_and_delete(client):
    register_user(client)
    login_user(client)

    upload_response = client.post(
        "/upload",
        data={
            "document_name": "My Test Document",
            "document": (
                io.BytesIO(b"Test document content"),
                "test.pdf"
            )
        },
        content_type="multipart/form-data"
    )

    assert upload_response.status_code == 302

    conn = trustvault.get_db()
    document = conn.execute(
        "SELECT * FROM documents"
    ).fetchone()
    conn.close()

    assert document is not None

    download_response = client.get(
    f"/download/{document['id']}"
    )
    assert download_response.status_code == 200

    download_response.close()
    delete_response = client.post(
        f"/delete/{document['id']}"
    )
    assert delete_response.status_code == 302

    conn = trustvault.get_db()
    remaining = conn.execute(
        "SELECT * FROM documents"
    ).fetchall()
    conn.close()

    assert len(remaining) == 0


def test_admin_dashboard_access(client):
    register_user(client)

    conn = trustvault.get_db()
    conn.execute(
        "UPDATE users SET role = 'admin' WHERE email = ?",
        ("test@example.com",)
    )
    conn.commit()
    conn.close()

    login_user(client)

    response = client.get("/admin")

    assert response.status_code == 200
def test_normal_user_cannot_access_admin(client):
    register_user(client)
    login_user(client)

    response = client.get("/admin")

    assert response.status_code == 403
    assert b"Access Denied" in response.data
def test_user_cannot_download_another_users_document(client):
    register_user(client, "user1@example.com")
    login_user(client, "user1@example.com")

    client.post(
        "/upload",
        data={
            "document_name": "Private Document",
            "document": (
                io.BytesIO(b"Private content"),
                "private.pdf"
            )
        },
        content_type="multipart/form-data"
    )

    conn = trustvault.get_db()
    document = conn.execute(
        "SELECT id FROM documents"
    ).fetchone()
    conn.close()

    client.get("/logout")

    register_user(client, "user2@example.com")
    login_user(client, "user2@example.com")

    response = client.get(
        f"/download/{document['id']}"
    )

    assert response.status_code == 200
    assert b"Document not found" in response.data
def test_unsupported_file_type_is_rejected(client):
    register_user(client)
    login_user(client)

    response = client.post(
        "/upload",
        data={
            "document_name": "Invalid File",
            "document": (
                io.BytesIO(b"test content"),
                "malware.exe"
            )
        },
        content_type="multipart/form-data"
    )

    assert response.status_code == 200
    assert b"File type not allowed." in response.data
def test_password_change_rejects_wrong_current_password(client):
    register_user(client)
    login_user(client)

    response = client.post(
        "/change-password",
        data={
            "current_password": "wrongpassword",
            "new_password": "newpassword123",
            "confirm_password": "newpassword123"
        }
    )

    assert response.status_code == 302
    assert "/change-password" in response.location
def test_password_change_rejects_mismatched_passwords(client):
    register_user(client)
    login_user(client)

    response = client.post(
        "/change-password",
        data={
            "current_password": "testpassword123",
            "new_password": "newpassword123",
            "confirm_password": "differentpassword123"
        }
    )

    assert response.status_code == 302
    assert "/change-password" in response.location
def test_password_change_rejects_short_password(client):
    register_user(client)
    login_user(client)

    response = client.post(
        "/change-password",
        data={
            "current_password": "testpassword123",
            "new_password": "short",
            "confirm_password": "short"
        }
    )

    assert response.status_code == 302
    assert "/change-password" in response.location
def test_login_creates_audit_log(client):
    register_user(client)
    login_user(client)

    conn = trustvault.get_db()
    log = conn.execute(
        "SELECT * FROM audit_logs WHERE action = 'LOGIN'"
    ).fetchone()
    conn.close()

    assert log is not None
    assert log["details"] == "User logged in successfully"


def test_admin_can_access_audit_logs(client):
    register_user(client)

    conn = trustvault.get_db()
    conn.execute(
        "UPDATE users SET role = 'admin' WHERE email = ?",
        ("test@example.com",)
    )
    conn.commit()
    conn.close()

    login_user(client)

    response = client.get("/admin/audit-logs")

    assert response.status_code == 200
    assert b"TrustVault Audit Logs" in response.data


def test_normal_user_cannot_access_audit_logs(client):
    register_user(client)
    login_user(client)

    response = client.get("/admin/audit-logs")

    assert response.status_code == 403
    assert b"Access Denied" in response.data