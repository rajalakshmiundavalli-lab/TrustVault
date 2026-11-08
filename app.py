
import os
import re
import sqlite3
import psycopg
import uuid
import secrets
import hashlib
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
app = Flask(__name__)
app.secret_key = os.environ.get("TRUSTVAULT_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("TRUSTVAULT_SECRET_KEY is not set!")
csrf = CSRFProtect(app)
# Added security headers
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
DATABASE = os.path.join(app.root_path, "trustvault.db")
DATABASE_URL = os.environ.get("DATABASE_URL")
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 58
MAIL_USERNAME = os.environ.get("TRUSTVAULT_EMAIL")
MAIL_PASSWORD = os.environ.get("TRUSTVAULT_EMAIL_PASSWORD")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg"}
# Database connection
class HybridRow(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)
def hybrid_row(cursor):
    columns = [
        column.name for column in (cursor.description or [])
    ]
    def make_row(values):
        return HybridRow(zip(columns, values))
    return make_row
class PostgresConnection:
    def __init__(self, connection):
        self.connection = connection
    def execute(self, query, params=()):
        query = query.replace("?", "%s")
        return self.connection.execute(query, params)
    def commit(self):
        self.connection.commit()
    def close(self):
        self.connection.close()
def get_db():
    if DATABASE_URL:
        connection = psycopg.connect(
            DATABASE_URL,
            row_factory=hybrid_row
        )
        return PostgresConnection(connection)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
def send_reset_email(email, reset_link):
    msg = EmailMessage()
    msg["Subject"] = "TrustVault - Password Reset"
    msg["From"] = MAIL_USERNAME
    msg["To"] = email
    msg.set_content(
        f"""Hello,
We received a request to reset your TrustVault password.
Use this link within 30 minutes:
{reset_link}
If you did not request this, ignore this email.
TrustVault Team
"""
    )
    with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
        server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.send_message(msg)
# Create database tables
def create_table():
    conn = get_db()
    is_postgres = bool(DATABASE_URL)
    if is_postgres:
        id_type = "SERIAL PRIMARY KEY"
    else:
        id_type = "INTEGER PRIMARY KEY AUTOINCREMENT"
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS users (
            id {id_type},
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)
    if is_postgres:
        columns = [
            row["column_name"]
            for row in conn.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users'
                  AND table_schema = current_schema()
            """).fetchall()
        ]
    else:
        columns = [
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        ]
    if "role" not in columns:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
        """)
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS documents (
            id {id_type},
            user_id INTEGER NOT NULL,
            document_name TEXT NOT NULL,
            filename TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS document_permissions (
            id {id_type},
            document_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            granted_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(document_id, user_id),
            FOREIGN KEY (document_id) REFERENCES documents(id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (granted_by) REFERENCES users(id)
        )
    """)
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id {id_type},
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS password_resets (
            id {id_type},
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    admin_email = os.environ.get(
        "TRUSTVAULT_ADMIN_EMAIL", ""
    ).strip().lower()
    if admin_email:
        conn.execute(
            "UPDATE users SET role = 'admin' WHERE LOWER(email) = ?",
            (admin_email,)
        )
    conn.commit()
    conn.close()
# Audit logging
def log_action(action, details=""):
    user_id = session.get("user_id")
    conn = get_db()
    conn.execute("""
        INSERT INTO audit_logs (user_id, action, details)
        VALUES (?, ?, ?)
    """, (user_id, action, details))
    conn.commit()
    conn.close()
# Admin check
def is_admin():
    if "user_id" not in session:
        return False
    conn = get_db()
    user = conn.execute(
        "SELECT role FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()
    conn.close()
    return user is not None and user["role"] == "admin"
# Home
@app.route("/")
def home():
    return render_template("index.html")
# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not name or not email or not password or not confirm:
            return render_template(
                "register.html",
                error="All fields are required."
            )
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return render_template(
                "register.html",
                error="Please enter a valid email address."
            )
        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password must contain at least 8 characters."
            )
        if password != confirm:
            return render_template(
                "register.html",
                error="Warning: Passwords do not match. Please try again."
            )
        admin_email = os.environ.get(
            "TRUSTVAULT_ADMIN_EMAIL", ""
        ).strip().lower()
        role = "admin" if admin_email and email == admin_email else "user"
        conn = get_db()
        try:
            conn.execute("""
                INSERT INTO users
                (full_name, email, password_hash, role)
                VALUES (?, ?, ?, ?)
            """, (
                name,
                email,
                generate_password_hash(password),
                role
            ))
            conn.commit()

        except (sqlite3.IntegrityError, psycopg.errors.UniqueViolation):
            conn.close()
            return render_template(
                "register.html",
                error="Email already registered."
            )
        conn.close()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")
# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE LOWER(email) = ?",
            (email,)
        ).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["full_name"]
            session["role"] = user["role"]
            log_action("LOGIN", "User logged in successfully")
            return redirect(url_for("dashboard"))
        return render_template(
            "login.html",
            error="Invalid email or password."
        )
    return render_template("login.html")
# User dashboard
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db()
    user = conn.execute(
        "SELECT role FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()
    documents = conn.execute(
        "SELECT filename FROM documents WHERE user_id = ?",
        (session["user_id"],)
    ).fetchall()
    conn.close()
    total_documents = len(documents)
    storage_bytes = 0
    for document in documents:
        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            document["filename"]
        )
        if os.path.exists(file_path):
            storage_bytes += os.path.getsize(file_path)
    return render_template(
        "dashboard.html",
        name=session["user_name"],
        total_documents=total_documents,
        storage_mb=round(storage_bytes / (1024 * 1024), 2),
        is_admin=user is not None and user["role"] == "admin"
    )
# Admin dashboard
@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if not is_admin():
        return "Access Denied: Admins only.", 403
    conn = get_db()
    users = conn.execute(
        "SELECT id, full_name, email, role FROM users"
    ).fetchall()
    total_users = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]
    total_documents = conn.execute(
        "SELECT COUNT(*) FROM documents"
    ).fetchone()[0]
    all_documents = conn.execute("""
        SELECT documents.id, documents.document_name,
               documents.filename, documents.upload_date,
               users.full_name, users.email
        FROM documents
        JOIN users ON documents.user_id = users.id
        ORDER BY documents.upload_date DESC
    """).fetchall()
    conn.close()
    return render_template(
        "admin.html",
        users=users,
        total_users=total_users,
        total_documents=total_documents,
        all_documents=all_documents
    )
# Audit logs
@app.route("/admin/audit-logs")
def audit_logs():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if not is_admin():
        return "Access Denied: Admins only.", 403
    conn = get_db()
    logs = conn.execute("""
        SELECT audit_logs.id, audit_logs.action,
               audit_logs.details, audit_logs.timestamp,
               users.full_name, users.email
        FROM audit_logs
        LEFT JOIN users ON audit_logs.user_id = users.id
        ORDER BY audit_logs.id DESC
    """).fetchall()
    conn.close()
    return render_template("audit_logs.html", logs=logs)
# Admin user-role management
@app.route("/admin/manage-user/<int:user_id>", methods=["POST"])
def manage_user(user_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if not is_admin():
        return "Access Denied: Admins only.", 403
    new_role = request.form.get("role")
    if new_role not in ("admin", "user"):
        return "Invalid role.", 400
    if user_id == session["user_id"]:
        return "You cannot change your own admin role.", 403
    conn = get_db()
    target = conn.execute(
        "SELECT id, role FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    if target is None:
        conn.close()
        return "User not found.", 404
    if target["role"] == "admin" and new_role == "user":
        admin_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'"
        ).fetchone()[0]
        if admin_count <= 1:
            conn.close()
            return "At least one admin account must remain.", 400
    conn.execute(
        "UPDATE users SET role = ? WHERE id = ?",
        (new_role, user_id)
    )
    conn.commit()
    conn.close()
    log_action(
        "ROLE_CHANGE",
        f"Admin changed user ID {user_id} role to {new_role}"
    )
    return redirect(url_for("admin_dashboard"))
# Upload documents
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        document_name = request.form.get(
            "document_name", ""
        ).strip()

        file = request.files.get("document")

        if not document_name or not file or not file.filename:
            return "Please provide a document name and select a file.", 400

        original_name = secure_filename(file.filename)

        if "." not in original_name:
            return "Invalid file type.", 400

        extension = original_name.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            return "File type not allowed.", 400

        unique_filename = str(uuid.uuid4()) + "." + extension

        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            unique_filename
        )

        file.save(file_path)

        try:
            conn = get_db()

            conn.execute("""
                INSERT INTO documents
                (user_id, document_name, filename)
                VALUES (?, ?, ?)
            """, (
                session["user_id"],
                document_name,
                unique_filename
            ))

            conn.commit()
            conn.close()

        except Exception:
            if os.path.exists(file_path):
                os.remove(file_path)
            raise

        log_action("UPLOAD", f"Uploaded document: {document_name}")
        return redirect(url_for("documents"))

    return render_template("upload.html")


# My documents and search
@app.route("/documents")
def documents():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip()
    conn = get_db()

    user_documents = conn.execute("""
        SELECT DISTINCT d.*
        FROM documents d
        LEFT JOIN document_permissions p
            ON d.id = p.document_id
        WHERE (
            d.user_id = ?
            OR p.user_id = ?
            OR ? = 'admin'
        )
        AND (? = '' OR d.document_name LIKE ?)
        ORDER BY d.upload_date DESC
    """, (
        session["user_id"],
        session["user_id"],
        session.get("role", "user"),
        search,
        "%" + search + "%"
    )).fetchall()

    conn.close()

    return render_template(
        "documents.html",
        documents=user_documents,
        search=search
    )


# Share a document with another user
@app.route("/share/<int:document_id>", methods=["POST"])
def share_document(document_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    email = request.form.get("email", "").strip().lower()
    conn = get_db()

    document = conn.execute("""
        SELECT * FROM documents
        WHERE id = ? AND user_id = ?
    """, (document_id, session["user_id"])).fetchone()

    if document is None:
        conn.close()
        return "Only the document owner can share it.", 403

    recipient = conn.execute("""
        SELECT * FROM users
        WHERE LOWER(email) = ?
    """, (email,)).fetchone()

    if recipient is None:
        conn.close()
        return "User not found. They must register first.", 404

    if recipient["id"] == session["user_id"]:
        conn.close()
        return "You already own this document.", 400

    conn.execute("""
    INSERT INTO document_permissions
    (document_id, user_id, granted_by)
    VALUES (?, ?, ?)
    ON CONFLICT (document_id, user_id) DO NOTHING
""", (document_id, recipient["id"], session["user_id"]))

    conn.commit()
    conn.close()

    log_action("SHARE", f"Shared document: {document['document_name']}")
    return redirect(url_for("documents"))


# User download
@app.route("/download/<int:document_id>")
def download_document(document_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    document = conn.execute("""
        SELECT d.*
        FROM documents d
        LEFT JOIN document_permissions p
            ON d.id = p.document_id
        WHERE d.id = ?
          AND (
              d.user_id = ?
              OR p.user_id = ?
              OR ? = 1
          )
    """, (
        document_id,
        session["user_id"],
        session["user_id"],
        1 if is_admin() else 0
    )).fetchone()

    conn.close()

    if document is None:
        return "Document not found.", 404

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document["filename"]
    )

    if not os.path.isfile(file_path):
        return "Document file is unavailable.", 404

    log_action(
        "DOWNLOAD",
        f"Downloaded document: {document['document_name']}"
    )

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document["filename"],
        as_attachment=True
    )


# View documents
@app.route("/view/<int:document_id>")
def view_document(document_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    document = conn.execute("""
        SELECT DISTINCT d.*
        FROM documents d
        LEFT JOIN document_permissions p
            ON d.id = p.document_id
        WHERE d.id = ?
          AND (
              d.user_id = ?
              OR p.user_id = ?
              OR ? = 1
          )
    """, (
        document_id,
        session["user_id"],
        session["user_id"],
        1 if is_admin() else 0
    )).fetchone()

    conn.close()

    if document is None:
        return "Document not found.", 404

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document["filename"]
    )

    if not os.path.isfile(file_path):
        return "Document file is unavailable.", 404

    log_action(
        "VIEW",
        f"Viewed document: {document['document_name']}"
    )

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document["filename"],
        as_attachment=True
    )


# Admin download
@app.route("/admin/download/<int:document_id>")
def admin_download(document_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    if not is_admin():
        return "Access Denied.", 403

    conn = get_db()

    document = conn.execute(
        "SELECT * FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()

    conn.close()

    if document is None:
        return "Document not found.", 404

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document["filename"]
    )

    if not os.path.isfile(file_path):
        return "Document file is unavailable.", 404

    log_action(
        "DOWNLOAD",
        f"Admin downloaded document: {document['document_name']}"
    )

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document["filename"],
        as_attachment=True
    )


# Delete documents
@app.route("/delete/<int:document_id>", methods=["POST"])
def delete_document(document_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    document = conn.execute("""
        SELECT * FROM documents
        WHERE id = ? AND user_id = ?
    """, (
        document_id,
        session["user_id"]
    )).fetchone()

    if document is None:
        conn.close()
        return "Document not found.", 404

    conn.execute("""
        DELETE FROM document_permissions
        WHERE document_id = ?
    """, (document_id,))
    conn.execute(
        "DELETE FROM documents WHERE id = ? AND user_id = ?",
        (document_id, session["user_id"])
    )
    conn.commit()
    conn.close()
    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document["filename"]
    )
    if os.path.isfile(file_path):
        os.remove(file_path)
    log_action(
        "DELETE",
        f"Deleted document: {document['document_name']}"
    )
    return redirect(url_for("documents"))
# Change password
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        conn = get_db()
        user = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?",
            (session["user_id"],)
        ).fetchone()
        if user is None:
            conn.close()
            session.clear()
            return redirect(url_for("login"))
        if not check_password_hash(
            user["password_hash"], current_password
        ):
            conn.close()
            flash("Current password is incorrect.", "error")
            return redirect(url_for("change_password"))
        if len(new_password) < 8:
            conn.close()
            flash("New password must contain at least 8 characters.", "error")
            return redirect(url_for("change_password"))
        if new_password != confirm_password:
            conn.close()
            flash("New passwords do not match.", "error")
            return redirect(url_for("change_password"))
        if new_password == current_password:
            conn.close()
            flash("Choose a different password.", "error")
            return redirect(url_for("change_password"))
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (
                generate_password_hash(new_password),
                session["user_id"]
            )
        )
        conn.commit()
        conn.close()
        log_action("PASSWORD_CHANGE", "User changed their password")
        flash("Password changed successfully!", "success")
        return redirect(url_for("change_password"))
    return render_template("change_password.html")
# Request password reset
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        # Always show the same response to avoid revealing registered emails.
        message = (
            "If an account exists for that email, "
            "password reset instructions will be provided."
        )

        conn = get_db()

        user = conn.execute(
            "SELECT id FROM users WHERE LOWER(email) = ?",
            (email,)
        ).fetchone()

        reset_link = None

        if user:
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            expiry = (
                datetime.now(timezone.utc) + timedelta(minutes=30)
            ).isoformat()

            conn.execute(
                "UPDATE password_resets SET used = 1 WHERE user_id = ?",
                (user["id"],)
            )

            conn.execute("""
                INSERT INTO password_resets
                (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
            """, (
                user["id"],
                token_hash,
                expiry
            ))

            reset_link = url_for(
                "reset_password",
                token=token,
                _external=True
            )

        if MAIL_USERNAME and MAIL_PASSWORD:
            try:
                send_reset_email(email, reset_link)
            except Exception:
                app.logger.exception("Password reset email could not be sent.")

        conn.commit()
        conn.close()

        app.logger.info(message)

        if reset_link and app.debug:
            app.logger.warning("Development password reset link: %s", reset_link)

        flash(message, "info")
        return redirect(url_for("forgot_password"))

    return render_template("forgot_password.html")


# Reset password
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_db()

    reset = conn.execute("""
        SELECT * FROM password_resets
        WHERE token_hash = ? AND used = 0
    """, (token_hash,)).fetchone()

    if reset is None:
        conn.close()
        return "Invalid or expired reset link.", 400

    expiry = datetime.fromisoformat(reset["expires_at"])

    if datetime.now(timezone.utc) > expiry:
        conn.close()
        return "Invalid or expired reset link.", 400

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if len(password) < 8:
            conn.close()
            return render_template(
                "reset_password.html",
                token=token,
                error="Password must contain at least 8 characters."
            )

        if password != confirm:
            conn.close()
            return render_template(
                "reset_password.html",
                token=token,
                error="Passwords do not match."
            )

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (
                generate_password_hash(password),
                reset["user_id"]
            )
        )
        conn.execute(
            "UPDATE password_resets SET used = 1 WHERE id = ?",
            (reset["id"],)
        )
        conn.commit()
        conn.close()
        flash("Password reset successfully. Please log in.", "success")
        return redirect(url_for("login"))
    conn.close()
    return render_template(
        "reset_password.html",
        token=token
    )
@app.route("/logout")
def logout():
    user_id = session.get("user_id")
    try:
        if user_id:
            conn = get_db()
            user = conn.execute(
                "SELECT id FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()
            conn.close()
            if user:
                log_action("LOGOUT", "User logged out successfully")
    except (sqlite3.Error, psycopg.Error):
        pass
    finally:
        session.clear()
    return redirect(url_for("login"))
# Initialize database
create_table()
if __name__ == "__main__":
    app.run(debug=True)
