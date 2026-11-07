
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash
import sqlite3
import os
import uuid

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)

app.secret_key = os.environ.get("TRUSTVAULT_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("TRUSTVAULT_SECRET_KEY is not set!")

csrf = CSRFProtect(app)

app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg"}


# Database connection
def get_db():
    conn = sqlite3.connect("trustvault.db")
    conn.row_factory = sqlite3.Row
    return conn


# Create database tables
def create_table():

    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    try:
        conn.execute("""
            ALTER TABLE users
            ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
        """)
    except sqlite3.OperationalError:
        pass

    conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            document_name TEXT NOT NULL,
            filename TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    admin_email = os.environ.get("TRUSTVAULT_ADMIN_EMAIL", "").strip().lower()

    if admin_email:
        conn.execute(
            "UPDATE users SET role = 'admin' WHERE LOWER(email) = ?",
            (admin_email,)
        )
    conn.close()
def log_action(action, details=""):
    user_id = session.get("user_id")

    conn = get_db()

    conn.execute("""
        INSERT INTO audit_logs (user_id, action, details)
        VALUES (?, ?, ?)
    """, (user_id, action, details))

    conn.commit()
    conn.close()


# Home page
@app.route("/")
def home():
    return render_template("index.html")


# Admin Dashboard
@app.route("/admin")
def admin_dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    user = conn.execute(
        "SELECT role FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if user is None or user["role"] != "admin":
        conn.close()
        return "Access Denied: Admins only.", 403

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
        SELECT documents.id,
               documents.document_name,
               documents.filename,
               documents.upload_date,
               users.full_name,
               users.email
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
# Admin Audit Logs
@app.route("/admin/audit-logs")
def audit_logs():

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    user = conn.execute(
        "SELECT role FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if user is None or user["role"] != "admin":
        conn.close()
        return "Access Denied: Admins only.", 403

    logs = conn.execute("""
        SELECT audit_logs.id,
               audit_logs.action,
               audit_logs.details,
               audit_logs.timestamp,
               users.full_name,
               users.email
        FROM audit_logs
        LEFT JOIN users ON audit_logs.user_id = users.id
        ORDER BY audit_logs.id DESC
    """).fetchall()

    conn.close()

    return render_template(
        "audit_logs.html",
        logs=logs
    )
# Admin Management - Change User Roles
@app.route("/admin/manage-user/<int:user_id>", methods=["POST"])
def manage_user(user_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    admin = conn.execute(
        "SELECT role FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if admin is None or admin["role"] != "admin":
        conn.close()
        return "Access Denied: Admins only.", 403

    new_role = request.form.get("role")

    if new_role not in ["admin", "user"]:
        conn.close()
        return "Invalid role.", 400

    target = conn.execute(
        "SELECT id, role FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    if target is None:
        conn.close()
        return "User not found.", 404

    # Admin cannot change their own role
    if user_id == session["user_id"]:
        conn.close()
        return "You cannot change your own admin role.", 403

    # Keep at least one admin account
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

        if password != confirm:
            return render_template(
                "register.html",
                error="Warning: Passwords do not match. Please try again."
            )

        admin_email = os.environ.get(
            "TRUSTVAULT_ADMIN_EMAIL", ""
        ).strip().lower()

        role = "admin" if email == admin_email and admin_email else "user"

        password_hash = generate_password_hash(password)

        conn = get_db()

        try:
            conn.execute(
                """
                INSERT INTO users
                (full_name, email, password_hash, role)
                VALUES (?, ?, ?, ?)
                """,
                (name, email, password_hash, role)
            )

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()

            return render_template(
                "register.html",
                error="Email already registered."
            )

        conn.close()

        return redirect(url_for("login"))

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user["password_hash"], password):

            session["user_id"] = user["id"]
            session["user_name"] = user["full_name"]
            log_action(
                "LOGIN",
                "User logged in successfully"
            )
            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid email or password."
        )

    return render_template("login.html")


# User Dashboard
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

    storage_mb = round(storage_bytes / (1024 * 1024), 2)

    return render_template(
        "dashboard.html",
        name=session["user_name"],
        total_documents=total_documents,
        storage_mb=storage_mb,
        is_admin=user and user["role"] == "admin"
    )


# Upload documents
@app.route("/upload", methods=["GET", "POST"])
def upload():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        document_name = request.form.get("document_name", "").strip()
        file = request.files.get("document")

        if not document_name or not file or not file.filename:
            return "Please provide a document name and select a file."

        original_name = secure_filename(file.filename)

        if "." not in original_name:
            return "Invalid file type."

        extension = original_name.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            return "File type not allowed."

        unique_filename = str(uuid.uuid4()) + "." + extension

        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            unique_filename
        )

        file.save(file_path)

        conn = get_db()

        conn.execute(
            """
            INSERT INTO documents (user_id, document_name, filename)
            VALUES (?, ?, ?)
            """,
            (session["user_id"], document_name, unique_filename)
        )

        conn.commit()
        conn.close()
        log_action(
            "UPLOAD",
            f"Uploaded document: {document_name}"
        )

        return redirect(url_for("documents"))

    return render_template("upload.html")


# My Documents with Search
@app.route("/documents")
def documents():

    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip()

    conn = get_db()

    if search:

        user_documents = conn.execute(
            """
            SELECT * FROM documents
            WHERE user_id = ? AND document_name LIKE ?
            ORDER BY upload_date DESC
            """,
            (session["user_id"], "%" + search + "%")
        ).fetchall()

    else:

        user_documents = conn.execute(
            """
            SELECT * FROM documents
            WHERE user_id = ?
            ORDER BY upload_date DESC
            """,
            (session["user_id"],)
        ).fetchall()

    conn.close()

    return render_template(
        "documents.html",
        documents=user_documents,
        search=search
    )


# Download user's own documents
@app.route("/download/<int:document_id>")
def download_document(document_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    document = conn.execute(
        """
        SELECT * FROM documents
        WHERE id = ? AND user_id = ?
        """,
        (document_id, session["user_id"])
    ).fetchone()

    conn.close()

    if document is None:
        return "Document not found."
    log_action(
        "DOWNLOAD",
        f"Downloaded document: {document['document_name']}"
    )
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document["filename"],
        as_attachment=True
    )


# Admin Download Documents
@app.route("/admin/download/<int:document_id>")
def admin_download(document_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()

    user = conn.execute(
        "SELECT role FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if user is None or user["role"] != "admin":
        conn.close()
        return "Access Denied", 403

    document = conn.execute(
        "SELECT * FROM documents WHERE id = ?",
        (document_id,)
    ).fetchone()

    conn.close()

    if document is None:
        return "Document not found.", 404
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

    document = conn.execute(
        """
        SELECT * FROM documents
        WHERE id = ? AND user_id = ?
        """,
        (document_id, session["user_id"])
    ).fetchone()

    if document is None:
        conn.close()
        return "Document not found."

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document["filename"]
    )

    if os.path.exists(file_path):
        os.remove(file_path)

    conn.execute(
        "DELETE FROM documents WHERE id = ? AND user_id = ?",
        (document_id, session["user_id"])
    )

    conn.commit()
    conn.close()
    log_action(
        "DELETE",
        f"Deleted document: {document['document_name']}"
    )
    return redirect(url_for("documents"))


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

        if not check_password_hash(user["password_hash"], current_password):
            conn.close()
            flash("Your current password is incorrect.", "error")
            return redirect(url_for("change_password"))

        if len(new_password) < 8:
            conn.close()
            flash("New password must contain at least 8 characters.", "error")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            conn.close()
            flash("New passwords do not match.", "error")
            return redirect(url_for("change_password"))

        if current_password == new_password:
            conn.close()
            flash("New password must be different from your current password.", "error")
            return redirect(url_for("change_password"))

        new_hash = generate_password_hash(new_password)

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_hash, session["user_id"])
        )

        conn.commit()
        conn.close()
        log_action(
            "PASSWORD_CHANGE",
            "User changed their password"
        )
        flash("Password changed successfully!", "success")
        return redirect(url_for("change_password"))

    return render_template("change_password.html")

# Logout
@app.route("/logout")
def logout():

    if session.get("user_id"):
        log_action(
            "LOGOUT",
            "User logged out successfully"
        )

    session.clear()

    return redirect(url_for("login"))
# Initialize database
create_table()

# Run application locally
if __name__ == "__main__":
    app.run(debug=True)