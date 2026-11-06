# TrustVault – Secure Document Management System

TrustVault is a secure web-based document management platform built using Python Flask and SQLite. It allows users to upload, manage, search, download, and delete documents while protecting confidential files through authentication and access control.

## Features

### User Features
- User registration and login
- Secure password hashing
- Personal dashboard
- Document upload and storage
- Search documents by name
- Download personal documents
- Delete uploaded documents
- Change password

### Admin Features
- Admin dashboard
- View registered users
- View uploaded documents
- Download documents
- Promote users to admin
- Demote admins to regular users
- Protection against unauthorized role changes

### Security Features
- Password hashing
- CSRF protection
- Session-based authentication
- Role-based access control
- Document ownership verification
- File extension validation
- 10 MB upload size limit
- Secret key stored in an environment variable

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web framework |
| SQLite | Database |
| HTML | Page structure |
| CSS | Styling |
| JavaScript | Interactive features |
| Pytest | Automated testing |
| Flask-WTF | CSRF protection |

## Project Structure

```text
TrustVault/
├── static/
│   └── style.css
├── templates/
├── uploads/
├── tests/
│   └── test_app.py
├── venv/
├── app.py
├── trustvault.db
├── .gitignore
└── README.md
```

## Installation and Setup

1. Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd trustvault
```

2. Create a virtual environment:

```bash
python -m venv venv
```

3. Activate it on Windows:

```powershell
.\venv\Scripts\Activate.ps1
```

4. Install dependencies:

```bash
pip install Flask Flask-WTF pytest
```

5. Set the secret key in PowerShell:

```powershell
$env:TRUSTVAULT_SECRET_KEY = "your-secret-key"
```

Use a strong, private key. Never commit it to GitHub.

6. Start the application:

```bash
python app.py
```

7. Open your browser:

```text
http://127.0.0.1:5000
```

## Running Automated Tests

Run:

```bash
python -m pytest -v
```

The project currently includes 12 automated tests covering registration, login, document management, access control, and password validation.

## Project Status

Development in progress.

## Future Enhancements

- Email verification
- Forgot password functionality
- Document sharing with permission controls
- Audit logs
- Improved deployment configuration

## Author

Developed as an individual academic project.