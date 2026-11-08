# TrustVault – Secure Document Management System

TrustVault is a secure web-based document management platform built using Python Flask. It helps users upload, organize, search, download, delete, and share confidential documents with controlled access.

## Features

### User Features
- User registration and login
- Secure password hashing
- Personal dashboard
- Upload and store documents
- Search and manage documents
- Download and delete personal documents
- Share documents with other registered users
- Change password
- Password reset functionality

### Admin Features
- Admin dashboard
- View registered users
- View uploaded documents
- Download documents
- Promote users to administrator and demote administrators
- Protection against unauthorized role changes

### Security Features
- Password hashing
- CSRF protection
- Session-based authentication
- Role-based access control
- Document ownership verification
- Document sharing permissions
- Protection against unauthorized document access
- File extension validation
- 10 MB upload size limit
- Audit logs recording user activities
- Security response headers
- Secret key stored in an environment variable

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web framework |
| SQLite | Local development database |
| PostgreSQL | Production database |
| HTML | Page structure |
| CSS | Styling |
| JavaScript | Interactive features |
| Pytest | Automated testing |
| Flask-WTF | CSRF protection |
| Gunicorn | Production web server |

## Project Structure

```text
TrustVault/
├── static/
├── templates/
├── tests/
│   └── test_app.py
├── app.py
├── requirements.txt
├── Procfile
├── PROMPTS.md
├── README.md
└── .gitignore
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/rajalakshmiundavalli-lab/TrustVault.git
cd TrustVault
```

### 2. Create a virtual environment

```bash
py -m venv venv
```

### 3. Activate the virtual environment on Windows

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure the secret key

In PowerShell:

```powershell
$env:TRUSTVAULT_SECRET_KEY = "your-private-secret-key"
```

Use a strong private key. Never commit secrets or passwords to GitHub.

### 6. Run the application

```bash
python app.py
```

Open your browser:

```text
http://127.0.0.1:5000
```

## Running Automated Tests

Run the following command:

```bash
python -m pytest -v
```

The project has successfully passed **15 automated tests** covering registration, login, document management, access control, admin permissions, and password validation.

## Live Deployment

TrustVault is deployed using Render.

Live URL: https://trustvault-1xjr.onrender.com

## Project Status

Core application features have been implemented, tested, and deployed.

## Future Enhancements
- Email verification
- Enhanced document preview
- Advanced document search and filtering
- Additional security monitoring

## Author

Developed as an individual academic project.

