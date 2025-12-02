# StudyFlow Setup Guide

This guide explains how to set up StudyFlow on your local machine after cloning from GitHub.

## Quick Start

We provide automated setup scripts for both Windows and Unix-like systems (Linux/macOS).

### Windows (PowerShell)

```powershell
# Clone the repository
git clone https://github.com/yourusername/StudyFlow.git
cd StudyFlow

# Run the setup script
.\setup.ps1
```

### Linux/macOS (Bash)

```bash
# Clone the repository
git clone https://github.com/yourusername/StudyFlow.git
cd StudyFlow

# Make the setup script executable
chmod +x setup.sh

# Run the setup script
./setup.sh
```

## What the Setup Script Does

The automated setup script performs the following steps:

1. **Checks Python Installation** - Verifies Python 3.8+ is installed
2. **Creates Virtual Environment** - Isolates project dependencies
3. **Installs Dependencies** - Installs all required Python packages from `requirements.txt`
4. **Generates Configuration** - Creates a `.env` file with secure settings
5. **Initializes Database** - Sets up SQLite database from `schema.sql`
6. **Creates Directories** - Makes folders for uploads, avatars, and sessions
7. **Provides Instructions** - Shows next steps to start using StudyFlow

## Manual Setup (Alternative)

If you prefer to set up manually or encounter issues with the automated script:

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

### Step-by-Step Manual Setup

#### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/StudyFlow.git
cd StudyFlow
```

#### 2. Create Virtual Environment

**Windows:**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 4. Create .env Configuration File

Create a file named `.env` in the root directory with the following content:

```env
# Flask Configuration
SECRET_KEY=your-secret-key-here-generate-a-random-one

# Database Configuration
DATABASE_URL=sqlite:///sessions.db

# AI Assistant Configuration (Optional)
AI_ENABLED=false
OPENAI_API_KEY=
AI_MODEL=gpt-4o-mini
AI_MAX_TOKENS=1000

# Email Configuration (Optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_DEFAULT_SENDER=

# Application Configuration
FLASK_ENV=development
DEBUG=true
```

**Generate a secure SECRET_KEY:**

**Python:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

**PowerShell:**
```powershell
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 64 | ForEach-Object {[char]$_})
```

#### 5. Initialize Database

**Using Python:**
```bash
python -c "import sqlite3; conn = sqlite3.connect('sessions.db'); conn.executescript(open('schema.sql').read()); conn.close()"
```

**Using SQLite command line:**
```bash
sqlite3 sessions.db < schema.sql
```

#### 6. Create Required Directories

**Windows:**
```powershell
New-Item -ItemType Directory -Force static/uploads, static/avatars, static/files, flask_session
```

**Linux/macOS:**
```bash
mkdir -p static/uploads static/avatars static/files flask_session
```

## Running the Application

After setup is complete:

1. **Activate the virtual environment** (if not already active):
   - Windows: `.\venv\Scripts\Activate.ps1`
   - Linux/macOS: `source venv/bin/activate`

2. **Start the Flask application:**
   ```bash
   python app.py
   ```

3. **Open your browser** and navigate to:
   ```
   http://localhost:5000
   ```

4. **Create an account** and start using StudyFlow!

## Optional Configuration

### Enable AI Assistant

To use the AI study assistant features:

1. Get an API key from [OpenAI](https://platform.openai.com/api-keys)
2. Edit your `.env` file:
   ```env
   AI_ENABLED=true
   OPENAI_API_KEY=sk-your-actual-api-key-here
   ```
3. Restart the application

### Enable Email Notifications

To send email notifications for study session invitations and reminders:

1. Set up an email account (Gmail recommended)
2. For Gmail, generate an [App Password](https://support.google.com/accounts/answer/185833)
3. Edit your `.env` file:
   ```env
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password
   MAIL_DEFAULT_SENDER=your-email@gmail.com
   ```
4. Restart the application

## Troubleshooting

### Common Issues

**"Python not found"**
- Install Python 3.8+ from [python.org](https://www.python.org/downloads/)
- Make sure Python is added to your PATH

**"Permission denied" on Linux/macOS**
- Run: `chmod +x setup.sh`
- Or use: `bash setup.sh`

**Database errors**
- Delete `sessions.db` file
- Re-run the setup script or manually initialize the database

**Port 5000 already in use**
- Edit `app.py` and change the port in the last line:
  ```python
  socketio.run(app, debug=True, port=5001)  # Use a different port
  ```

**Module import errors**
- Make sure virtual environment is activated
- Re-run: `pip install -r requirements.txt`

### Getting Help

If you encounter issues:

1. Check that all prerequisites are installed
2. Ensure you're in the correct directory
3. Verify the virtual environment is activated
4. Review error messages carefully
5. Check the application logs

## Directory Structure

After setup, your project structure should look like this:

```
StudyFlow/
├── venv/                    # Virtual environment (not committed)
├── static/
│   ├── uploads/            # User uploaded files
│   ├── avatars/            # User profile pictures
│   ├── files/              # Session shared files
│   ├── css/                # Stylesheets
│   └── js/                 # JavaScript files
├── templates/              # HTML templates
├── flask_session/          # Session data (not committed)
├── app.py                  # Main application
├── config.py               # Configuration
├── schema.sql              # Database schema
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (not committed)
├── sessions.db             # SQLite database (not committed)
├── setup.ps1               # Windows setup script
├── setup.sh                # Linux/macOS setup script
├── SETUP.md                # This file
└── README.md               # Project documentation
```

## Security Notes

⚠️ **Important Security Reminders:**

- **Never commit** `.env` file to version control
- **Never commit** `sessions.db` to version control
- **Keep your SECRET_KEY secure** and unique
- **Use strong passwords** for user accounts
- **Use App Passwords** for email, not your main password
- **Keep your OpenAI API key private**

## Next Steps

After successful setup:

1. Create your first user account
2. Explore the features:
   - Create study sessions
   - Use the real-time whiteboard
   - Try flashcards and notes
   - Start video/audio calls
   - Chat with AI assistant (if configured)
3. Invite friends to collaborate!

## Development

To contribute or develop features:

1. Create a new branch: `git checkout -b feature-name`
2. Make your changes
3. Test thoroughly
4. Commit: `git commit -m "Description"`
5. Push: `git push origin feature-name`
6. Create a Pull Request

## Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Socket.IO Documentation](https://socket.io/docs/)
- [WebRTC Documentation](https://webrtc.org/)
- [Python Documentation](https://docs.python.org/3/)

---

**Happy studying with StudyFlow! 🚀📚**
