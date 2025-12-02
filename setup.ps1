#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Automated setup script for StudyFlow web application (Windows/PowerShell)

.DESCRIPTION
    This script automates the complete setup process for StudyFlow after cloning from GitHub.
    It creates a virtual environment, installs dependencies, sets up the database, and configures
    the application with a .env file for secure configuration.

.NOTES
    Author: StudyFlow Team
    Version: 1.0.0
    Date: December 2025
    
    Requirements:
    - Python 3.8 or higher
    - pip (Python package manager)
    - Internet connection for package downloads
#>

# Script configuration
$ErrorActionPreference = "Stop"
$VENV_DIR = "venv"
$PYTHON_VERSION_REQUIRED = [Version]"3.8"

# Color output functions
function Write-Success { param($Message) Write-Host "✅ $Message" -ForegroundColor Green }
function Write-Info { param($Message) Write-Host "ℹ️  $Message" -ForegroundColor Cyan }
function Write-Warning { param($Message) Write-Host "⚠️  $Message" -ForegroundColor Yellow }
function Write-Error { param($Message) Write-Host "❌ $Message" -ForegroundColor Red }
function Write-Step { param($Message) Write-Host "`n🔹 $Message" -ForegroundColor Magenta }

# Banner
Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              StudyFlow Setup Script v1.0                  ║
║         Automated Installation & Configuration            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Step 1: Check Python installation
Write-Step "Checking Python installation..."
try {
    $pythonCmd = Get-Command python -ErrorAction Stop
    $pythonVersion = python --version 2>&1 | Select-String -Pattern "Python ([\d.]+)" | ForEach-Object { $_.Matches.Groups[1].Value }
    $pythonVersionObj = [Version]$pythonVersion
    
    if ($pythonVersionObj -lt $PYTHON_VERSION_REQUIRED) {
        Write-Error "Python version $pythonVersion is installed, but $PYTHON_VERSION_REQUIRED or higher is required."
        Write-Info "Please install Python from https://www.python.org/downloads/"
        exit 1
    }
    
    Write-Success "Python $pythonVersion detected"
} catch {
    Write-Error "Python is not installed or not in PATH."
    Write-Info "Please install Python 3.8+ from https://www.python.org/downloads/"
    exit 1
}

# Step 2: Create virtual environment
Write-Step "Creating virtual environment..."
if (Test-Path $VENV_DIR) {
    Write-Warning "Virtual environment already exists. Removing old environment..."
    Remove-Item -Recurse -Force $VENV_DIR
}

python -m venv $VENV_DIR
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create virtual environment"
    exit 1
}
Write-Success "Virtual environment created successfully"

# Step 3: Activate virtual environment
Write-Step "Activating virtual environment..."
$activateScript = Join-Path $VENV_DIR "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    Write-Error "Activation script not found at: $activateScript"
    exit 1
}

& $activateScript
Write-Success "Virtual environment activated"

# Step 4: Upgrade pip
Write-Step "Upgrading pip to latest version..."
python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to upgrade pip, continuing anyway..."
}
Write-Success "Pip upgraded successfully"

# Step 5: Install dependencies
Write-Step "Installing Python dependencies from requirements.txt..."
if (-not (Test-Path "requirements.txt")) {
    Write-Error "requirements.txt not found! Make sure you're in the StudyFlow directory."
    exit 1
}

pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install dependencies"
    exit 1
}
Write-Success "All dependencies installed successfully"

# Step 6: Create .env file
Write-Step "Creating .env configuration file..."
if (Test-Path ".env") {
    Write-Warning ".env file already exists. Creating backup as .env.backup"
    Copy-Item .env .env.backup -Force
}

# Generate a secure random secret key
$secretKey = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 64 | ForEach-Object {[char]$_})

$envContent = @"
# StudyFlow Environment Configuration
# Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

# Flask Configuration
SECRET_KEY=$secretKey

# Database Configuration
DATABASE_URL=sqlite:///sessions.db

# AI Assistant Configuration (Optional)
# To enable AI features, set AI_ENABLED=true and provide your OpenAI API key
AI_ENABLED=false
OPENAI_API_KEY=
AI_MODEL=gpt-4o-mini
AI_MAX_TOKENS=1000

# Email Configuration (Optional - for notifications)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_DEFAULT_SENDER=

# Application Configuration
FLASK_ENV=development
DEBUG=true
"@

Set-Content -Path ".env" -Value $envContent
Write-Success ".env file created with secure configuration"

# Step 7: Initialize database
Write-Step "Initializing database from schema.sql..."
if (-not (Test-Path "schema.sql")) {
    Write-Error "schema.sql not found! Database cannot be initialized."
    exit 1
}

# Check if database already exists
if (Test-Path "sessions.db") {
    Write-Warning "Database sessions.db already exists."
    $response = Read-Host "Do you want to recreate it? This will DELETE all existing data! (yes/no)"
    if ($response -ne "yes") {
        Write-Info "Skipping database initialization. Using existing database."
    } else {
        Remove-Item "sessions.db" -Force
        Write-Info "Old database removed. Creating new database..."
        
        # Create database from schema
        python -c @"
import sqlite3
with open('schema.sql', 'r', encoding='utf-8') as f:
    schema = f.read()
conn = sqlite3.connect('sessions.db')
conn.executescript(schema)
conn.commit()
conn.close()
print('Database created successfully')
"@
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to initialize database"
            exit 1
        }
        Write-Success "Database initialized successfully"
    }
} else {
    python -c @"
import sqlite3
with open('schema.sql', 'r', encoding='utf-8') as f:
    schema = f.read()
conn = sqlite3.connect('sessions.db')
conn.executescript(schema)
conn.commit()
conn.close()
print('Database created successfully')
"@
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to initialize database"
        exit 1
    }
    Write-Success "Database initialized successfully"
}

# Step 8: Create required directories
Write-Step "Creating required directories..."
$directories = @("static/uploads", "static/avatars", "static/files", "flask_session")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Success "Created directory: $dir"
    } else {
        Write-Info "Directory already exists: $dir"
    }
}

# Step 9: Final setup summary
Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║            🎉 Setup Completed Successfully! 🎉            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

📋 Next Steps:

1. (Optional) Configure AI Assistant:
   - Edit .env file
   - Set AI_ENABLED=true
   - Add your OPENAI_API_KEY

2. (Optional) Configure Email Notifications:
   - Edit .env file
   - Set MAIL_USERNAME and MAIL_PASSWORD

3. Start the application:
   
   Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   python app.py
   
   Then open your browser to: http://localhost:5000

4. Create your first account and start collaborating!

📚 Documentation:
   - README.md - Full application documentation
   - config.py - Configuration reference
   - schema.sql - Database structure

🔧 Troubleshooting:
   - If you encounter port conflicts, edit app.py and change the port
   - For database issues, delete sessions.db and re-run this script
   - Check that all dependencies installed correctly with: pip list

💡 Tips:
   - Use 'deactivate' to exit the virtual environment
   - Keep your .env file secure and never commit it to version control
   - Backup your sessions.db file regularly

"@ -ForegroundColor Green

Write-Success "Setup script completed. Happy studying with StudyFlow! 🚀"
