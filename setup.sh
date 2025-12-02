#!/bin/bash
#
# StudyFlow Setup Script for Unix-like systems (Linux/macOS)
#
# This script automates the complete setup process for StudyFlow after cloning from GitHub.
# It creates a virtual environment, installs dependencies, sets up the database, and configures
# the application with a .env file for secure configuration.
#
# Author: StudyFlow Team
# Version: 1.0.0
# Date: December 2025
#
# Requirements:
# - Python 3.8 or higher
# - pip (Python package manager)
# - Internet connection for package downloads

set -e  # Exit on error

# Configuration
VENV_DIR="venv"
PYTHON_VERSION_REQUIRED="3.8"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Output functions
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_info() { echo -e "${CYAN}ℹ️  $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_step() { echo -e "\n${MAGENTA}🔹 $1${NC}"; }

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              StudyFlow Setup Script v1.0                  ║
║         Automated Installation & Configuration            ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Step 1: Check Python installation
print_step "Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed or not in PATH."
    print_info "Please install Python 3.8+ from https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | grep -oP '\d+\.\d+' | head -1)
if [ "$(printf '%s\n' "$PYTHON_VERSION_REQUIRED" "$PYTHON_VERSION" | sort -V | head -n1)" != "$PYTHON_VERSION_REQUIRED" ]; then
    print_error "Python version $PYTHON_VERSION is installed, but $PYTHON_VERSION_REQUIRED or higher is required."
    print_info "Please install Python 3.8+ from https://www.python.org/downloads/"
    exit 1
fi

print_success "Python $PYTHON_VERSION detected"

# Step 2: Create virtual environment
print_step "Creating virtual environment..."
if [ -d "$VENV_DIR" ]; then
    print_warning "Virtual environment already exists. Removing old environment..."
    rm -rf "$VENV_DIR"
fi

python3 -m venv "$VENV_DIR"
print_success "Virtual environment created successfully"

# Step 3: Activate virtual environment
print_step "Activating virtual environment..."
source "$VENV_DIR/bin/activate"
print_success "Virtual environment activated"

# Step 4: Upgrade pip
print_step "Upgrading pip to latest version..."
python -m pip install --upgrade pip || print_warning "Failed to upgrade pip, continuing anyway..."
print_success "Pip upgraded successfully"

# Step 5: Install dependencies
print_step "Installing Python dependencies from requirements.txt..."
if [ ! -f "requirements.txt" ]; then
    print_error "requirements.txt not found! Make sure you're in the StudyFlow directory."
    exit 1
fi

pip install -r requirements.txt
print_success "All dependencies installed successfully"

# Step 6: Create .env file
print_step "Creating .env configuration file..."
if [ -f ".env" ]; then
    print_warning ".env file already exists. Creating backup as .env.backup"
    cp .env .env.backup
fi

# Generate a secure random secret key
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

cat > .env << EOF
# StudyFlow Environment Configuration
# Generated on $(date '+%Y-%m-%d %H:%M:%S')

# Flask Configuration
SECRET_KEY=$SECRET_KEY

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
EOF

print_success ".env file created with secure configuration"

# Step 7: Initialize database
print_step "Initializing database from schema.sql..."
if [ ! -f "schema.sql" ]; then
    print_error "schema.sql not found! Database cannot be initialized."
    exit 1
fi

# Check if database already exists
if [ -f "sessions.db" ]; then
    print_warning "Database sessions.db already exists."
    read -p "Do you want to recreate it? This will DELETE all existing data! (yes/no): " response
    if [ "$response" != "yes" ]; then
        print_info "Skipping database initialization. Using existing database."
    else
        rm -f sessions.db
        print_info "Old database removed. Creating new database..."
        
        python3 << 'PYEOF'
import sqlite3
with open('schema.sql', 'r', encoding='utf-8') as f:
    schema = f.read()
conn = sqlite3.connect('sessions.db')
conn.executescript(schema)
conn.commit()
conn.close()
print('Database created successfully')
PYEOF
        
        print_success "Database initialized successfully"
    fi
else
    python3 << 'PYEOF'
import sqlite3
with open('schema.sql', 'r', encoding='utf-8') as f:
    schema = f.read()
conn = sqlite3.connect('sessions.db')
conn.executescript(schema)
conn.commit()
conn.close()
print('Database created successfully')
PYEOF
    
    print_success "Database initialized successfully"
fi

# Step 8: Create required directories
print_step "Creating required directories..."
directories=("static/uploads" "static/avatars" "static/files" "flask_session")
for dir in "${directories[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        print_success "Created directory: $dir"
    else
        print_info "Directory already exists: $dir"
    fi
done

# Step 9: Final setup summary
echo -e "${GREEN}"
cat << "EOF"

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
   
   Linux/macOS:
   source venv/bin/activate
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

EOF
echo -e "${NC}"

print_success "Setup script completed. Happy studying with StudyFlow! 🚀"
