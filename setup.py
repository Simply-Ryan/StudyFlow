#!/usr/bin/env python3
"""
Quick setup script for StudySync application.
Run this after cloning the repository to set up everything automatically.
"""

import subprocess
import sys
import os

def print_step(message):
    """Print a formatted step message"""
    print(f"\n{'='*60}")
    print(f"  {message}")
    print('='*60)

def check_python_version():
    """Ensure Python version is 3.8 or higher"""
    print_step("Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Error: Python 3.8+ required. You have {version.major}.{version.minor}")
        sys.exit(1)
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} detected")

def install_dependencies():
    """Install required Python packages"""
    print_step("Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        sys.exit(1)

def initialize_database():
    """Initialize the SQLite database"""
    print_step("Initializing database...")
    try:
        # Remove old database if it exists
        if os.path.exists("sessions.db"):
            os.remove("sessions.db")
            print("🗑️  Removed old database")
        
        subprocess.check_call([sys.executable, "init_db.py"])
        print("✅ Database initialized successfully")
    except subprocess.CalledProcessError:
        print("❌ Failed to initialize database")
        sys.exit(1)

def main():
    """Run the complete setup process"""
    print("\n🚀 StudySync Setup Script")
    print("This will set up your development environment\n")
    
    # Run setup steps
    check_python_version()
    install_dependencies()
    initialize_database()
    
    # Success message
    print_step("Setup Complete! 🎉")
    print("\n📝 Next Steps:")
    print("   1. Run the application: python app.py")
    print("   2. Open your browser to: http://127.0.0.1:5000")
    print("   3. Start creating study sessions!\n")

if __name__ == "__main__":
    main()
