# Installation Guide 📦

This guide will help you get StudySync up and running on your machine in minutes.

## 🎯 Quick Setup (Recommended)

### For Windows Users
1. Open Command Prompt or PowerShell in the project directory
2. Run the setup script:
   ```cmd
   setup.bat
   ```
3. Start the application:
   ```cmd
   python app.py
   ```

### For Mac/Linux Users
1. Open Terminal in the project directory
2. Make the setup script executable:
   ```bash
   chmod +x setup.sh
   ```
3. Run the setup script:
   ```bash
   ./setup.sh
   ```
4. Start the application:
   ```bash
   python3 app.py
   ```

### Alternative: Python Setup Script
Works on all platforms:
```bash
python setup.py
python app.py
```

---

## 📋 Manual Installation

If you prefer to set things up manually or the automated scripts don't work:

### Step 1: Verify Python
Check that Python 3.8+ is installed:
```bash
python --version
# or
python3 --version
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
# or
pip3 install -r requirements.txt
```

Required packages:
- Flask 3.0+
- (All dependencies are listed in `requirements.txt`)

### Step 3: Initialize Database
```bash
python init_db.py
```

This creates `sessions.db` with three tables:
- `sessions` - Study session information
- `rsvps` - Participant RSVPs
- `messages` - Session chat messages

### Step 4: Run Application
```bash
python app.py
```

You should see:
```
* Serving Flask app 'app'
* Debug mode: on
* Running on http://127.0.0.1:5000
```

### Step 5: Open Browser
Navigate to: **http://127.0.0.1:5000**

---

## 🐛 Troubleshooting

### Database Errors
**Error:** `sqlite3.OperationalError: no such table: sessions`

**Solution:**
1. Delete the database file:
   ```bash
   rm sessions.db        # Mac/Linux
   del sessions.db       # Windows
   ```
2. Reinitialize:
   ```bash
   python init_db.py
   ```

### Port Already in Use
**Error:** `OSError: [Errno 48] Address already in use`

**Solution:**
- Stop other Flask applications
- Or change the port in `app.py`:
  ```python
  app.run(debug=True, port=5001)  # Use different port
  ```

### Module Not Found
**Error:** `ModuleNotFoundError: No module named 'flask'`

**Solution:**
```bash
pip install flask
# or install all dependencies
pip install -r requirements.txt
```

### Permission Denied (Linux/Mac)
**Error:** Permission denied when running scripts

**Solution:**
```bash
chmod +x setup.sh
./setup.sh
```

### Python Version Issues
**Error:** Syntax errors or compatibility issues

**Solution:**
- Ensure Python 3.8 or higher is installed
- Use `python3` instead of `python` on Mac/Linux
- Check your version: `python --version`

---

## 🔧 Development Setup

### Using Virtual Environment (Recommended)

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python init_db.py
python app.py
```

**Mac/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python init_db.py
python app.py
```

### Environment Variables
For production, set a secure secret key:
```bash
export FLASK_SECRET_KEY="your-secret-key-here"  # Mac/Linux
set FLASK_SECRET_KEY="your-secret-key-here"     # Windows
```

Then update `app.py` to use it:
```python
import os
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key')
```

---

## ✅ Verification

After setup, verify everything works:

1. **Homepage loads**: http://127.0.0.1:5000
2. **Create session**: Click "Create Study Session" button
3. **Fill form**: Enter session details with date/time
4. **View session**: Should redirect to homepage showing new session
5. **Click session**: Should open detail page with RSVP and chat

If all steps work, you're ready to go! 🎉

---

## 📚 Additional Resources

- **README.md** - Project overview and features
- **PROJECT_PLAN.md** - Development roadmap and demo guide
- **schema.sql** - Database structure
- **requirements.txt** - Python dependencies

---

## 🆘 Still Having Issues?

If you encounter problems not covered here:

1. Check that all files are present (app.py, schema.sql, init_db.py, requirements.txt)
2. Verify you're in the correct directory
3. Try the manual installation steps
4. Check Python and pip are properly installed
5. Ensure no firewall is blocking port 5000

For persistent issues, check the error message carefully - it usually indicates what's wrong!
