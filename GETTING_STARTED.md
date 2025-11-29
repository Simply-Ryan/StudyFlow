# Getting Started with StudySync 🚀

Welcome! This guide will get you from clone to running application in under 2 minutes.

## ⚡ Super Quick Start

### Option 1: Windows (Easiest)
```cmd
git clone https://github.com/Simply-Ryan/Simply-Ryan.github.io.git
cd Simply-Ryan.github.io\Visual_Studio_Code\WebApps\HackDecouverteStudyApp
start.bat
```
The script will automatically run setup if needed, then start the app!

### Option 2: Mac/Linux (Easiest)
```bash
git clone https://github.com/Simply-Ryan/Simply-Ryan.github.io.git
cd Simply-Ryan.github.io/Visual_Studio_Code/WebApps/HackDecouverteStudyApp
chmod +x start.sh
./start.sh
```

### Option 3: Manual (Any OS)
```bash
# Clone the repo
git clone https://github.com/Simply-Ryan/Simply-Ryan.github.io.git
cd Simply-Ryan.github.io/Visual_Studio_Code/WebApps/HackDecouverteStudyApp

# Run automated setup
python setup.py

# Start the app
python app.py
```

Open your browser to: **http://127.0.0.1:5000**

---

## 📋 What You Need

Before you start, make sure you have:

- ✅ **Python 3.8+** ([Download](https://www.python.org/downloads/))
- ✅ **Git** ([Download](https://git-scm.com/downloads))
- ✅ **pip** (comes with Python)

### Check Your Setup
```bash
python --version    # Should show 3.8 or higher
git --version       # Should show git version
pip --version       # Should show pip version
```

---

## 🎓 First Time Using the App?

After setup completes and the server starts:

1. **Open browser to http://127.0.0.1:5000**
2. **Click "Create Study Session"**
3. Fill in the form:
   - Title: "Calculus Study Group"
   - Subject: Mathematics
   - Date: Tomorrow
   - Time: 2:00 PM
   - Type: Remote
   - Max Participants: 5
   - Meeting Link: Your Zoom/Google Meet link
4. **Click "Create Session"**
5. You'll see your session on the homepage!
6. **Click the session card** to view details
7. **Try the RSVP feature** by entering your name
8. **Send a message** in the chat

---

## 🐛 Something Wrong?

### Setup Failed?
- **Missing Python?** Install from [python.org](https://www.python.org/downloads/)
- **Permission errors?** Run terminal as administrator (Windows) or use `sudo` (Mac/Linux)
- **Network issues?** Check your internet connection for pip install

### App Won't Start?
- **Port 5000 busy?** Change to port 5001 in `app.py`
- **Database errors?** Delete `sessions.db` and run setup again
- **Import errors?** Reinstall dependencies: `pip install -r requirements.txt`

### Still Stuck?
Check out [INSTALL.md](INSTALL.md) for detailed troubleshooting.

---

## 📁 Project Files Explained

| File | Purpose |
|------|---------|
| `app.py` | Main Flask application - **run this to start** |
| `setup.py` / `setup.bat` / `setup.sh` | Automated setup scripts |
| `start.bat` / `start.sh` | Smart start scripts (auto-setup if needed) |
| `init_db.py` | Database initialization |
| `schema.sql` | Database structure definition |
| `requirements.txt` | Python dependencies list |
| `README.md` | Project overview and features |
| `INSTALL.md` | Detailed installation guide |

---

## 🎯 What's Next?

Once you have the app running:

1. **Explore the features** - Create sessions, RSVP, send messages
2. **Check the code** - Look at `app.py` to understand the routes
3. **Customize** - Modify `style.css` to change colors and styling
4. **Extend** - Add new features (see PROJECT_PLAN.md for ideas)

---

## 💡 Tips for Success

- **Use a virtual environment** for cleaner dependency management
- **Read the code** - It's well-commented and easy to follow
- **Experiment** - The database resets easily, so feel free to test
- **Check PROJECT_PLAN.md** - See demo flow and feature ideas

---

## ✨ You're Ready!

That's it! You should now have StudySync running locally. Happy studying! 📚

Need more details? Check out:
- [README.md](README.md) - Full project documentation
- [INSTALL.md](INSTALL.md) - Detailed installation guide
- [PROJECT_PLAN.md](PROJECT_PLAN.md) - Development roadmap
