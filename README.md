# 📚 StudyFlow

A collaborative study session management web application built for **HackDécouverte** (HackConcordia). Create study sessions, invite friends, share materials, chat in real-time, and stay organized with automatic reminders!

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## ✨ Features

### 🎯 Core Functionality
- **User Authentication**: Secure signup/login with password hashing
- **Study Sessions**: Create, edit, and manage study sessions with date/time/location
- **Invitations System**: Invite users or request to join sessions
- **RSVP Management**: Accept/decline invitations and manage attendees
- **Access Control**: Only participants can view session details

### 💬 Real-Time Collaboration
- **WebSocket Communication**: Instant message delivery with Socket.IO
- **Live Chat**: Real-time messaging with typing indicators
- **Message Reactions**: React to messages with 8 emoji options (👍❤️😂🎉😕🔥👏✅)
- **Message Threading**: Reply to specific messages to create threaded conversations
- **Typing Indicators**: See "user is typing..." in real-time
- **User Presence**: Live online/offline status with green/gray indicators
- **Chat File Sharing**: Upload files directly in chat with instant preview
- **File Preview Modal**: Full-screen image and PDF viewer with zoom/download

### 📝 Collaborative Note-Taking
- **Rich Text Editor**: TinyMCE WYSIWYG editor with full formatting
- **Auto-Save**: Automatic saves every 30 seconds while editing
- **Draft Recovery**: Restore unsaved drafts from localStorage
- **Real-Time Viewers**: See who's currently viewing each note
- **Version Tracking**: Updated timestamps on all note changes
- **Public/Private Notes**: Control note visibility

### 🔔 Notification System
- **In-App Notifications**: Bell icon in navbar with unread count badge
- **Real-Time Delivery**: Instant notifications via WebSocket
- **Notification Types**: Invitations, reminders, replies, mentions
- **Mark as Read**: Individual or bulk mark all read
- **Notification Dropdown**: Quick access panel with notification history

### 📁 File Management
- **Study Materials Upload**: Share files with session participants
- **Multiple File Types**: Images, PDFs, Word, Excel, PowerPoint
- **File Preview System**: Click to preview images and PDFs in modal
- **Download & Delete**: Quick actions on all files
- **File Context**: Separate chat files from study materials

### 🎙️ Session Recordings
- **Audio/Video Upload**: Upload session recordings (8 formats supported)
- **Manual Transcriptions**: Add and edit transcriptions for recordings
- **Permission Control**: Only participants can download, creators can delete
- **File Management**: View recording details (uploader, date, duration, size)

### 📊 Study Analytics
- **Analytics Dashboard**: Comprehensive dashboard with Chart.js visualizations
- **Study Time Tracking**: Total hours across all attended sessions
- **Session Statistics**: Attendance count, favorite subject, study streak
- **Visual Charts**: Line, doughnut, and bar charts for data insights
- **Time Patterns**: Daily, weekly, and monthly study patterns
- **Recent Activity**: Feed of last 5 attended sessions

### 🔍 Global Search
- **FTS5 Full-Text Search**: Lightning-fast search powered by SQLite FTS5
- **Multi-Category Search**: Search across sessions, messages, notes, and files
- **Live Results**: Real-time search dropdown with instant results
- **Smart Highlighting**: Search terms highlighted in result snippets
- **Permission-Aware**: Only shows content you have access to
- **Ranked Results**: Most relevant results appear first

### 📅 Calendar Integration
- **Add to Calendar**: Export sessions to Google Calendar, Outlook, or .ics file
- **One-Click Sync**: Direct integration with Google and Outlook calendars
- **Universal .ics Export**: Download calendar files compatible with any calendar app
- **Smart Metadata**: Automatically includes location, meeting links, and session details

### ⏰ Productivity Features
- **Automatic Reminders**: Email notifications 24 hours before sessions
- **Countdown Timer**: See how much time until your session
- **Dashboard**: View all your upcoming sessions at a glance
- **Session Invitations**: Invite specific users or accept join requests

### 🎨 Modern Design
- **Purple Gradient Theme**: Beautiful color scheme throughout
- **Glass Morphism**: Frosted glass effects with backdrop blur
- **Fully Responsive**: Optimized for mobile, tablet, and desktop devices
- **Hamburger Menu**: Smooth slide-in navigation for mobile devices
- **Touch-Optimized**: Large touch targets and mobile-friendly interactions
- **Horizontal Cards**: Clean 4-per-row layout for study materials (1-column on mobile)
- **Smooth Animations**: Polished transitions and hover effects

## 🚀 Quick Start

Get up and running in 5 minutes! See **[QUICKSTART.md](QUICKSTART.md)** for detailed instructions.

```bash
# Clone repository
git clone <your-repo-url>
cd HackDecouverteStudyApp

# Install dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run application
python app.py
```

Visit `http://127.0.0.1:5000` and create your account!

## 📖 Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get started in minutes
- **[Development Roadmap](DEVELOPMENT.md)** - Future features and expansion ideas
- **[Deployment Guide](DEPLOYMENT.md)** - Deploy to production (PythonAnywhere, Heroku, AWS)
- **[API Documentation](API.md)** - Internal API endpoints reference
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute to the project

## 🛠️ Tech Stack

### Backend
- **[Flask 3.0](https://flask.palletsprojects.com/)** - Web framework
- **[Flask-SocketIO 5.3.6](https://flask-socketio.readthedocs.io/)** - WebSocket support for real-time features
- **[SQLite3](https://www.sqlite.org/)** - Database
- **[Werkzeug](https://werkzeug.palletsprojects.com/)** - Security (password hashing)
- **[APScheduler](https://apscheduler.readthedocs.io/)** - Automated reminders

### Frontend
- **HTML5** - Semantic markup
- **CSS3** - Modern styling with gradients and animations
- **JavaScript (ES6+)** - Real-time updates and interactivity
- **[Socket.IO 4.5.4](https://socket.io/)** - WebSocket client for real-time communication
- **[TinyMCE 6](https://www.tiny.cloud/)** - Rich text editor for notes
- **[Chart.js 4.4.0](https://www.chartjs.org/)** - Data visualization for analytics
- **[Font Awesome 6.5](https://fontawesome.com/)** - Icon library (including brand icons)
- **[Google Fonts (Inter)](https://fonts.google.com/)** - Typography

### Calendar Integration
- **[ics 0.7.2](https://pypi.org/project/ics/)** - iCalendar file generation
- **Google Calendar API** - Deep linking for direct calendar integration
- **Outlook Calendar API** - Deep linking for Outlook.com integration

### Development Tools
- **Git & GitHub** - Version control
- **Visual Studio Code** - Code editor
- **Python 3.8+** - Programming language

## 📂 Project Structure

```
HackDecouverteStudyApp/
├── app.py                 # Main Flask application
├── init_db.py            # Database initialization
├── reset_db.py           # Database reset utility
├── schema.sql            # Database schema
├── requirements.txt      # Python dependencies
├── sessions.db           # SQLite database (generated)
├── static/
│   ├── css/
│   │   └── style.css    # Main stylesheet
│   └── js/
│       └── main.js      # Frontend JavaScript
├── templates/           # Jinja2 HTML templates
│   ├── base.html       # Base template
│   ├── index.html      # Homepage
│   ├── dashboard.html  # User dashboard
│   ├── detail.html     # Session detail page
│   └── ...
├── uploads/            # User-uploaded files
├── flask_session/      # Session storage
└── docs/              # Documentation
    ├── QUICKSTART.md
    ├── DEVELOPMENT.md
    ├── DEPLOYMENT.md
    ├── API.md
    └── CONTRIBUTING.md
```

## 🎯 Use Cases

### For Students
- Organize group study sessions for exams
- Share lecture notes and study materials
- Collaborate on assignments
- Stay accountable with scheduled sessions

### For Study Groups
- Plan recurring weekly study sessions
- Build a library of shared resources
- Track attendance and participation
- Communicate in real-time

### For Tutors
- Schedule tutoring sessions
- Share teaching materials
- Manage multiple student groups
- Send automatic session reminders

## 🔐 Security Features

- **Password Hashing**: Werkzeug secure password hashing (SHA-256)
- **Session Management**: Secure Flask sessions with secret key
- **File Validation**: Restricted file types and size limits (100MB)
- **Filename Sanitization**: Prevents directory traversal attacks
- **Access Control**: Permission checks on all sensitive routes
- **SQL Injection Protection**: Parameterized queries throughout

## 🌐 Browser Support

- ✅ Chrome/Edge (Recommended)
- ✅ Firefox
- ✅ Safari
- ✅ Opera

## 📊 Database Schema

**Users Table**:
- id, username (unique), email, password_hash

**Sessions Table**:
- id, title, description, date, time, duration, location, max_attendees, creator_id

**Invitations Table**:
- id, session_id, user_id, status (pending/accepted/declined)

**Messages Table**:
- id, session_id, user_id, content, timestamp, parent_message_id (for threading)

**Message Reactions Table**:
- id, message_id, user_id, reaction (emoji), created_at

**Files Table**:
- id, session_id, filename, filepath, upload_date, user_id, file_context (chat/study)

**Notes Table**:
- id, user_id, title, description, content, subject, is_public, created_at, updated_at

**Note Files Table**:
- id, note_id, user_id, filename, original_filename, file_size, file_type, uploaded_at

**Note Comments Table**:
- id, note_id, user_id, comment, created_at

**Notifications Table**:
- id, user_id, type, title, message, link, is_read, created_at

## 🤝 Contributing

We welcome contributions! Please see **[CONTRIBUTING.md](CONTRIBUTING.md)** for:
- Code of conduct
- Development workflow
- Coding standards
- Pull request process
- Bug reporting guidelines

## 🐛 Known Issues

- File storage is local (consider cloud storage for production)
- TinyMCE uses free tier (no API key - has branding footer)
- No mobile-responsive design yet (coming soon)

## 🔮 Future Features

See **[DEVELOPMENT.md](DEVELOPMENT.md)** for the complete roadmap, including:
- Session recording/transcription with Whisper API
- Study analytics dashboard with Chart.js
- Calendar sync (Google Calendar, Outlook)
- Global search with SQLite FTS5
- Flashcard system with spaced repetition
- User profiles with avatars and preferences
- Mobile-responsive PWA
- Video/audio call integration
- And much more!

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Credits

### Team Name: The Goon Squad

### Front-end
Félix Hardy, Stryker Pinchin

### Back-end
Ryan El Fani, Rafael Ethan Olliver

### Stress Test
Stryker Pinchin, Rafael Ethan Olliver

## Third-Party Libraries & Frameworks

#### Backend
- **[Flask](https://flask.palletsprojects.com/)** - Simple Web Framework
- **[Flask-SocketIO](https://flask-socketio.readthedocs.io/)** - WebSocket support
- **[Werkzeug](https://werkzeug.palletsprojects.com/)** - Security functions & utilities
- **[Jinja2](https://jinja.palletsprojects.com/)** - Templates (included with Flask)

#### Frontend
- **[Font Awesome](https://fontawesome.com/)** - Online Icon Database
- **[Socket.IO](https://socket.io/)** - WebSocket client library
- **[TinyMCE](https://www.tiny.cloud/)** - Rich text editor

#### Database
- **SQLite3** - Embedded database (included with Python)

### Development Tools
- **Python** - Programming language
- **Git & GitHub** - Version control (used it for unnecessary things!)
- **Visual Studio Code** - Code editor
- **Stack Overflow, PythonAnywhere, W3Schools** - General Forums Scavenging and assistance
