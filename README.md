# StudySync 📚

A web application that helps students and study groups organize and manage collaborative study sessions, supporting both remote and in-person meetings.

> **🚀 First time here?** See [GETTING_STARTED.md](GETTING_STARTED.md) for a 2-minute setup guide!
> 
> **Windows:** Run `start.bat` | **Mac/Linux:** Run `./start.sh` | **Any OS:** Run `python setup.py`

## 🎯 Project Overview

This application addresses the real need for students to coordinate study sessions efficiently, whether they're meeting remotely or in person. It provides a simple, intuitive interface for creating, discovering, and joining study sessions with automated reminder functionality.

## ✨ Features

### Core Functionality
- **Create Study Sessions**: Students can create new study sessions with customizable details
- **Session Type Selection**: 
  - **Remote Sessions**: Include meeting links (Zoom, Google Meet, etc.)
  - **In-Person Sessions**: Specify location/room number
- **RSVP System**: Other students can easily join and RSVP to sessions
- **Automated Reminders**: Simulated notification system to remind participants about upcoming sessions
- **Session Discovery**: Browse all available study sessions from a centralized dashboard

### User Flow
1. **Create** → Student creates a study session (remote or in-person)
2. **Join/RSVP** → Other students discover and RSVP to the session
3. **Reminder** → Automated reminders notify participants before the session

## 🛠️ Technology Stack

- **Backend**: Python Flask 3.0
- **Database**: SQLite3
- **Frontend**: HTML5, CSS3, JavaScript
- **Template Engine**: Jinja2
- **Styling**: Custom CSS with gradient design

## 📁 Project Structure

```
HackDecouverteStudyApp/
├── app.py                 # Main Flask application
├── init_db.py            # Database initialization script
├── schema.sql            # Database schema definition
├── requirements.txt      # Python dependencies
├── sessions.db           # SQLite database (generated)
├── static/
│   ├── css/
│   │   └── style.css    # Application styles
│   └── js/
│       └── main.js      # Client-side JavaScript
└── templates/
    ├── base.html        # Base template
    ├── index.html       # Home page / session list
    ├── create.html      # Create session form
    └── detail.html      # Session details & RSVP page
```

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git (to clone the repository)

### Automated Setup (Recommended)

**Windows Users:**
```cmd
setup.bat
python app.py
```

**Mac/Linux Users:**
```bash
chmod +x setup.sh
./setup.sh
python3 app.py
```

**Cross-Platform (Python):**
```bash
python setup.py
python app.py
```

Then open: **http://127.0.0.1:5000**

### Manual Installation

**1. Clone the Repository**
```bash
git clone https://github.com/Simply-Ryan/Simply-Ryan.github.io.git
cd Simply-Ryan.github.io/Visual_Studio_Code/WebApps/HackDecouverteStudyApp
```

**2. Install Dependencies**
```bash
pip install -r requirements.txt
```

**3. Initialize Database**
```bash
python init_db.py
```

**4. Run Application**
```bash
python app.py
```

**5. Open Browser**
Navigate to: **http://127.0.0.1:5000**

### 📖 Need Help?
See [INSTALL.md](INSTALL.md) for detailed installation instructions and troubleshooting.

## 📊 Database Schema

### Sessions Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto-increment) |
| title | TEXT | Session name/title |
| session_type | TEXT | 'remote' or 'in-person' |
| meeting_link | TEXT | URL for remote sessions |
| location | TEXT | Physical location for in-person sessions |
| created_at | TIMESTAMP | Session creation time |
| session_date | DATETIME | Scheduled session date/time |
| reminder_sent | INTEGER | Flag for reminder status |

### RSVPs Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto-increment) |
| session_id | INTEGER | Foreign key to sessions table |
| participant_name | TEXT | Name of participant |
| created_at | TIMESTAMP | RSVP submission time |

## 🎨 User Interface

### Home Page
- Hero section with call-to-action
- Grid display of all available study sessions
- Session cards showing type (remote/in-person) and key details
- Quick access to create new sessions

### Create Session Page
- Clean form interface
- Dynamic fields based on session type:
  - Remote: Meeting link field appears
  - In-Person: Location field appears
- Form validation
- Success feedback

### Session Detail Page
- Full session information display
- Meeting link (for remote) or location (for in-person)
- RSVP form
- List of all participants
- Simulated reminder system with test button

## 🔔 Reminder System

The application includes a simulated reminder notification system that demonstrates how participants would receive notifications about upcoming sessions.

**Features:**
- Test reminder button on session detail page
- Visual notification display
- Timestamp of reminder
- Auto-dismissing alerts (5 seconds)

**Future Enhancement Ideas:**
- Email notifications via SMTP
- SMS reminders via Twilio
- Browser push notifications
- Scheduled background tasks with APScheduler
- Calendar integration (Google Calendar, iCal)

## 📈 Scalability Considerations

### Current Implementation
- SQLite database (suitable for prototype/demo)
- Simple file-based structure
- Minimal dependencies

### Scaling for Production
1. **Database Migration**: Move from SQLite to PostgreSQL or MySQL for better concurrency
2. **User Authentication**: Add login system with Flask-Login
3. **Session Management**: Implement Flask-Session for user sessions
4. **Caching**: Add Redis for session caching and real-time features
5. **Background Tasks**: Implement Celery for scheduled reminders
6. **API Development**: Create RESTful API for mobile app integration
7. **Deployment**: Deploy on cloud platforms (AWS, Heroku, DigitalOcean)
8. **Load Balancing**: Use multiple app instances behind load balancer

## 🎯 Demo Flow for Judges

### 1. Create Session Demo
- Navigate to home page
- Click "Create New Session"
- Fill out form with sample data:
  - Title: "Calculus Midterm Study Group"
  - Type: Remote
  - Meeting Link: https://zoom.us/j/1234567890
- Submit and see success message
- Redirected to home page showing new session

### 2. Join/RSVP Demo
- Click on the newly created session
- View session details (title, type, meeting link)
- Enter participant name in RSVP form
- Submit RSVP
- See participant added to list

### 3. Reminder Demo
- On session detail page
- Click "Test Reminder" button
- See simulated reminder notification appear
- Notification shows timestamp and message
- Auto-dismisses after 5 seconds

### 4. Browse Sessions Demo
- Return to home page
- Create additional sessions (mix of remote and in-person)
- Show session grid with different types
- Demonstrate easy navigation between sessions

## 🎓 Real Student Needs Addressed

### Remote Learning Support
- Easy sharing of video conference links
- Centralized location for all remote study sessions
- No need for separate communication channels

### Hybrid Learning Flexibility
- Support for both remote and in-person sessions
- Students can choose based on their preferences
- Location transparency for campus meetings

### Organization & Coordination
- Eliminates confusion about study session details
- Clear RSVP system shows who's attending
- Reminder system ensures students don't miss sessions

### Accessibility
- Simple, clean interface requiring minimal technical knowledge
- Mobile-responsive design (works on phones/tablets)
- Quick session creation process

## 🔧 Configuration

### Secret Key
For production, change the secret key in `app.py`:
```python
app.secret_key = 'your-secure-secret-key-here'
```

### Debug Mode
Debug mode is enabled by default for development. For production:
```python
if __name__ == '__main__':
    app.run(debug=False)
```

## 🐛 Troubleshooting

### Database Issues
If you encounter database errors:
```bash
# Delete existing database
Remove-Item sessions.db

# Reinitialize
python init_db.py
```

### Port Already in Use
If port 5000 is occupied:
```python
# In app.py, change the port
if __name__ == '__main__':
    app.run(debug=True, port=5001)
```

### Template Not Found
Ensure templates are in the `templates/` directory and spelled correctly.

## 📝 Future Enhancements

### Phase 1 (MVP Complete) ✅
- Create sessions
- Join/RSVP functionality
- Simulated reminders
- Basic UI

### Phase 2 (Proposed)
- User authentication and profiles
- Session editing and deletion
- Search and filter sessions
- Session categories (subject-based)
- Recurring sessions

### Phase 3 (Advanced)
- Real-time notifications
- Chat functionality within sessions
- File sharing (notes, study materials)
- Calendar integration
- Mobile app (React Native/Flutter)
- Analytics dashboard for organizers

## 👥 Contributing

This project was created for Hack Découverte. Contributions and suggestions are welcome!

## 📄 License

This project is open source and available for educational purposes.

## 📧 Contact

For questions or feedback about this project, please contact the development team.

---

**Built with ❤️ for students, by students**