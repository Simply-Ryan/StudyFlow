# StudyFlow

A comprehensive web application that helps students organize and manage collaborative study sessions with full user authentication, invitation system, real-time messaging, and reminder functionality.

> **First time here?** See [GETTING_STARTED.md](GETTING_STARTED.md) for a 2-minute setup guide!
> 
> **Windows:** Run `setup.bat` | **Mac/Linux:** Run `./setup.sh` | **Any OS:** Run `python setup.py`

## Project Overview

This application addresses the real need for students to coordinate study sessions efficiently, whether they're meeting remotely or in person. It provides a secure, feature-rich platform for creating, discovering, and participating in study sessions with complete user management and communication tools.

## Features

### User Management
- **User Registration**: Secure account creation with password hashing
- **User Authentication**: Login/logout system with session management
- **User Profiles**: Full name, username, and email tracking
- **Password Security**: Werkzeug password hashing for secure credential storage

### Session Management
- **Create Study Sessions**: Authenticated users can create new study sessions
- **Session Types**: 
  - **Remote Sessions**: Include meeting links (Zoom, Google Meet, etc.)
  - **In-Person Sessions**: Specify physical location
- **Session Scheduling**: Date and time picker for scheduling sessions
- **Participant Capacity**: Set maximum participant limits with visual progress indicators
- **Session Categories**: Subject-based categorization (Math, Science, Languages, etc.)
- **Session Ownership**: Creators have full control over their sessions
- **Delete Sessions**: Session owners can delete their sessions and all related data

### RSVP & Participation
- **User-Linked RSVPs**: RSVP system tied to user accounts
- **Participant Tracking**: View all participants for each session
- **Capacity Management**: Visual indicators for available spots
- **Auto-RSVP**: Session creators automatically RSVP to their own sessions

### Invitation System
- **Send Invitations**: Session creators can invite specific users to join
- **Invitation Status**: Track pending, accepted, and declined invitations
- **Invitation Notifications**: Users see pending invitations on homepage
- **Accept/Decline**: Simple one-click response to invitations

### Communication Features
- **Study Room Chat**: Real-time messaging within each study session
- **User Attribution**: Messages linked to user accounts with full names
- **Message History**: Persistent chat history for each session
- **Creator Tools**: Send reminders to all participants
- **Dismissible Reminders**: Users can dismiss reminders from their homepage

### User Experience
- **Session Discovery**: Browse all available study sessions
- **Personalized Dashboard**: View your invitations and reminders
- **Countdown Timers**: See time remaining until sessions start
- **Color-Coded Categories**: Visual subject identification
- **Responsive Design**: Works on desktop, tablet, and mobile devices

### User Flow
1. **Register/Login** → Create an account and log in securely
2. **Create** → Authenticated user creates a study session with details
3. **Invite** → Session creator invites specific users to join
4. **Join/RSVP** → Users accept invitations or RSVP directly to sessions
5. **Communicate** → Participants use chat to coordinate and discuss
6. **Remind** → Creators send reminders to all participants
7. **Participate** → Users attend sessions via meeting link or physical location

## Technology Stack

- **Backend**: Python Flask 3.0
- **Database**: SQLite3 with relational schema
- **Authentication**: Werkzeug security for password hashing
- **Session Management**: Flask sessions with login_required decorator
- **Frontend**: HTML5, CSS3, JavaScript
- **Template Engine**: Jinja2 with template inheritance
- **Styling**: Custom CSS (900+ lines) with organized sections

## Project Structure

```
HackDecouverteStudyApp/
├── app.py                      # Main Flask application (400+ lines)
├── init_db.py                  # Database initialization script
├── schema.sql                  # Database schema (6 tables)
├── requirements.txt            # Python dependencies
├── sessions.db                 # SQLite database (generated)
├── setup.py                    # Cross-platform setup script
├── setup.bat                   # Windows setup automation
├── setup.sh                    # Mac/Linux setup automation
├── .gitignore                  # Git ignore patterns
├── GETTING_STARTED.md          # Quick start guide
├── INSTALL.md                  # Detailed installation guide
├── static/
│   ├── css/
│   │   └── style.css          # Application styles (900+ lines)
│   └── js/
│       └── main.js            # Client-side JavaScript
└── templates/
    ├── base.html              # Base template with navigation
    ├── index.html             # Home page with invitations and reminders
    ├── login.html             # User login form
    ├── register.html          # User registration form
    ├── create_session.html    # Create session form with dynamic fields
    └── detail.html            # Session details, chat, RSVP, and invitations
```

## Quick Start Guide

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

### Need Help?
See [INSTALL.md](INSTALL.md) for detailed installation instructions and troubleshooting.

## Database Schema

The application uses 6 relational tables with proper foreign key constraints:

### Users Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto-increment) |
| username | TEXT | Unique username |
| email | TEXT | Unique email address |
| password_hash | TEXT | Hashed password (werkzeug) |
| full_name | TEXT | User's full name |
| created_at | TIMESTAMP | Account creation time |

### Sessions Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto-increment) |
| title | TEXT | Session name/title |
| session_type | TEXT | 'remote' or 'in-person' |
| subject | TEXT | Category/subject (default 'General') |
| meeting_link | TEXT | URL for remote sessions |
| location | TEXT | Physical location for in-person |
| session_date | DATETIME | Scheduled date/time |
| max_participants | INTEGER | Capacity limit (default 10) |
| creator_id | INTEGER | Foreign key to users table |
| created_at | TIMESTAMP | Session creation time |

### RSVPs Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto-increment) |
| session_id | INTEGER | Foreign key to sessions |
| user_id | INTEGER | Foreign key to users |
| created_at | TIMESTAMP | RSVP submission time |
| UNIQUE | (session_id, user_id) | Prevents duplicate RSVPs |

### Invitations Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto-increment) |
| session_id | INTEGER | Foreign key to sessions |
| inviter_id | INTEGER | Foreign key to users (sender) |
| invitee_id | INTEGER | Foreign key to users (recipient) |
| status | TEXT | 'pending', 'accepted', or 'declined' |
| created_at | TIMESTAMP | Invitation sent time |
| UNIQUE | (session_id, invitee_id) | One invitation per user per session |

### Messages Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto-increment) |
| session_id | INTEGER | Foreign key to sessions |
| user_id | INTEGER | Foreign key to users |
| message_text | TEXT | Message content |
| created_at | TIMESTAMP | Message sent time |

### Reminders Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto-increment) |
| session_id | INTEGER | Foreign key to sessions |
| reminder_text | TEXT | Reminder message content |
| sent_by | INTEGER | Foreign key to users (sender) |
| created_at | TIMESTAMP | Reminder sent time |

### Dismissed Reminders Table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key (auto-increment) |
| reminder_id | INTEGER | Foreign key to reminders |
| user_id | INTEGER | Foreign key to users |
| dismissed_at | TIMESTAMP | Dismissal time |
| UNIQUE | (reminder_id, user_id) | Track dismissals per user |

## User Interface

### Home Page
- Hero section with conditional call-to-action (login state aware)
- Personalized invitations section (pending invitations)
- Recent reminders section (dismissible notifications)
- Grid display of all study sessions with color-coded categories
- Session cards showing type, subject, creator, and countdown
- Quick access to create new sessions (authenticated users only)

### Authentication Pages
- **Login**: Username and password with validation
- **Register**: Full name, username, email, password (6+ characters)
- Secure password hashing with werkzeug
- Session management with Flask sessions
- Flash messages for feedback

### Create Session Page
- Clean, organized form interface
- Subject/category dropdown
- Dynamic fields based on session type:
  - Remote: Meeting link field appears
  - In-Person: Location field appears
- Date/time picker for scheduling
- Max participants capacity field
- Form validation and error messages

### Session Detail Page
- Full session information with creator attribution
- Meeting link (remote) or location (in-person) display
- Countdown timer to session start
- Capacity progress bar (visual indicator)
- **Creator Tools** (session owner only):
  - Send reminder form to notify all participants
  - Delete session button with confirmation
  - Invite specific users from dropdown
- **RSVP Section**:
  - RSVP button (if not at capacity)
  - Participant list with user badges
- **Chat/Messaging**:
  - Message history with user attribution
  - Real-time message posting form
  - Scrollable chat interface
- Login prompts for unauthenticated users

## Reminder System

Full-featured reminder system for session communication:

**Features:**
- Session creators can send custom reminder messages
- Text input for personalized reminder content
- Reminders sent to all RSVP'd participants
- Reminders display on user's homepage
- Each user can dismiss reminders individually
- Dismissals are user-specific (doesn't affect others)
- Visual styling with yellow/orange theme
- Timestamp tracking for all reminders
- Database persistence of all reminder data

**User Experience:**
- Creators see reminder form on their session detail page
- Participants see reminders in dedicated section on homepage
- One-click dismiss button removes from personal view
- "View Session" link for quick navigation
- Sender attribution on all reminders

## Scalability Considerations

### Current Implementation
- SQLite database with 6 relational tables
- User authentication with session management
- Password hashing for security
- Modular Flask architecture (400+ lines)
- Organized CSS (900+ lines in 12 sections)
- Template inheritance for maintainability

### Production Readiness
Already Implemented:
- User authentication system (login required decorator)
- Password hashing (werkzeug security)
- Session management (Flask sessions)
- Database normalization with foreign keys
- CSRF protection (Flask secret key)
- Unique constraints to prevent data duplication

### Scaling for Production
1. **Database Migration**: Move from SQLite to PostgreSQL or MySQL for better concurrency
2. **Caching**: Add Redis for session caching and real-time features
3. **Background Tasks**: Implement Celery for scheduled email reminders
4. **Email Integration**: Add SendGrid/Mailgun for email notifications
5. **API Development**: Create RESTful API for mobile app integration
6. **WebSockets**: Add Socket.IO for real-time chat updates
7. **File Upload**: Implement file sharing for study materials
8. **Deployment**: Deploy on cloud platforms (AWS, Heroku, DigitalOcean)
9. **Load Balancing**: Use multiple app instances behind load balancer
10. **CDN**: Serve static assets from CDN for faster loading

## Demo Flow

### 1. User Registration & Login
- Navigate to home page
- Click "Register Now" or "Register" in navigation
- Fill out registration form:
  - Full Name: "John Smith"
  - Username: "jsmith"
  - Email: "john@example.com"
  - Password: "password123"
- Submit and get redirected to login
- Log in with credentials
- See personalized greeting in navigation

### 2. Create Study Session
- Click "Create New Session" from homepage
- Fill out form with sample data:
  - Title: "Calculus Midterm Study Group"
  - Subject: "Mathematics"
  - Type: Remote
  - Meeting Link: https://zoom.us/j/1234567890
  - Date/Time: Select future date
  - Max Participants: 10
- Submit and see success message
- Redirected to session detail page
- Automatically RSVP'd as creator

### 3. Invite Users
- As session creator, see invitation form
- Select user from dropdown
- Send invitation
- Other user sees invitation on their homepage

### 4. Chat/Messaging
- Scroll to chat section on session detail
- Enter message in text area
- Submit message
- See message appear with your name and timestamp
- Messages persist in database

### 5. Send Reminder
- As session creator, see reminder form at top
- Enter custom reminder text
- Click "Send Reminder to All Participants"
- All RSVP'd users see reminder on homepage
- Participants can dismiss reminder individually

### 6. RSVP to Session (as different user)
- Log out and register/login as different user
- Navigate to session from homepage
- View session details
- Click "RSVP to Join" button
- See name added to participant list
- See capacity progress bar update

### 7. Accept Invitation
- User with pending invitation logs in
- See invitation card on homepage
- Click "Accept" button
- Automatically RSVP'd to session
- Invitation status updated

### 8. Delete Session
- As session creator, navigate to session detail
- Scroll to creator actions
- Click "Delete Session" button
- Confirm deletion in dialog
- Session and all related data removed
- Redirected to homepage

## Real Student Needs Addressed

### Secure User Management
- Personal accounts with secure authentication
- Password protection for user data
- Track your created sessions and RSVPs
- Personalized dashboard with your invitations and reminders

### Remote Learning Support
- Easy sharing of video conference links
- Centralized location for all remote study sessions
- Built-in chat for coordination
- No need for multiple communication channels

### Hybrid Learning Flexibility
- Support for both remote and in-person sessions
- Students can choose based on their preferences
- Location transparency for campus meetings
- Date/time scheduling with countdown timers

### Organization & Coordination
- Eliminates confusion about study session details
- Clear RSVP system shows who's attending
- Capacity management prevents overcrowding
- Reminder system keeps everyone informed
- Session categories for easy browsing

### Communication Tools
- Study room chat for each session
- Direct invitation system to specific users
- Custom reminder messages from session creators
- Message history for reference

### Accessibility
- Simple, clean interface requiring minimal technical knowledge
- Mobile-responsive design (works on phones/tablets)
- Quick session creation process
- Visual indicators (countdown, capacity, categories)
- Color-coded subject categories

## Configuration

### Secret Key
For production, change the secret key in `app.py`:
```python
app.secret_key = 'your-secure-secret-key-here'
```
Generate a secure key using:
```python
import secrets
secrets.token_hex(32)
```

### Debug Mode
Debug mode is enabled by default for development. For production:
```python
if __name__ == '__main__':
    app.run(debug=False)
```

### Database
To reset the database and start fresh:
```bash
# Windows
Remove-Item sessions.db
python init_db.py

# Mac/Linux
rm sessions.db
python3 init_db.py
```

## Troubleshooting

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

### Authentication Issues
If you're having login problems:
- Verify username and password are correct
- Try registering a new account
- Check that the users table exists in database
- Reinitialize database if needed

## Future Enhancements

### Phase 1 (MVP) - COMPLETED
- User registration and authentication
- Secure password hashing
- Session creation with scheduling
- RSVP system with user accounts
- Study room chat/messaging
- Invitation system
- Reminder notifications
- Session deletion
- Capacity management
- Subject categories

### Phase 2 (Proposed)
- Session editing for creators
- Search and filter sessions by multiple criteria
- Recurring sessions (weekly study groups)
- User profile pages with activity history
- Email notifications via SMTP
- Export sessions to calendar (iCal format)
- Session ratings and reviews

### Phase 3 (Advanced)
- Real-time chat with WebSockets
- File sharing (notes, study materials, recordings)
- Video integration (embedded calls)
- Mobile app (React Native/Flutter)
- Analytics dashboard for session creators
- Study group leaderboards
- Integration with learning management systems (LMS)
- API for third-party integrations

## Technology Highlights

- **Security**: Werkzeug password hashing, session-based auth, login_required decorator
- **Database**: 6 relational tables with foreign key constraints
- **Code Quality**: Organized, commented code (400+ lines Python, 900+ lines CSS)
- **User Experience**: Responsive design, visual feedback, error handling
- **Scalability**: Modular architecture ready for production deployment

## Contributing

This project was created for Hack Découverte. Contributions and suggestions are welcome!

## Credits & Acknowledgments

### Third-Party Libraries & Frameworks

#### Backend
- **[Flask](https://flask.palletsprojects.com/)** (v3.0.0) - Web framework
  - License: BSD-3-Clause
  - Copyright: Pallets Projects
  
- **[Werkzeug](https://werkzeug.palletsprojects.com/)** (v3.0.1) - WSGI utilities and security functions
  - License: BSD-3-Clause
  - Copyright: Pallets Projects
  - Used for: Password hashing (`generate_password_hash`, `check_password_hash`), secure filename handling

- **[Jinja2](https://jinja.palletsprojects.com/)** - Template engine (included with Flask)
  - License: BSD-3-Clause
  - Copyright: Pallets Projects

#### Frontend
- **[Font Awesome](https://fontawesome.com/)** (v6.5.1) - Icon library
  - License: Font Awesome Free License (Icons: CC BY 4.0, Fonts: SIL OFL 1.1, Code: MIT)
  - CDN: `https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css`
  - Used for: UI icons throughout the application

#### Database
- **SQLite3** - Embedded database (included with Python)
  - License: Public Domain
  - No external dependencies required

#### Python Standard Library
The following built-in Python modules are used (no attribution required but acknowledged):
- `sqlite3` - Database connectivity
- `os` - File and directory operations
- `datetime` - Date and time handling
- `functools` - Higher-order functions and decorators

### Design & Inspiration
- Color scheme inspired by modern gradient design trends
- UI/UX patterns following Material Design principles
- Responsive design techniques from modern web development best practices

### Development Tools
- **Python** (3.x) - Programming language
- **Git** - Version control
- **Visual Studio Code** - Code editor

### Special Thanks
- **Hack Découverte** - For providing the opportunity and platform for this project
- **Open Source Community** - For maintaining the libraries and tools that made this project possible

## License

This project is open source and available for educational purposes.

## Contact

For questions or feedback about this project, please contact the development team.

---

**Built for students, by students**