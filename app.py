"""
StudyFlow - Collaborative Study Session Platform

A comprehensive Flask application for managing study sessions with real-time chat,
flashcards, notes, analytics, user profiles, and AI-powered study assistance.

Author: StudyFlow Team
Version: 1.17.0
Date: December 2025
"""

# ============================================
# IMPORTS
# ============================================
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler
from ics import Calendar, Event
import markdown
import atexit
from openai import OpenAI
from config import Config
from deep_translator import GoogleTranslator
from langdetect import detect, LangDetectException

# ============================================
# APPLICATION CONFIGURATION
# ============================================
app = Flask(__name__)

# Security: Secret key for session management and CSRF protection
app.secret_key = 'f47cba5d7844e3b4cc01994acb8de040c559faf14e9284d5530eeb02055d150b'
app.config['SECRET_KEY'] = app.secret_key
app.config.from_object(Config)

# WebSocket: Initialize SocketIO for real-time features
socketio = SocketIO(app, cors_allowed_origins="*")

# AI Configuration: Initialize OpenAI client
openai_client = None
if Config.OPENAI_API_KEY and Config.AI_ENABLED:
    try:
        openai_client = OpenAI(api_key=Config.OPENAI_API_KEY)
        print("✅ AI Assistant enabled with OpenAI")
    except Exception as e:
        print(f"⚠️ AI Assistant initialization failed: {e}")
        print("ℹ️ AI features will be disabled. Check your OPENAI_API_KEY if you want to enable them.")
else:
    print("ℹ️ AI Assistant disabled. Set OPENAI_API_KEY and AI_ENABLED=true to enable.")

# Database Configuration
DATABASE = 'sessions.db'

# File Upload Configuration
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB limit
ALLOWED_EXTENSIONS = {
    # Images
    'png', 'jpg', 'jpeg', 'gif',
    # Documents
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt',
    # Archives
    'zip', 'rar'
}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# ============================================
# INITIALIZATION
# ============================================

# Create uploads directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def add_file_context_column():
    """Add file_context column to files table if not exists (migration helper)"""
    conn = sqlite3.connect(DATABASE)
    try:
        conn.execute("ALTER TABLE files ADD COLUMN file_context TEXT DEFAULT 'study_material'")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Column already exists, skip
    finally:
        conn.close()

add_file_context_column()

# ============================================
# DECORATORS & UTILITY FUNCTIONS
# ============================================

def login_required(f):
    """Decorator to protect routes that require authentication.
    
    Redirects unauthenticated users to the login page with a flash message.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def format_time_remaining(session_date_str):
    """Calculate and format the time remaining until a session starts.
    
    Args:
        session_date_str: ISO format datetime string
        
    Returns:
        Human-readable time remaining string (e.g., "In 2 hours", "Starting soon!")
    """
    if not session_date_str:
        return None
    
    try:
        session_date = datetime.fromisoformat(session_date_str.replace('T', ' '))
        now = datetime.now()
        
        if session_date < now:
            return "Session ended"
        
        delta = session_date - now
        
        if delta.days > 0:
            return f"In {delta.days} day{'s' if delta.days > 1 else ''}"
        elif delta.seconds >= 3600:
            hours = delta.seconds // 3600
            return f"In {hours} hour{'s' if hours > 1 else ''}"
        elif delta.seconds >= 60:
            minutes = delta.seconds // 60
            return f"In {minutes} minute{'s' if minutes > 1 else ''}"
        else:
            return "Starting soon!"
    except:
        return None

app.jinja_env.globals.update(format_time_remaining=format_time_remaining)

def markdown_to_html(text):
    """Convert markdown text to safe HTML.
    
    Args:
        text: Markdown formatted text
        
    Returns:
        HTML string with markdown rendered
    """
    if not text:
        return ""
    return markdown.markdown(text, extensions=['fenced_code', 'codehilite', 'tables', 'nl2br', 'extra'])

app.jinja_env.filters['markdown'] = markdown_to_html

def allowed_file(filename):
    """Check if uploaded file extension is allowed.
    
    Args:
        filename: Name of the file to check
        
    Returns:
        Boolean indicating if file type is permitted
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_size_str(size_bytes):
    """Convert file size in bytes to human-readable format.
    
    Args:
        size_bytes: File size in bytes
        
    Returns:
        Formatted string (e.g., "2.5 MB", "1.2 GB")
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

app.jinja_env.globals.update(get_file_size_str=get_file_size_str)

def get_db():
    """Get database connection with Row factory for dict-like access.
    
    Returns:
        SQLite connection object with row_factory enabled
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.context_processor
def inject_user_theme():
    """Inject user theme preference into all templates"""
    if 'user_id' in session:
        conn = get_db()
        user_settings = conn.execute(
            'SELECT theme FROM user_settings WHERE user_id = ?',
            (session['user_id'],)
        ).fetchone()
        conn.close()
        
        if user_settings and user_settings['theme']:
            return {'user_theme': user_settings['theme']}
    
    return {'user_theme': 'dark'}

def create_notification(user_id, notif_type, title, message, link=None):
    """Create a notification and emit it via WebSocket for real-time delivery.
    
    Args:
        user_id: ID of the user to notify
        notif_type: Type of notification ('invitation', 'reminder', 'reply', 'mention')
        title: Notification title
        message: Notification message body
        link: Optional URL to link to
        
    Returns:
        ID of the created notification
    """
    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO notifications (user_id, type, title, message, link) VALUES (?, ?, ?, ?, ?)',
        (user_id, notif_type, title, message, link)
    )
    notif_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Emit real-time notification via WebSocket to user's personal room
    socketio.emit('new_notification', {
        'id': notif_id,
        'type': notif_type,
        'title': title,
        'message': message,
        'link': link
    }, room=f'user_{user_id}')
    
    return notif_id

# ============================================
# TRANSLATION UTILITIES
# ============================================

def detect_language(text):
    """Detect the language of a text.
    
    Args:
        text: Text to detect language for
        
    Returns:
        ISO 639-1 language code (e.g., 'en', 'es', 'fr') or None if detection fails
    """
    if not text or len(text.strip()) < 3:
        return None
    
    try:
        return detect(text)
    except LangDetectException:
        return None

def translate_text(text, target_lang='en', source_lang='auto'):
    """Translate text to target language using Google Translate.
    
    Args:
        text: Text to translate
        target_lang: Target language code (default: 'en')
        source_lang: Source language code (default: 'auto' for auto-detection)
        
    Returns:
        Translated text or original text if translation fails
    """
    if not text or not text.strip():
        return text
    
    try:
        # Auto-detect source language if not specified
        if source_lang == 'auto':
            detected = detect_language(text)
            if detected == target_lang:
                # Text is already in target language
                return text
            source_lang = detected if detected else 'en'
        
        # Don't translate if source and target are the same
        if source_lang == target_lang:
            return text
        
        # Perform translation
        translator = GoogleTranslator(source=source_lang, target=target_lang)
        translated = translator.translate(text)
        return translated if translated else text
    except Exception as e:
        print(f"Translation error: {e}")
        return text

def get_user_language_preference(user_id):
    """Get user's preferred language from settings.
    
    Args:
        user_id: User ID
        
    Returns:
        Language code or 'en' as default
    """
    conn = get_db()
    settings = conn.execute(
        'SELECT preferred_language, auto_translate FROM user_settings WHERE user_id = ?',
        (user_id,)
    ).fetchone()
    conn.close()
    
    if settings:
        return settings['preferred_language'], bool(settings['auto_translate'])
    return 'en', False

# ============================================
# MAIN APPLICATION ROUTES
# ============================================

@app.route('/')
def index():
    """Main dashboard showing all study sessions with search and filter options."""
    conn = get_db()
    
    # Extract search and filter parameters from URL query string
    search_query = request.args.get('search', '').strip()
    subject_filter = request.args.get('subject', '').strip()
    
    # Build dynamic SQL query based on active filters
    query = '''
        SELECT s.*, u.full_name as creator_name 
        FROM sessions s
        LEFT JOIN users u ON s.creator_id = u.id
        WHERE 1=1
    '''
    params = []
    
    if search_query:
        query += ' AND s.title LIKE ?'
        params.append(f'%{search_query}%')
    
    if subject_filter:
        query += ' AND s.subject = ?'
        params.append(subject_filter)
    
    query += ' ORDER BY s.created_at DESC'
    
    sessions_query = conn.execute(query, params).fetchall()
    
    # Convert to list of dicts and add participant info
    sessions = []
    for sess in sessions_query:
        sess_dict = dict(sess)
        sess_dict['user_is_participant'] = False
        if 'user_id' in session:
            # Check if user is participant
            rsvp = conn.execute('SELECT * FROM rsvps WHERE session_id = ? AND user_id = ?',
                              (sess['id'], session['user_id'])).fetchone()
            sess_dict['user_is_participant'] = (rsvp is not None or sess['creator_id'] == session['user_id'])
        sessions.append(sess_dict)
    
    # fetch user invitations if they're logged in
    invitations = []
    reminders = []
    if 'user_id' in session:
        invitations = conn.execute('''
            SELECT i.*, s.title as session_title, u.full_name as inviter_name
            FROM invitations i
            JOIN sessions s ON i.session_id = s.id
            JOIN users u ON i.inviter_id = u.id
            WHERE i.invitee_id = ? AND i.status = 'pending'
        ''', (session['user_id'],)).fetchall()
        
        # grab reminders for RSVP'd sessions (skip dismissed ones)
        reminders = conn.execute('''
            SELECT r.id, r.session_id, r.reminder_text, r.created_at,
                   s.title as session_title, u.full_name as sender_name
            FROM reminders r
            JOIN sessions s ON r.session_id = s.id
            JOIN users u ON r.sent_by = u.id
            WHERE r.session_id IN (
                SELECT session_id FROM rsvps WHERE user_id = ?
            )
            AND r.id NOT IN (
                SELECT reminder_id FROM dismissed_reminders WHERE user_id = ?
            )
            ORDER BY r.created_at DESC
            LIMIT 10
        ''', (session['user_id'], session['user_id'])).fetchall()
    
    conn.close()
    return render_template('index.html', sessions=sessions, invitations=invitations, reminders=reminders)

# ============================================
# AUTHENTICATION ROUTES
# ============================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with username, email, and password."""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        
        conn = get_db()
        
        # Check for existing username or email
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?', 
            (username, email)
        ).fetchone()
        
        if existing_user:
            flash('Username or email already exists!')
            conn.close()
            return redirect(url_for('register'))
        
        password_hash = generate_password_hash(password)
        conn.execute('INSERT INTO users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)',
                     (username, email, password_hash, full_name))
        conn.commit()
        conn.close()
        
        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            flash(f'Welcome back, {user["full_name"]}!')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Clear session and log out user."""
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

# ============================================
# SESSION MANAGEMENT ROUTES
# ============================================

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """Create a new study session with details like date, subject, location, etc."""
    if request.method == 'POST':
        title = request.form['title']
        session_type = request.form['session_type']
        subject = request.form.get('subject', 'General')
        session_date = request.form.get('session_date', '')
        max_participants = request.form.get('max_participants', 10)
        meeting_link = request.form.get('meeting_link', '')
        location = request.form.get('location', '')
        
        conn = get_db()
        cursor = conn.execute(
            '''INSERT INTO sessions (title, session_type, subject, session_date, 
               max_participants, meeting_link, location, creator_id) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (title, session_type, subject, session_date, max_participants, 
             meeting_link, location, session['user_id'])
        )
        session_id = cursor.lastrowid
        
        # Automatically RSVP the creator to their own session
        conn.execute(
            'INSERT INTO rsvps (session_id, user_id) VALUES (?, ?)',
            (session_id, session['user_id'])
        )
        conn.commit()
        conn.close()
        flash('Study session created successfully!')
        return redirect(url_for('detail', session_id=session_id))
    
    return render_template('create.html')

@app.route('/session/<int:session_id>', methods=['GET', 'POST'])
def detail(session_id):
    conn = get_db()
    study_session = conn.execute('''
        SELECT s.*, u.full_name as creator_name, u.id as creator_user_id
        FROM sessions s
        LEFT JOIN users u ON s.creator_id = u.id
        WHERE s.id = ?
    ''', (session_id,)).fetchone()
    
    # verify session exists
    if not study_session:
        conn.close()
        flash('Session not found!')
        return redirect(url_for('index'))
    
    # Fetch all RSVPs for this session with user details
    rsvps = conn.execute('''
        SELECT r.*, u.full_name, u.username
        FROM rsvps r
        JOIN users u ON r.user_id = u.id
        WHERE r.session_id = ?
    ''', (session_id,)).fetchall()
    
    # Handle RSVP submission
    if request.method == 'POST':
        if 'rsvp' in request.form and 'user_id' in session:
            current_count = len(rsvps)
            max_participants = study_session['max_participants'] if study_session['max_participants'] else 10
            
            # Check for duplicate RSVP
            user_rsvp = conn.execute(
                'SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
                (session_id, session['user_id'])
            ).fetchone()
            
            # Validate RSVP constraints
            if user_rsvp:
                flash('You have already RSVP\'d to this session!')
            elif current_count >= max_participants:
                flash('Sorry, this session is full!')
            else:
                # Create new RSVP
                conn.execute(
                    'INSERT INTO rsvps (session_id, user_id) VALUES (?, ?)',
                    (session_id, session['user_id'])
                )
                conn.commit()
                flash('RSVP submitted successfully!')
        return redirect(url_for('detail', session_id=session_id))
    
    # Fetch all chat messages for this session
    messages_raw = conn.execute('''
        SELECT m.*, u.full_name, u.username
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.session_id = ?
        ORDER BY m.created_at ASC
    ''', (session_id,)).fetchall()
    
    # Enrich messages with reactions and thread context
    messages = []
    for msg in messages_raw:
        # Fetch reactions aggregated by emoji
        reactions = conn.execute('''
            SELECT emoji, COUNT(*) as count, GROUP_CONCAT(user_id) as user_ids
            FROM message_reactions
            WHERE message_id = ?
            GROUP BY emoji
        ''', (msg['id'],)).fetchall()
        
        # Get parent message context for threaded replies
        parent_info = None
        if msg['parent_message_id']:
            parent = conn.execute('''
                SELECT m.message_text, u.full_name
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            ''', (msg['parent_message_id'],)).fetchone()
            if parent:
                parent_info = {
                    'id': msg['parent_message_id'],
                    'text': parent['message_text'],
                    'author': parent['full_name']
                }
        
        messages.append({
            'id': msg['id'],
            'type': 'message',
            'full_name': msg['full_name'],
            'username': msg['username'],
            'message_text': msg['message_text'],
            'created_at': msg['created_at'],
            'user_id': msg['user_id'],
            'parent_message_id': msg['parent_message_id'],
            'parent_info': parent_info,
            'reactions': [{
                'emoji': r['emoji'],
                'count': r['count'],
                'user_ids': [int(uid) for uid in r['user_ids'].split(',')]
            } for r in reactions]
        })
    
    # Fetch files uploaded in chat context and merge into timeline
    chat_files = conn.execute('''
        SELECT f.*, u.full_name, u.username
        FROM files f
        JOIN users u ON f.user_id = u.id
        WHERE f.session_id = ? AND f.file_context = 'chat'
        ORDER BY f.uploaded_at ASC
    ''', (session_id,)).fetchall()
    
    # Add chat files to message timeline for chronological display
    for file in chat_files:
        messages.append({
            'id': file['id'],
            'type': 'file',
            'full_name': file['full_name'],
            'username': file['username'],
            'created_at': file['uploaded_at'],
            'user_id': file['user_id'],
            'file_id': file['id'],
            'filename': file['filename'],
            'original_filename': file['original_filename'],
            'file_size': file['file_size'],
            'file_type': file['file_type']
        })
    
    # Create unified timeline: sort messages and chat files chronologically
    messages = sorted(messages, key=lambda x: x['created_at'])
    
    # Fetch study material files separately (displayed in dedicated section)
    files = conn.execute('''
        SELECT f.*, u.full_name, u.username
        FROM files f
        JOIN users u ON f.user_id = u.id
        WHERE f.session_id = ? AND (f.file_context IS NULL OR f.file_context = 'study_material')
        ORDER BY f.uploaded_at DESC
    ''', (session_id,)).fetchall()
    
    # get users for invite dropdown (exclude already invited/joined)
    all_users = []
    if 'user_id' in session and study_session['creator_user_id'] == session['user_id']:
        rsvp_user_ids = [r['user_id'] for r in rsvps]
        invited_user_ids = [i['invitee_id'] for i in conn.execute(
            'SELECT invitee_id FROM invitations WHERE session_id = ?', (session_id,)
        ).fetchall()]
        excluded_ids = rsvp_user_ids + invited_user_ids + [session['user_id']]
        
        placeholders = ','.join('?' * len(excluded_ids))
        all_users = conn.execute(f'''
            SELECT id, full_name, username FROM users 
            WHERE id NOT IN ({placeholders})
            ORDER BY full_name
        ''', excluded_ids).fetchall()
    
    # Fetch session recordings
    recordings = conn.execute('''
        SELECT r.*, u.full_name, u.username
        FROM session_recordings r
        JOIN users u ON r.user_id = u.id
        WHERE r.session_id = ?
        ORDER BY r.created_at DESC
    ''', (session_id,)).fetchall()
    
    conn.close()
    
    # calculate spots remaining
    current_count = len(rsvps)
    max_participants = study_session['max_participants'] if study_session['max_participants'] else 10
    is_full = current_count >= max_participants
    spots_left = max_participants - current_count
    
    # check if logged in user has RSVP'd
    user_has_rsvp = False
    if 'user_id' in session:
        user_has_rsvp = any(r['user_id'] == session['user_id'] for r in rsvps)
    
    is_creator = 'user_id' in session and study_session['creator_user_id'] == session['user_id']
    
    # Get user's translation preferences
    preferred_language = 'en'
    auto_translate = False
    if 'user_id' in session:
        preferred_language, auto_translate = get_user_language_preference(session['user_id'])
        # Store in session for easy access
        session['preferred_language'] = preferred_language
        session['auto_translate'] = auto_translate
    
    return render_template('detail.html', study_session=study_session, rsvps=rsvps, messages=messages,
                         current_count=current_count, max_participants=max_participants,
                         is_full=is_full, spots_left=spots_left, user_has_rsvp=user_has_rsvp,
                         is_creator=is_creator, all_users=all_users, files=files, recordings=recordings)

# ============================================
# MESSAGING ROUTES
# ============================================

@app.route('/session/<int:session_id>/message', methods=['POST'])
@login_required
def post_message(session_id):
    """Post a new message to a session's chat.
    
    Supports threaded replies via parent_message_id.
    Broadcasts new messages via WebSocket for real-time updates.
    """
    message_text = request.form.get('message_text', '')
    parent_message_id = request.form.get('parent_message_id', None)
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    if message_text.strip():
        conn = get_db()
        
        # Insert message with optional parent for threading
        conn.execute(
            'INSERT INTO messages (session_id, user_id, message_text, parent_message_id) VALUES (?, ?, ?, ?)',
            (session_id, session['user_id'], message_text, parent_message_id)
        )
        conn.commit()
        
        # Retrieve newly created message with user details for broadcast
        new_message = conn.execute('''
            SELECT m.*, u.full_name, u.username
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.session_id = ? AND m.user_id = ?
            ORDER BY m.created_at DESC
            LIMIT 1
        ''', (session_id, session['user_id'])).fetchone()
        
        # Get parent message info if this is a reply
        parent_info = None
        if parent_message_id:
            parent = conn.execute('''
                SELECT m.message_text, u.full_name
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            ''', (parent_message_id,)).fetchone()
            if parent:
                parent_info = {
                    'id': parent_message_id,
                    'text': parent['message_text'],
                    'author': parent['full_name']
                }
        
        conn.close()
        
        # Broadcast message to all users in the session room via WebSocket
        message_data = {
            'id': new_message['id'],
            'full_name': new_message['full_name'],
            'username': new_message['username'],
            'message_text': new_message['message_text'],
            'created_at': new_message['created_at'],
            'user_id': new_message['user_id'],
            'parent_message_id': new_message['parent_message_id'],
            'parent_info': parent_info,
            'reactions': []
        }
        socketio.emit('new_message', message_data, room=f'session_{session_id}')
        
        if is_ajax:
            return jsonify({
                'success': True,
                'message': message_data
            })
        
        flash('Message posted!')
    
    if is_ajax:
        return jsonify({'success': False, 'error': 'Empty message'})
    
    return redirect(url_for('detail', session_id=session_id))

@app.route('/session/<int:session_id>/messages')
def get_messages(session_id):
    """API endpoint to fetch new messages since a given message ID.
    
    Args:
        session_id: ID of the study session
        last_id (query param): Last message ID client has received
        
    Returns:
        JSON with list of new messages including reactions
    """
    last_message_id = request.args.get('last_id', 0, type=int)
    
    conn = get_db()
    
    # Fetch only messages newer than last_id for efficient polling
    messages = conn.execute('''
        SELECT m.*, u.full_name, u.username
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.session_id = ? AND m.id > ?
        ORDER BY m.created_at ASC
    ''', (session_id, last_message_id)).fetchall()
    
    # Enrich each message with aggregated reactions
    message_list = []
    for msg in messages:
        reactions = conn.execute('''
            SELECT emoji, COUNT(*) as count, GROUP_CONCAT(user_id) as user_ids
            FROM message_reactions
            WHERE message_id = ?
            GROUP BY emoji
        ''', (msg['id'],)).fetchall()
        
        message_list.append({
            'id': msg['id'],
            'full_name': msg['full_name'],
            'username': msg['username'],
            'message_text': msg['message_text'],
            'created_at': msg['created_at'],
            'user_id': msg['user_id'],
            'parent_message_id': msg['parent_message_id'],
            'reactions': [{
                'emoji': r['emoji'],
                'count': r['count'],
                'user_ids': [int(uid) for uid in r['user_ids'].split(',')]
            } for r in reactions]
        })
    
    conn.close()
    
    return jsonify({'messages': message_list})

@app.route('/message/<int:message_id>/react', methods=['POST'])
@login_required
def react_to_message(message_id):
    """Add or remove an emoji reaction to a chat message.
    
    Args:
        message_id: ID of the message to react to
        
    JSON Body:
        emoji: Emoji character to react with
        action: 'add', 'remove', or 'toggle' (default: toggle)
        
    Returns:
        JSON with success status and updated reaction counts
    """
    data = request.get_json()
    emoji = data.get('emoji', '').strip()
    action = data.get('action', 'toggle')
    
    if not emoji:
        return jsonify({'success': False, 'error': 'Emoji is required'}), 400
    
    conn = get_db()
    
    # Validate message exists and get its session for broadcasting
    message = conn.execute(
        'SELECT session_id FROM messages WHERE id = ?',
        (message_id,)
    ).fetchone()
    
    if not message:
        conn.close()
        return jsonify({'success': False, 'error': 'Message not found'}), 404
    
    session_id = message['session_id']
    
    # Check if user has already reacted with this emoji
    existing = conn.execute('''
        SELECT id FROM message_reactions 
        WHERE message_id = ? AND user_id = ? AND emoji = ?
    ''', (message_id, session['user_id'], emoji)).fetchone()
    
    # Toggle logic: remove if exists, add if doesn't
    if action == 'toggle':
        action = 'remove' if existing else 'add'
    
    if action == 'add' and not existing:
        conn.execute('''
            INSERT INTO message_reactions (message_id, user_id, emoji) 
            VALUES (?, ?, ?)
        ''', (message_id, session['user_id'], emoji))
        conn.commit()
    elif action == 'remove' and existing:
        conn.execute('''
            DELETE FROM message_reactions 
            WHERE message_id = ? AND user_id = ? AND emoji = ?
        ''', (message_id, session['user_id'], emoji))
        conn.commit()
    
    # Get updated reaction counts for this message
    reactions = conn.execute('''
        SELECT emoji, COUNT(*) as count, GROUP_CONCAT(user_id) as user_ids
        FROM message_reactions
        WHERE message_id = ?
        GROUP BY emoji
    ''', (message_id,)).fetchall()
    
    conn.close()
    
    reaction_data = {
        'message_id': message_id,
        'reactions': [{
            'emoji': r['emoji'],
            'count': r['count'],
            'user_ids': [int(uid) for uid in r['user_ids'].split(',')]
        } for r in reactions]
    }
    
    # Broadcast reaction update to all users in the session
    socketio.emit('reaction_updated', reaction_data, room=f'session_{session_id}')
    
    return jsonify({'success': True, 'data': reaction_data})

# ============================================
# RSVP & INVITATION ROUTES
# ============================================

@app.route('/session/<int:session_id>/invite', methods=['POST'])
@login_required
def invite_user(session_id):
    """Send an invitation to another user to join a session.
    
    Only the session creator can send invitations.
    Creates a notification for the invited user.
    """
    invitee_id = request.form.get('invitee_id')
    
    if invitee_id:
        conn = get_db()
        
        # Verify the current user is the session creator
        study_session = conn.execute(
            'SELECT creator_id FROM sessions WHERE id = ?',
            (session_id,)
        ).fetchone()
        
        if study_session and study_session['creator_id'] == session['user_id']:
            try:
                # Create invitation record
                conn.execute('''
                    INSERT INTO invitations (session_id, inviter_id, invitee_id) 
                    VALUES (?, ?, ?)
                ''', (session_id, session['user_id'], invitee_id))
                conn.commit()
                
                # Get session details for notification
                session_info = conn.execute('SELECT title FROM sessions WHERE id = ?', (session_id,)).fetchone()
                
                # Create notification for invitee
                create_notification(
                    user_id=int(invitee_id),
                    notif_type='invitation',
                    title='New Session Invitation',
                    message=f'{session["full_name"]} invited you to "{session_info["title"]}"',
                    link=f'/session/{session_id}'
                )
                
                flash('Invitation sent successfully!')
            except sqlite3.IntegrityError:
                flash('User has already been invited!')
        else:
            flash('Only the session creator can send invitations!')
        
        conn.close()
    
    return redirect(url_for('detail', session_id=session_id))

# ============================================
# SESSION MANAGEMENT ROUTES
# ============================================

@app.route('/session/<int:session_id>/delete', methods=['POST'])
@login_required
def delete_session(session_id):
    """Delete a study session and all associated data.
    
    Only the session creator can delete the session.
    Removes all files, messages, RSVPs, and invitations.
    """
    conn = get_db()
    
    # Verify the current user is the session creator
    study_session = conn.execute(
        'SELECT creator_id FROM sessions WHERE id = ?',
        (session_id,)
    ).fetchone()
    
    if study_session and study_session['creator_id'] == session['user_id']:
        # Remove uploaded files from disk first
        files = conn.execute(
            'SELECT filename FROM files WHERE session_id = ?',
            (session_id,)
        ).fetchall()
        
        for file_record in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['filename'])
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # Clean up all database records associated with this session
        conn.execute('DELETE FROM files WHERE session_id = ?', (session_id,))
        conn.execute('DELETE FROM messages WHERE session_id = ?', (session_id,))
        conn.execute('DELETE FROM rsvps WHERE session_id = ?', (session_id,))
        conn.execute('DELETE FROM invitations WHERE session_id = ?', (session_id,))
        conn.execute('DELETE FROM sessions WHERE id = ?', (session_id,))
        conn.commit()
        
        flash('Study session deleted successfully!')
        conn.close()
        return redirect(url_for('index'))
    else:
        flash('Only the session creator can delete this session!')
        conn.close()
        return redirect(url_for('detail', session_id=session_id))

@app.route('/session/<int:session_id>/reminder', methods=['POST'])
@login_required
def send_reminder(session_id):
    """Send a reminder message to all session participants.
    
    Only the session creator can send reminders.
    """
    reminder_text = request.form.get('reminder_text', '').strip()
    
    if not reminder_text:
        flash('Please enter a reminder message!')
        return redirect(url_for('detail', session_id=session_id))
    
    conn = get_db()
    
    # Verify the current user is the session creator
    study_session = conn.execute(
        'SELECT creator_id FROM sessions WHERE id = ?',
        (session_id,)
    ).fetchone()
    
    if study_session and study_session['creator_id'] == session['user_id']:
        # Create reminder record
        conn.execute(
            'INSERT INTO reminders (session_id, reminder_text, sent_by) VALUES (?, ?, ?)',
            (session_id, reminder_text, session['user_id'])
        )
        conn.commit()
        flash(f'Reminder sent to all participants: "{reminder_text}"')
    else:
        flash('Only the session creator can send reminders!')
    
    conn.close()
    return redirect(url_for('detail', session_id=session_id))

@app.route('/reminder/<int:reminder_id>/dismiss', methods=['POST'])
@login_required
def dismiss_reminder(reminder_id):
    """Mark a reminder as dismissed for the current user."""
    conn = get_db()
    
    try:
        conn.execute(
            'INSERT INTO dismissed_reminders (reminder_id, user_id) VALUES (?, ?)',
            (reminder_id, session['user_id'])
        )
        conn.commit()
        flash('Reminder dismissed')
    except sqlite3.IntegrityError:
        # Reminder already dismissed by this user
        pass
        pass
    
    conn.close()
    return redirect(url_for('index'))

# ============================================
# NOTIFICATION ROUTES
# ============================================

@app.route('/notifications')
@login_required
def get_notifications():
    """API endpoint to fetch user's recent notifications.
    
    Returns:
        JSON with list of up to 50 most recent notifications
    """
    conn = get_db()
    notifications = conn.execute('''
        SELECT * FROM notifications 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 50
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return jsonify({
        'notifications': [{
            'id': n['id'],
            'type': n['type'],
            'title': n['title'],
            'message': n['message'],
            'link': n['link'],
            'is_read': n['is_read'],
            'created_at': n['created_at']
        } for n in notifications]
    })

@app.route('/notifications/unread-count')
@login_required
def unread_count():
    """Get count of unread notifications"""
    conn = get_db()
    count = conn.execute(
        'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0',
        (session['user_id'],)
    ).fetchone()['count']
    conn.close()
    return jsonify({'count': count})

@app.route('/notifications/<int:notif_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notif_id):
    """Mark a notification as read"""
    conn = get_db()
    conn.execute(
        'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
        (notif_id, session['user_id'])
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_read():
    """Mark all notifications as read"""
    conn = get_db()
    conn.execute(
        'UPDATE notifications SET is_read = 1 WHERE user_id = ?',
        (session['user_id'],)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ============================================
# FILE UPLOAD ROUTES
# ============================================

@app.route('/session/<int:session_id>/upload', methods=['POST'])
@login_required
def upload_file(session_id):
    """Upload a file to a study session.
    
    Files can be uploaded in two contexts:
    - 'study_material': Shared study resources (default)
    - 'chat': Files sent in chat messages
    
    Only RSVP'd users can upload files.
    Broadcasts file to all session participants via WebSocket.
    """
    # Detect AJAX vs regular form submission
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', '')
    
    # Get file context (determines where file appears in UI)
    file_context = request.form.get('file_context', 'study_material')
    
    # validate file exists in request
    if 'file' not in request.files:
        if is_ajax:
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        flash('No file selected')
        return redirect(url_for('detail', session_id=session_id))
    
    file = request.files['file']
    
    # make sure file isn't empty
    if file.filename == '':
        if is_ajax:
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        flash('No file selected')
        return redirect(url_for('detail', session_id=session_id))
    
    # only allow uploads from RSVP'd users
    conn = get_db()
    rsvp = conn.execute('SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
                       (session_id, session['user_id'])).fetchone()
    
    if not rsvp:
        error_msg = 'You must RSVP to upload files to this session'
        conn.close()
        if is_ajax:
            return jsonify({'success': False, 'error': error_msg}), 403
        flash(error_msg)
        return redirect(url_for('detail', session_id=session_id))
    
    # check file type is allowed
    if file and allowed_file(file.filename):
        # create unique filename with timestamp
        original_filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{original_filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # save to disk
        file.save(file_path)
        
        # get file metadata
        file_size = os.path.getsize(file_path)
        file_type = original_filename.rsplit('.', 1)[1].lower()
        
        # store file info in database
        cursor = conn.execute('''INSERT INTO files (session_id, user_id, filename, original_filename, file_size, file_type, file_context) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (session_id, session['user_id'], filename, original_filename, file_size, file_type, file_context))
        file_id = cursor.lastrowid
        conn.commit()
        
        # get user info for AJAX response
        user_info = conn.execute('SELECT full_name, username FROM users WHERE id = ?', 
                                 (session['user_id'],)).fetchone()
        conn.close()
        
        # Broadcast new file to all users in the session via WebSocket
        file_data = {
            'id': file_id,
            'file_id': file_id,
            'original_filename': original_filename,
            'file_size': file_size,
            'file_type': file_type,
            'file_context': file_context,
            'full_name': user_info['full_name'],
            'username': user_info['username'],
            'user_id': session['user_id'],
            'uploaded_at': datetime.now().isoformat(),
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': 'file'
        }
        
        # Emit different events based on context
        if file_context == 'chat':
            socketio.emit('chat_file', file_data, room=f'session_{session_id}')
        else:
            socketio.emit('new_file', file_data, room=f'session_{session_id}')
        
        if is_ajax:
            return jsonify({
                'success': True, 
                'message': f'File "{original_filename}" uploaded successfully!',
                'file': file_data
            }), 200
        else:
            flash(f'File "{original_filename}" uploaded successfully!')
            return redirect(url_for('detail', session_id=session_id))
    else:
        error_msg = 'Invalid file type. Allowed types: images, PDFs, Office documents, text files, archives'
        conn.close()
        if is_ajax:
            return jsonify({'success': False, 'error': error_msg}), 400
        else:
            flash(error_msg)
            return redirect(url_for('detail', session_id=session_id))

@app.route('/session/<int:session_id>/files')
def get_files(session_id):
    """API endpoint to fetch study material files for real-time updates"""
    last_file_id = request.args.get('last_id', 0, type=int)
    
    conn = get_db()
    files = conn.execute('''
        SELECT f.*, u.full_name, u.username
        FROM files f
        JOIN users u ON f.user_id = u.id
        WHERE f.session_id = ? AND f.id > ? AND (f.file_context IS NULL OR f.file_context = 'study_material')
        ORDER BY f.uploaded_at ASC
    ''', (session_id, last_file_id)).fetchall()
    conn.close()
    
    return jsonify({
        'files': [{
            'id': f['id'],
            'original_filename': f['original_filename'],
            'file_size': f['file_size'],
            'file_type': f['file_type'],
            'full_name': f['full_name'],
            'username': f['username'],
            'uploaded_at': f['uploaded_at']
        } for f in files]
    })

@app.route('/file/<int:file_id>/download')
@login_required
def download_file(file_id):
    conn = get_db()
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        flash('File not found')
        return redirect(url_for('index'))
    
    # verify user has RSVP'd before allowing download
    rsvp = conn.execute('SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
                       (file_record['session_id'], session['user_id'])).fetchone()
    conn.close()
    
    if not rsvp:
        flash('You must RSVP to download files from this session')
        return redirect(url_for('detail', session_id=file_record['session_id']))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_record['filename'], 
                              as_attachment=True, download_name=file_record['original_filename'])

@app.route('/file/<int:file_id>/info')
@login_required
def file_info(file_id):
    """Get file metadata for preview modal"""
    conn = get_db()
    file_record = conn.execute('SELECT id, original_filename, file_type, user_id, session_id FROM files WHERE id = ?', (file_id,)).fetchone()
    conn.close()
    
    if not file_record:
        return jsonify({'error': 'File not found'}), 404
    
    return jsonify({
        'id': file_record['id'],
        'original_filename': file_record['original_filename'],
        'file_type': file_record['file_type'],
        'user_id': file_record['user_id'],
        'session_id': file_record['session_id']
    })

@app.route('/file/<int:file_id>/preview')
@login_required
def preview_file(file_id):
    """Serve file for inline preview (images, PDFs)"""
    conn = get_db()
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        flash('File not found')
        return redirect(url_for('index'))
    
    # verify user has RSVP'd before allowing preview
    rsvp = conn.execute('SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
                       (file_record['session_id'], session['user_id'])).fetchone()
    conn.close()
    
    if not rsvp:
        flash('You must RSVP to preview files from this session')
        return redirect(url_for('detail', session_id=file_record['session_id']))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_record['filename'])

@app.route('/file/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    conn = get_db()
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        flash('File not found')
        return redirect(url_for('index'))
    
    session_id = file_record['session_id']
    
    # only uploader or session creator can delete
    study_session = conn.execute('SELECT creator_id FROM sessions WHERE id = ?', (session_id,)).fetchone()
    
    if file_record['user_id'] == session['user_id'] or study_session['creator_id'] == session['user_id']:
        # remove from disk
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # remove from database
        conn.execute('DELETE FROM files WHERE id = ?', (file_id,))
        conn.commit()
        flash('File deleted successfully')
    else:
        flash('You can only delete your own files')
    
    conn.close()
    return redirect(url_for('detail', session_id=session_id))

# ============================================
# ADVANCED FILE MANAGEMENT
# ============================================

@app.route('/api/files/categories', methods=['GET'])
@login_required
def get_file_categories():
    """Get all file categories"""
    conn = get_db()
    categories = conn.execute('SELECT * FROM file_categories ORDER BY name').fetchall()
    conn.close()
    return jsonify({
        'success': True,
        'categories': [dict(cat) for cat in categories]
    })

@app.route('/api/files/categories', methods=['POST'])
@login_required
def create_file_category():
    """Create a new file category"""
    data = request.get_json()
    name = data.get('name')
    icon = data.get('icon', 'fa-file')
    color = data.get('color', '#667eea')
    
    if not name:
        return jsonify({'success': False, 'error': 'Category name is required'}), 400
    
    conn = get_db()
    try:
        cursor = conn.execute(
            'INSERT INTO file_categories (name, icon, color) VALUES (?, ?, ?)',
            (name, icon, color)
        )
        conn.commit()
        category_id = cursor.lastrowid
        conn.close()
        return jsonify({
            'success': True,
            'category': {'id': category_id, 'name': name, 'icon': icon, 'color': color}
        })
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': 'Category already exists'}), 400

@app.route('/api/files/tags', methods=['GET'])
@login_required
def get_file_tags():
    """Get all file tags"""
    conn = get_db()
    tags = conn.execute('SELECT * FROM file_tags ORDER BY name').fetchall()
    conn.close()
    return jsonify({
        'success': True,
        'tags': [dict(tag) for tag in tags]
    })

@app.route('/api/files/tags', methods=['POST'])
@login_required
def create_file_tag():
    """Create a new file tag"""
    data = request.get_json()
    name = data.get('name')
    color = data.get('color', '#667eea')
    
    if not name:
        return jsonify({'success': False, 'error': 'Tag name is required'}), 400
    
    conn = get_db()
    try:
        cursor = conn.execute(
            'INSERT INTO file_tags (name, color) VALUES (?, ?)',
            (name, color)
        )
        conn.commit()
        tag_id = cursor.lastrowid
        conn.close()
        return jsonify({
            'success': True,
            'tag': {'id': tag_id, 'name': name, 'color': color}
        })
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': 'Tag already exists'}), 400

@app.route('/api/files/<int:file_id>/categorize', methods=['POST'])
@login_required
def categorize_file(file_id):
    """Assign a category to a file"""
    data = request.get_json()
    category_id = data.get('category_id')
    
    conn = get_db()
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        return jsonify({'success': False, 'error': 'File not found'}), 404
    
    # Check if user has access to the session
    session_id = file_record['session_id']
    rsvp = conn.execute('SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
                       (session_id, session['user_id'])).fetchone()
    
    if not rsvp:
        conn.close()
        return jsonify({'success': False, 'error': 'No access to this session'}), 403
    
    conn.execute('UPDATE files SET category_id = ? WHERE id = ?', (category_id, file_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'File categorized successfully'})

@app.route('/api/files/<int:file_id>/tag', methods=['POST'])
@login_required
def tag_file(file_id):
    """Add tags to a file"""
    data = request.get_json()
    tag_ids = data.get('tag_ids', [])
    
    conn = get_db()
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        return jsonify({'success': False, 'error': 'File not found'}), 404
    
    # Check if user has access to the session
    session_id = file_record['session_id']
    rsvp = conn.execute('SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
                       (session_id, session['user_id'])).fetchone()
    
    if not rsvp:
        conn.close()
        return jsonify({'success': False, 'error': 'No access to this session'}), 403
    
    # Remove existing tags and add new ones
    conn.execute('DELETE FROM file_tag_relationships WHERE file_id = ?', (file_id,))
    for tag_id in tag_ids:
        conn.execute(
            'INSERT OR IGNORE INTO file_tag_relationships (file_id, tag_id) VALUES (?, ?)',
            (file_id, tag_id)
        )
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'File tagged successfully'})

@app.route('/api/files/<int:file_id>/favorite', methods=['POST'])
@login_required
def toggle_file_favorite(file_id):
    """Toggle favorite status for a file"""
    conn = get_db()
    user_id = session['user_id']
    
    # Check if already favorited
    existing = conn.execute(
        'SELECT id FROM file_favorites WHERE file_id = ? AND user_id = ?',
        (file_id, user_id)
    ).fetchone()
    
    if existing:
        conn.execute('DELETE FROM file_favorites WHERE file_id = ? AND user_id = ?', 
                    (file_id, user_id))
        is_favorite = False
    else:
        conn.execute('INSERT INTO file_favorites (file_id, user_id) VALUES (?, ?)',
                    (file_id, user_id))
        is_favorite = True
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'is_favorite': is_favorite,
        'message': 'Added to favorites' if is_favorite else 'Removed from favorites'
    })

@app.route('/api/files/folders', methods=['GET'])
@login_required
def get_folders():
    """Get folders for a session"""
    session_id = request.args.get('session_id', type=int)
    
    if not session_id:
        return jsonify({'success': False, 'error': 'Session ID required'}), 400
    
    conn = get_db()
    folders = conn.execute('''
        SELECT f.*, u.full_name as creator_name
        FROM file_folders f
        JOIN users u ON f.created_by = u.id
        WHERE f.session_id = ?
        ORDER BY f.name
    ''', (session_id,)).fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'folders': [dict(folder) for folder in folders]
    })

@app.route('/api/files/folders', methods=['POST'])
@login_required
def create_folder():
    """Create a new folder"""
    data = request.get_json()
    session_id = data.get('session_id')
    name = data.get('name')
    parent_folder_id = data.get('parent_folder_id')
    
    if not session_id or not name:
        return jsonify({'success': False, 'error': 'Session ID and name required'}), 400
    
    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO file_folders (session_id, name, parent_folder_id, created_by) VALUES (?, ?, ?, ?)',
        (session_id, name, parent_folder_id, session['user_id'])
    )
    folder_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'folder': {'id': folder_id, 'name': name, 'session_id': session_id}
    })

@app.route('/api/files/<int:file_id>/move', methods=['POST'])
@login_required
def move_file_to_folder(file_id):
    """Move a file to a folder"""
    data = request.get_json()
    folder_id = data.get('folder_id')
    
    conn = get_db()
    conn.execute('UPDATE files SET folder_id = ? WHERE id = ?', (folder_id, file_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'File moved successfully'})

@app.route('/api/files/bulk-download', methods=['POST'])
@login_required
def bulk_download_files():
    """Download multiple files as a ZIP"""
    import zipfile
    from io import BytesIO
    
    data = request.get_json()
    file_ids = data.get('file_ids', [])
    
    if not file_ids:
        return jsonify({'success': False, 'error': 'No files selected'}), 400
    
    conn = get_db()
    files = conn.execute(f'''
        SELECT * FROM files WHERE id IN ({','.join('?' * len(file_ids))})
    ''', file_ids).fetchall()
    conn.close()
    
    # Create ZIP file in memory
    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_record in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['filename'])
            if os.path.exists(file_path):
                zf.write(file_path, file_record['original_filename'])
    
    memory_file.seek(0)
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name='files.zip'
    )

@app.route('/api/files/<int:file_id>/archive', methods=['POST'])
@login_required
def archive_file(file_id):
    """Archive or unarchive a file"""
    data = request.get_json()
    is_archived = data.get('is_archived', 1)
    
    conn = get_db()
    conn.execute('UPDATE files SET is_archived = ? WHERE id = ?', (is_archived, file_id))
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'File archived' if is_archived else 'File restored'
    })

@app.route('/api/files/<int:file_id>/versions', methods=['GET'])
@login_required
def get_file_versions(file_id):
    """Get version history for a file"""
    conn = get_db()
    versions = conn.execute('''
        SELECT v.*, u.full_name as uploader_name
        FROM file_versions v
        JOIN users u ON v.uploaded_by = u.id
        WHERE v.file_id = ?
        ORDER BY v.version_number DESC
    ''', (file_id,)).fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'versions': [dict(v) for v in versions]
    })

@app.route('/api/files/<int:file_id>/upload-version', methods=['POST'])
@login_required
def upload_file_version(file_id):
    """Upload a new version of an existing file"""
    conn = get_db()
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        return jsonify({'success': False, 'error': 'File not found'}), 404
    
    if 'file' not in request.files:
        conn.close()
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    change_description = request.form.get('change_description', '')
    
    if file.filename == '':
        conn.close()
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        # Save new version with timestamp
        original_filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{original_filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get current version number
        current_version = file_record['version'] or 1
        new_version = current_version + 1
        
        # Save old version to file_versions table
        conn.execute('''
            INSERT INTO file_versions 
            (file_id, version_number, filename, file_size, uploaded_by, change_description)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (file_id, current_version, file_record['filename'], 
              file_record['file_size'], file_record['user_id'], 'Previous version'))
        
        # Update files table with new version
        file_size = os.path.getsize(file_path)
        conn.execute('''
            UPDATE files 
            SET filename = ?, original_filename = ?, file_size = ?, 
                version = ?, user_id = ?, uploaded_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (filename, original_filename, file_size, new_version, session['user_id'], file_id))
        
        # Save new version to file_versions
        conn.execute('''
            INSERT INTO file_versions 
            (file_id, version_number, filename, file_size, uploaded_by, change_description)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (file_id, new_version, filename, file_size, session['user_id'], change_description))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Version {new_version} uploaded successfully',
            'version': new_version
        })
    else:
        conn.close()
        return jsonify({'success': False, 'error': 'Invalid file type'}), 400

@app.route('/api/files/<int:file_id>/revert/<int:version_number>', methods=['POST'])
@login_required
def revert_file_version(file_id, version_number):
    """Revert file to a previous version"""
    conn = get_db()
    
    # Get the version to revert to
    version = conn.execute('''
        SELECT * FROM file_versions 
        WHERE file_id = ? AND version_number = ?
    ''', (file_id, version_number)).fetchone()
    
    if not version:
        conn.close()
        return jsonify({'success': False, 'error': 'Version not found'}), 404
    
    # Get current file
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    current_version = file_record['version'] or 1
    new_version = current_version + 1
    
    # Save current version before reverting
    conn.execute('''
        INSERT INTO file_versions 
        (file_id, version_number, filename, file_size, uploaded_by, change_description)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (file_id, current_version, file_record['filename'], 
          file_record['file_size'], file_record['user_id'], 'Before revert'))
    
    # Update files table with reverted version
    conn.execute('''
        UPDATE files 
        SET filename = ?, file_size = ?, version = ?, user_id = ?, 
            uploaded_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (version['filename'], version['file_size'], new_version, 
          session['user_id'], file_id))
    
    # Record the revert as a new version
    conn.execute('''
        INSERT INTO file_versions 
        (file_id, version_number, filename, file_size, uploaded_by, change_description)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (file_id, new_version, version['filename'], version['file_size'], 
          session['user_id'], f'Reverted to version {version_number}'))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': f'Reverted to version {version_number}',
        'version': new_version
    })

# ============================================
# STUDY GROUPS & COMMUNITIES
# ============================================

@app.route('/groups')
@login_required
def groups_list():
    """Display all study groups"""
    conn = get_db()
    
    # Get all public groups and user's private groups
    groups = conn.execute('''
        SELECT g.*, u.full_name as creator_name, u.username as creator_username,
               COUNT(DISTINCT gm.user_id) as member_count
        FROM study_groups g
        JOIN users u ON g.created_by = u.id
        LEFT JOIN group_members gm ON g.id = gm.group_id
        WHERE g.is_archived = 0 AND (
            g.group_type = 'public' OR 
            g.id IN (SELECT group_id FROM group_members WHERE user_id = ?)
        )
        GROUP BY g.id
        ORDER BY g.created_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get user's memberships
    user_groups = conn.execute('''
        SELECT group_id FROM group_members WHERE user_id = ?
    ''', (session['user_id'],)).fetchall()
    user_group_ids = {g['group_id'] for g in user_groups}
    
    conn.close()
    
    return render_template('groups.html', 
                         groups=groups, 
                         user_group_ids=user_group_ids)

@app.route('/groups/create', methods=['GET', 'POST'])
@login_required
def create_group():
    """Create a new study group"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        subject = request.form.get('subject')
        group_type = request.form.get('group_type', 'public')
        member_limit = request.form.get('member_limit', 50, type=int)
        
        if not name or not subject:
            flash('Name and subject are required')
            return redirect(url_for('create_group'))
        
        conn = get_db()
        cursor = conn.execute('''
            INSERT INTO study_groups (name, description, subject, group_type, member_limit, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (name, description, subject, group_type, member_limit, session['user_id']))
        group_id = cursor.lastrowid
        
        # Auto-join creator as admin
        conn.execute('''
            INSERT INTO group_members (group_id, user_id, role)
            VALUES (?, ?, 'admin')
        ''', (group_id, session['user_id']))
        
        # Log activity
        conn.execute('''
            INSERT INTO group_activities (group_id, user_id, activity_type, activity_data)
            VALUES (?, ?, 'group_created', ?)
        ''', (group_id, session['user_id'], f'{{"group_name": "{name}"}}'))
        
        conn.commit()
        conn.close()
        
        flash(f'Study group "{name}" created successfully!')
        return redirect(url_for('group_detail', group_id=group_id))
    
    return render_template('create_group.html')

@app.route('/groups/<int:group_id>')
@login_required
def group_detail(group_id):
    """Display group details, posts, and resources"""
    conn = get_db()
    
    # Get group info
    group = conn.execute('''
        SELECT g.*, u.full_name as creator_name, u.username as creator_username
        FROM study_groups g
        JOIN users u ON g.created_by = u.id
        WHERE g.id = ?
    ''', (group_id,)).fetchone()
    
    if not group:
        conn.close()
        flash('Group not found')
        return redirect(url_for('groups_list'))
    
    # Check if user is member
    membership = conn.execute('''
        SELECT * FROM group_members WHERE group_id = ? AND user_id = ?
    ''', (group_id, session['user_id'])).fetchone()
    
    # If private group and not a member, redirect
    if group['group_type'] == 'private' and not membership:
        conn.close()
        flash('This is a private group')
        return redirect(url_for('groups_list'))
    
    # Get members
    members = conn.execute('''
        SELECT gm.*, u.full_name, u.username, u.avatar_filename
        FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = ?
        ORDER BY gm.role, gm.joined_at
    ''', (group_id,)).fetchall()
    
    # Get posts
    posts = conn.execute('''
        SELECT p.*, u.full_name, u.username, u.avatar_filename,
               COUNT(DISTINCT r.id) as reply_count,
               COUNT(DISTINCT pr.id) as reaction_count
        FROM group_posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN group_post_replies r ON p.id = r.post_id
        LEFT JOIN group_post_reactions pr ON p.id = pr.post_id
        WHERE p.group_id = ?
        GROUP BY p.id
        ORDER BY p.is_pinned DESC, p.created_at DESC
        LIMIT 20
    ''', (group_id,)).fetchall()
    
    # Get resources
    resources = conn.execute('''
        SELECT gr.*, u.full_name, u.username
        FROM group_resources gr
        JOIN users u ON gr.user_id = u.id
        WHERE gr.group_id = ?
        ORDER BY gr.created_at DESC
        LIMIT 10
    ''', (group_id,)).fetchall()
    
    # Get recent activities
    activities = conn.execute('''
        SELECT ga.*, u.full_name, u.username
        FROM group_activities ga
        JOIN users u ON ga.user_id = u.id
        WHERE ga.group_id = ?
        ORDER BY ga.created_at DESC
        LIMIT 10
    ''', (group_id,)).fetchall()
    
    conn.close()
    
    return render_template('group_detail.html',
                         group=group,
                         membership=membership,
                         members=members,
                         posts=posts,
                         resources=resources,
                         activities=activities,
                         is_member=bool(membership))

@app.route('/api/groups/<int:group_id>/join', methods=['POST'])
@login_required
def join_group(group_id):
    """Join a public group or request to join private group"""
    conn = get_db()
    group = conn.execute('SELECT * FROM study_groups WHERE id = ?', (group_id,)).fetchone()
    
    if not group:
        conn.close()
        return jsonify({'success': False, 'error': 'Group not found'}), 404
    
    # Check if already a member
    existing = conn.execute('''
        SELECT id FROM group_members WHERE group_id = ? AND user_id = ?
    ''', (group_id, session['user_id'])).fetchone()
    
    if existing:
        conn.close()
        return jsonify({'success': False, 'error': 'Already a member'}), 400
    
    if group['group_type'] == 'public':
        # Direct join for public groups
        conn.execute('''
            INSERT INTO group_members (group_id, user_id, role)
            VALUES (?, ?, 'member')
        ''', (group_id, session['user_id']))
        
        # Log activity
        conn.execute('''
            INSERT INTO group_activities (group_id, user_id, activity_type)
            VALUES (?, ?, 'member_joined')
        ''', (group_id, session['user_id']))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Joined group successfully'})
    else:
        # Create join request for private groups
        data = request.get_json() or {}
        message = data.get('message', '')
        
        try:
            conn.execute('''
                INSERT INTO group_join_requests (group_id, user_id, message)
                VALUES (?, ?, ?)
            ''', (group_id, session['user_id'], message))
            conn.commit()
            conn.close()
            return jsonify({'success': True, 'message': 'Join request sent'})
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'success': False, 'error': 'Request already pending'}), 400

@app.route('/api/groups/<int:group_id>/leave', methods=['POST'])
@login_required
def leave_group(group_id):
    """Leave a group"""
    conn = get_db()
    
    # Check if user is the creator
    group = conn.execute('SELECT created_by FROM study_groups WHERE id = ?', (group_id,)).fetchone()
    if group and group['created_by'] == session['user_id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Group creator cannot leave'}), 400
    
    conn.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?',
                (group_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Left group successfully'})

@app.route('/api/groups/<int:group_id>/posts', methods=['POST'])
@login_required
def create_group_post(group_id):
    """Create a new discussion post"""
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    post_type = data.get('post_type', 'discussion')
    
    if not title or not content:
        return jsonify({'success': False, 'error': 'Title and content required'}), 400
    
    conn = get_db()
    
    # Verify membership
    membership = conn.execute('''
        SELECT id FROM group_members WHERE group_id = ? AND user_id = ?
    ''', (group_id, session['user_id'])).fetchone()
    
    if not membership:
        conn.close()
        return jsonify({'success': False, 'error': 'Must be a member to post'}), 403
    
    cursor = conn.execute('''
        INSERT INTO group_posts (group_id, user_id, title, content, post_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (group_id, session['user_id'], title, content, post_type))
    post_id = cursor.lastrowid
    
    # Log activity
    conn.execute('''
        INSERT INTO group_activities (group_id, user_id, activity_type, activity_data)
        VALUES (?, ?, 'post_created', ?)
    ''', (group_id, session['user_id'], f'{{"post_id": {post_id}, "title": "{title}"}}'))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'post_id': post_id, 'message': 'Post created'})

@app.route('/api/groups/posts/<int:post_id>/reply', methods=['POST'])
@login_required
def reply_to_post(post_id):
    """Reply to a discussion post"""
    data = request.get_json()
    content = data.get('content')
    
    if not content:
        return jsonify({'success': False, 'error': 'Content required'}), 400
    
    conn = get_db()
    cursor = conn.execute('''
        INSERT INTO group_post_replies (post_id, user_id, content)
        VALUES (?, ?, ?)
    ''', (post_id, session['user_id'], content))
    reply_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'reply_id': reply_id})

@app.route('/api/groups/<int:group_id>/resources', methods=['POST'])
@login_required
def add_group_resource(group_id):
    """Add a resource to the group"""
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    resource_type = data.get('resource_type')
    resource_url = data.get('resource_url')
    content = data.get('content')
    
    if not title or not resource_type:
        return jsonify({'success': False, 'error': 'Title and type required'}), 400
    
    conn = get_db()
    cursor = conn.execute('''
        INSERT INTO group_resources 
        (group_id, user_id, title, description, resource_type, resource_url, content)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (group_id, session['user_id'], title, description, resource_type, resource_url, content))
    resource_id = cursor.lastrowid
    
    # Log activity
    conn.execute('''
        INSERT INTO group_activities (group_id, user_id, activity_type, activity_data)
        VALUES (?, ?, 'resource_added', ?)
    ''', (group_id, session['user_id'], f'{{"resource_id": {resource_id}, "title": "{title}"}}'))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'resource_id': resource_id})

# ============================================
# STUDY MUSIC INTEGRATION
# ============================================

@app.route('/api/music/playlists', methods=['GET'])
@login_required
def get_playlists():
    """Get all available study playlists"""
    conn = get_db()
    playlists = conn.execute('''
        SELECT p.*, 
               CASE WHEN f.id IS NOT NULL THEN 1 ELSE 0 END as is_favorite
        FROM study_playlists p
        LEFT JOIN user_playlist_favorites f ON p.id = f.playlist_id AND f.user_id = ?
        WHERE p.is_active = 1
        ORDER BY p.playlist_type, p.name
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'playlists': [dict(p) for p in playlists]
    })

@app.route('/api/music/playlists/<int:playlist_id>/favorite', methods=['POST'])
@login_required
def toggle_playlist_favorite(playlist_id):
    """Toggle playlist favorite status"""
    conn = get_db()
    
    existing = conn.execute('''
        SELECT id FROM user_playlist_favorites 
        WHERE user_id = ? AND playlist_id = ?
    ''', (session['user_id'], playlist_id)).fetchone()
    
    if existing:
        conn.execute('DELETE FROM user_playlist_favorites WHERE user_id = ? AND playlist_id = ?',
                    (session['user_id'], playlist_id))
        is_favorite = False
    else:
        conn.execute('INSERT INTO user_playlist_favorites (user_id, playlist_id) VALUES (?, ?)',
                    (session['user_id'], playlist_id))
        is_favorite = True
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'is_favorite': is_favorite})

@app.route('/api/music/session/<int:session_id>/play', methods=['POST'])
@login_required
def play_session_music(session_id):
    """Start music playback for a session (synced for all participants)"""
    data = request.get_json()
    playlist_id = data.get('playlist_id')
    
    conn = get_db()
    
    # Check if user has access to session
    rsvp = conn.execute('SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
                       (session_id, session['user_id'])).fetchone()
    
    if not rsvp:
        conn.close()
        return jsonify({'success': False, 'error': 'No access to this session'}), 403
    
    # Update or create session music record
    existing = conn.execute('SELECT id FROM session_music WHERE session_id = ?', 
                          (session_id,)).fetchone()
    
    if existing:
        conn.execute('''
            UPDATE session_music 
            SET playlist_id = ?, is_playing = 1, current_time = 0,
                started_by = ?, started_at = CURRENT_TIMESTAMP
            WHERE session_id = ?
        ''', (playlist_id, session['user_id'], session_id))
    else:
        conn.execute('''
            INSERT INTO session_music (session_id, playlist_id, is_playing, started_by)
            VALUES (?, ?, 1, ?)
        ''', (session_id, playlist_id, session['user_id']))
    
    conn.commit()
    
    # Get playlist info
    playlist = conn.execute('SELECT * FROM study_playlists WHERE id = ?', 
                          (playlist_id,)).fetchone()
    conn.close()
    
    # Broadcast to all session participants via WebSocket
    socketio.emit('music_started', {
        'playlist_id': playlist_id,
        'playlist_name': playlist['name'],
        'youtube_url': playlist['youtube_url'],
        'started_by': session['user_id']
    }, room=f'session_{session_id}')
    
    return jsonify({'success': True, 'message': 'Music started'})

@app.route('/api/music/session/<int:session_id>/pause', methods=['POST'])
@login_required
def pause_session_music(session_id):
    """Pause music playback for a session"""
    data = request.get_json()
    current_time = data.get('current_time', 0)
    
    conn = get_db()
    conn.execute('''
        UPDATE session_music 
        SET is_playing = 0, current_time = ?
        WHERE session_id = ?
    ''', (current_time, session_id))
    conn.commit()
    conn.close()
    
    # Broadcast pause to all participants
    socketio.emit('music_paused', {
        'paused_by': session['user_id'],
        'current_time': current_time
    }, room=f'session_{session_id}')
    
    return jsonify({'success': True})

@app.route('/api/music/session/<int:session_id>/stop', methods=['POST'])
@login_required
def stop_session_music(session_id):
    """Stop music playback for a session"""
    conn = get_db()
    conn.execute('DELETE FROM session_music WHERE session_id = ?', (session_id,))
    conn.commit()
    conn.close()
    
    # Broadcast stop to all participants
    socketio.emit('music_stopped', {
        'stopped_by': session['user_id']
    }, room=f'session_{session_id}')
    
    return jsonify({'success': True})

@app.route('/api/music/session/<int:session_id>/status', methods=['GET'])
@login_required
def get_session_music_status(session_id):
    """Get current music status for a session"""
    conn = get_db()
    music_status = conn.execute('''
        SELECT sm.*, p.name as playlist_name, p.youtube_url, p.playlist_type,
               u.full_name as started_by_name
        FROM session_music sm
        LEFT JOIN study_playlists p ON sm.playlist_id = p.id
        LEFT JOIN users u ON sm.started_by = u.id
        WHERE sm.session_id = ?
    ''', (session_id,)).fetchone()
    conn.close()
    
    if music_status:
        return jsonify({
            'success': True,
            'music': dict(music_status)
        })
    else:
        return jsonify({
            'success': True,
            'music': None
        })

# ============================================
# ANALYTICS DASHBOARD
# ============================================

@app.route('/analytics')
@login_required
def analytics():
    """Display study analytics dashboard"""
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get sessions user has attended
    c.execute('''
        SELECT s.*, u.username as creator_name
        FROM sessions s
        JOIN rsvps r ON s.id = r.session_id
        JOIN users u ON s.creator_id = u.id
        WHERE r.user_id = ?
        ORDER BY s.session_date DESC
    ''', (user_id,))
    attended_sessions = c.fetchall()
    
    # Calculate total hours (assuming 2 hours per session if not specified)
    total_hours = sum([2 for _ in attended_sessions])
    
    # Count total sessions
    total_sessions = len(attended_sessions)
    
    # Get subject breakdown
    c.execute('''
        SELECT s.subject, COUNT(*) as count
        FROM sessions s
        JOIN rsvps r ON s.id = r.session_id
        WHERE r.user_id = ?
        GROUP BY s.subject
        ORDER BY count DESC
    ''', (user_id,))
    subject_data = c.fetchall()
    subject_labels = [row['subject'] for row in subject_data]
    subject_counts = [row['count'] for row in subject_data]
    favorite_subject = subject_labels[0] if subject_labels else 'N/A'
    
    # Calculate current streak (consecutive days with sessions)
    c.execute('''
        SELECT DISTINCT DATE(s.session_date) as session_date
        FROM sessions s
        JOIN rsvps r ON s.id = r.session_id
        WHERE r.user_id = ?
        ORDER BY session_date DESC
    ''', (user_id,))
    session_dates = [row['session_date'] for row in c.fetchall()]
    
    current_streak = 0
    if session_dates:
        current_date = datetime.now().date()
        for date_str in session_dates:
            session_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if (current_date - session_date).days == current_streak:
                current_streak += 1
            else:
                break
    
    # Sessions over time (last 30 days)
    c.execute('''
        SELECT DATE(s.session_date) as session_date, COUNT(*) as count
        FROM sessions s
        JOIN rsvps r ON s.id = r.session_id
        WHERE r.user_id = ?
        AND DATE(s.session_date) >= DATE('now', '-30 days')
        GROUP BY session_date
        ORDER BY session_date
    ''', (user_id,))
    timeline_data = c.fetchall()
    sessions_dates = [row['session_date'] for row in timeline_data]
    sessions_counts = [row['count'] for row in timeline_data]
    
    # Day of week analysis
    day_of_week_hours = [0, 0, 0, 0, 0, 0, 0]  # Mon-Sun
    for sess in attended_sessions:
        session_date = datetime.strptime(sess['session_date'], '%Y-%m-%d %H:%M')
        day_index = session_date.weekday()  # 0=Monday, 6=Sunday
        day_of_week_hours[day_index] += 2  # 2 hours per session
    
    # Monthly progress (last 6 months)
    c.execute('''
        SELECT strftime('%Y-%m', s.session_date) as month, 
               COUNT(*) as session_count,
               COUNT(*) * 2 as hours
        FROM sessions s
        JOIN rsvps r ON s.id = r.session_id
        WHERE r.user_id = ?
        AND DATE(s.session_date) >= DATE('now', '-6 months')
        GROUP BY month
        ORDER BY month
    ''', (user_id,))
    monthly_data = c.fetchall()
    monthly_labels = [datetime.strptime(row['month'], '%Y-%m').strftime('%B') for row in monthly_data]
    monthly_sessions = [row['session_count'] for row in monthly_data]
    monthly_hours = [row['hours'] for row in monthly_data]
    
    # Recent sessions for activity feed
    recent_sessions = []
    for sess in attended_sessions[:5]:  # Last 5 sessions
        session_date = datetime.strptime(sess['session_date'], '%Y-%m-%d %H:%M')
        recent_sessions.append({
            'id': sess['id'],
            'title': sess['title'],
            'subject': sess['subject'],
            'type': sess['session_type'],
            'date': session_date.strftime('%b %d, %Y'),
            'duration': 2
        })
    
    conn.close()
    
    return render_template('analytics.html',
                         total_hours=total_hours,
                         total_sessions=total_sessions,
                         favorite_subject=favorite_subject,
                         current_streak=current_streak,
                         subject_labels=subject_labels,
                         subject_counts=subject_counts,
                         sessions_dates=sessions_dates,
                         sessions_counts=sessions_counts,
                         day_of_week_hours=day_of_week_hours,
                         monthly_labels=monthly_labels,
                         monthly_sessions=monthly_sessions,
                         monthly_hours=monthly_hours,
                         recent_sessions=recent_sessions)

# ============================================
# CALENDAR INTEGRATION
# ============================================

@app.route('/session/<int:session_id>/calendar.ics')
@login_required
def export_to_calendar(session_id):
    """Export session to .ics calendar file"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get session details
    c.execute('SELECT * FROM sessions WHERE id = ?', (session_id,))
    sess = c.fetchone()
    
    if not sess:
        conn.close()
        flash('Session not found.')
        return redirect(url_for('index'))
    
    # Check if user is participant
    c.execute('SELECT * FROM rsvps WHERE session_id = ? AND user_id = ?', 
              (session_id, session['user_id']))
    rsvp = c.fetchone()
    
    if not rsvp and sess['creator_id'] != session['user_id']:
        conn.close()
        flash('You must be a participant to export this session.')
        return redirect(url_for('detail', session_id=session_id))
    
    # Get creator name
    c.execute('SELECT full_name FROM users WHERE id = ?', (sess['creator_id'],))
    creator = c.fetchone()
    conn.close()
    
    # Create calendar and event
    cal = Calendar()
    event = Event()
    
    # Parse session datetime
    session_datetime = datetime.strptime(sess['session_date'], '%Y-%m-%d %H:%M')
    
    # Set event details
    event.name = sess['title']
    event.begin = session_datetime
    event.duration = timedelta(hours=2)  # Default 2 hours
    
    # Build description
    description_parts = [
        f"Subject: {sess['subject']}",
        f"Type: {sess['session_type']}",
        f"Organized by: {creator['full_name']}"
    ]
    
    if sess['location']:
        description_parts.append(f"Location: {sess['location']}")
        event.location = sess['location']
    
    if sess['meeting_link']:
        description_parts.append(f"Meeting Link: {sess['meeting_link']}")
    
    event.description = "\n".join(description_parts)
    
    # Add event to calendar
    cal.events.add(event)
    
    # Create response with .ics file
    response = make_response(str(cal))
    response.headers['Content-Type'] = 'text/calendar; charset=utf-8'
    response.headers['Content-Disposition'] = f'attachment; filename="study_session_{session_id}.ics"'
    
    return response

# ============================================
# SEARCH FUNCTIONALITY
# ============================================

@app.route('/api/search')
@login_required
def search():
    """Global search across sessions, messages, notes, and files using FTS5"""
    query = request.args.get('q', '').strip()
    
    if not query or len(query) < 2:
        return jsonify({'results': []})
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    results = {
        'sessions': [],
        'messages': [],
        'notes': [],
        'files': []
    }
    
    # Search sessions
    try:
        c.execute('''
            SELECT s.*, u.full_name as creator_name, 
                   snippet(sessions_fts, 0, '<mark>', '</mark>', '...', 50) as title_snippet
            FROM sessions_fts
            JOIN sessions s ON sessions_fts.rowid = s.id
            JOIN users u ON s.creator_id = u.id
            WHERE sessions_fts MATCH ?
            ORDER BY rank
            LIMIT 10
        ''', (query,))
        
        for row in c.fetchall():
            results['sessions'].append({
                'id': row['id'],
                'title': row['title'],
                'title_snippet': row['title_snippet'],
                'subject': row['subject'],
                'session_date': row['session_date'],
                'creator_name': row['creator_name'],
                'type': 'session'
            })
    except sqlite3.OperationalError:
        pass  # FTS query syntax error, skip
    
    # Search messages (only in sessions user has access to)
    try:
        c.execute('''
            SELECT m.*, s.title as session_title, u.full_name as author_name,
                   snippet(messages_fts, 0, '<mark>', '</mark>', '...', 100) as message_snippet
            FROM messages_fts
            JOIN messages m ON messages_fts.rowid = m.id
            JOIN sessions s ON m.session_id = s.id
            JOIN users u ON m.user_id = u.id
            WHERE messages_fts MATCH ?
            AND (s.creator_id = ? OR m.session_id IN (
                SELECT session_id FROM rsvps WHERE user_id = ?
            ))
            ORDER BY rank
            LIMIT 10
        ''', (query, session['user_id'], session['user_id']))
        
        for row in c.fetchall():
            results['messages'].append({
                'id': row['id'],
                'session_id': row['session_id'],
                'session_title': row['session_title'],
                'author_name': row['author_name'],
                'message_snippet': row['message_snippet'],
                'created_at': row['created_at'],
                'type': 'message'
            })
    except sqlite3.OperationalError:
        pass
    
    # Search notes (only public notes or user's own notes)
    try:
        c.execute('''
            SELECT n.*, u.full_name as author_name,
                   snippet(notes_fts, 0, '<mark>', '</mark>', '...', 100) as title_snippet,
                   snippet(notes_fts, 1, '<mark>', '</mark>', '...', 150) as content_snippet
            FROM notes_fts
            JOIN notes n ON notes_fts.rowid = n.id
            JOIN users u ON n.user_id = u.id
            WHERE notes_fts MATCH ?
            AND (n.is_public = 1 OR n.user_id = ?)
            ORDER BY rank
            LIMIT 10
        ''', (query, session['user_id']))
        
        for row in c.fetchall():
            results['notes'].append({
                'id': row['id'],
                'title': row['title'],
                'title_snippet': row['title_snippet'],
                'content_snippet': row['content_snippet'],
                'author_name': row['author_name'],
                'subject': row['subject'],
                'is_public': row['is_public'],
                'type': 'note'
            })
    except sqlite3.OperationalError:
        pass
    
    # Search files (only in sessions user has access to)
    try:
        c.execute('''
            SELECT f.*, s.title as session_title, u.full_name as uploader_name,
                   snippet(files_fts, 0, '<mark>', '</mark>', '...', 50) as filename_snippet
            FROM files_fts
            JOIN files f ON files_fts.rowid = f.id
            JOIN sessions s ON f.session_id = s.id
            JOIN users u ON f.user_id = u.id
            WHERE files_fts MATCH ?
            AND (s.creator_id = ? OR f.session_id IN (
                SELECT session_id FROM rsvps WHERE user_id = ?
            ))
            ORDER BY rank
            LIMIT 10
        ''', (query, session['user_id'], session['user_id']))
        
        for row in c.fetchall():
            results['files'].append({
                'id': row['id'],
                'session_id': row['session_id'],
                'session_title': row['session_title'],
                'original_filename': row['original_filename'],
                'filename_snippet': row['filename_snippet'],
                'file_type': row['file_type'],
                'uploader_name': row['uploader_name'],
                'uploaded_at': row['uploaded_at'],
                'type': 'file'
            })
    except sqlite3.OperationalError:
        pass
    
    conn.close()
    
    # Calculate total results
    total = sum(len(results[key]) for key in results)
    
    return jsonify({
        'query': query,
        'total': total,
        'results': results
    })

# ============================================
# FLASHCARD SYSTEM
# ============================================

@app.route('/flashcards')
@login_required
def flashcards():
    """View all flashcard decks"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get user's decks and public decks
    c.execute('''
        SELECT d.*, u.full_name as creator_name,
               COUNT(DISTINCT f.id) as card_count,
               s.title as session_title
        FROM flashcard_decks d
        LEFT JOIN flashcards f ON d.id = f.deck_id
        LEFT JOIN users u ON d.user_id = u.id
        LEFT JOIN sessions s ON d.session_id = s.id
        WHERE d.user_id = ? OR d.is_public = 1
        GROUP BY d.id
        ORDER BY d.created_at DESC
    ''', (session['user_id'],))
    
    decks = c.fetchall()
    conn.close()
    
    return render_template('flashcards.html', decks=decks)

@app.route('/flashcards/deck/<int:deck_id>')
@login_required
def view_deck(deck_id):
    """View cards in a deck"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get deck info
    deck = c.execute('''
        SELECT d.*, u.full_name as creator_name, s.title as session_title
        FROM flashcard_decks d
        LEFT JOIN users u ON d.user_id = u.id
        LEFT JOIN sessions s ON d.session_id = s.id
        WHERE d.id = ? AND (d.user_id = ? OR d.is_public = 1)
    ''', (deck_id, session['user_id'])).fetchone()
    
    if not deck:
        flash('Deck not found or access denied')
        return redirect(url_for('flashcards'))
    
    # Get all cards
    cards = c.execute('''
        SELECT * FROM flashcards
        WHERE deck_id = ?
        ORDER BY id
    ''', (deck_id,)).fetchall()
    
    conn.close()
    
    return render_template('deck_view.html', deck=deck, cards=cards)

@app.route('/flashcards/create', methods=['GET', 'POST'])
@login_required
def create_deck():
    """Create a new flashcard deck"""
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        session_id = request.form.get('session_id')
        is_public = 1 if request.form.get('is_public') else 0
        
        if not title:
            flash('Deck title is required')
            return redirect(url_for('create_deck'))
        
        conn = get_db()
        
        # Verify session exists if provided
        if session_id:
            session_check = conn.execute('SELECT id FROM sessions WHERE id = ?', (session_id,)).fetchone()
            if not session_check:
                session_id = None
        
        conn.execute('''
            INSERT INTO flashcard_decks (title, description, session_id, user_id, is_public)
            VALUES (?, ?, ?, ?, ?)
        ''', (title, description, session_id, session['user_id'], is_public))
        
        deck_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.commit()
        conn.close()
        
        flash('Deck created successfully!')
        return redirect(url_for('view_deck', deck_id=deck_id))
    
    # GET - show form
    conn = get_db()
    sessions_list = conn.execute('''
        SELECT s.id, s.title, s.subject
        FROM sessions s
        WHERE s.creator_id = ? OR s.id IN (
            SELECT session_id FROM rsvps WHERE user_id = ?
        )
        ORDER BY s.session_date DESC
    ''', (session['user_id'], session['user_id'])).fetchall()
    conn.close()
    
    return render_template('create_deck.html', sessions=sessions_list)

@app.route('/flashcards/deck/<int:deck_id>/add-card', methods=['POST'])
@login_required
def add_card(deck_id):
    """Add a card to a deck"""
    conn = get_db()
    
    # Verify deck ownership
    deck = conn.execute('SELECT user_id FROM flashcard_decks WHERE id = ?', (deck_id,)).fetchone()
    if not deck or deck['user_id'] != session['user_id']:
        conn.close()
        flash('Access denied')
        return redirect(url_for('flashcards'))
    
    question = request.form.get('question', '').strip()
    answer = request.form.get('answer', '').strip()
    
    if not question or not answer:
        conn.close()
        flash('Question and answer are required')
        return redirect(url_for('view_deck', deck_id=deck_id))
    
    conn.execute('''
        INSERT INTO flashcards (deck_id, question, answer)
        VALUES (?, ?, ?)
    ''', (deck_id, question, answer))
    
    conn.commit()
    conn.close()
    
    flash('Card added successfully!')
    return redirect(url_for('view_deck', deck_id=deck_id))

@app.route('/flashcards/deck/<int:deck_id>/study')
@login_required
def study_deck(deck_id):
    """Study mode - spaced repetition"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get deck info
    deck_row = c.execute('''
        SELECT d.*, u.full_name as creator_name
        FROM flashcard_decks d
        LEFT JOIN users u ON d.user_id = u.id
        WHERE d.id = ? AND (d.user_id = ? OR d.is_public = 1)
    ''', (deck_id, session['user_id'])).fetchone()
    
    if not deck_row:
        flash('Deck not found or access denied')
        return redirect(url_for('flashcards'))
    
    # Convert deck Row to dict
    deck = dict(deck_row)
    
    # Get cards due for review (SM-2 algorithm)
    cards_rows = c.execute('''
        SELECT f.*, p.easiness_factor, p.interval, p.repetitions, p.next_review_date
        FROM flashcards f
        LEFT JOIN flashcard_progress p ON f.id = p.flashcard_id AND p.user_id = ?
        WHERE f.deck_id = ?
        AND (p.next_review_date IS NULL OR p.next_review_date <= datetime('now'))
        ORDER BY p.next_review_date ASC
    ''', (session['user_id'], deck_id)).fetchall()
    
    # Convert cards Rows to list of dicts
    cards = [dict(row) for row in cards_rows]
    
    conn.close()
    
    return render_template('study_mode.html', deck=deck, cards=cards)

@app.route('/api/flashcards/review', methods=['POST'])
@login_required
def review_card():
    """Record a card review and update SM-2 algorithm"""
    data = request.get_json()
    card_id = data.get('card_id')
    quality = int(data.get('quality', 0))  # 0-5 rating
    
    if not card_id or quality < 0 or quality > 5:
        return jsonify({'error': 'Invalid data'}), 400
    
    conn = get_db()
    
    # Get current progress
    progress = conn.execute('''
        SELECT * FROM flashcard_progress
        WHERE flashcard_id = ? AND user_id = ?
    ''', (card_id, session['user_id'])).fetchone()
    
    # SM-2 algorithm calculations
    if progress:
        ef = progress['easiness_factor']
        interval = progress['interval']
        repetitions = progress['repetitions']
    else:
        ef = 2.5
        interval = 0
        repetitions = 0
    
    # Update easiness factor
    ef = ef + (0.1 - (5 - quality) * (0.08 + (5 - quality) * 0.02))
    if ef < 1.3:
        ef = 1.3
    
    # Update interval and repetitions
    if quality < 3:
        repetitions = 0
        interval = 0
    else:
        if repetitions == 0:
            interval = 1
        elif repetitions == 1:
            interval = 6
        else:
            interval = int(interval * ef)
        repetitions += 1
    
    # Calculate next review date
    next_review = datetime.now() + timedelta(days=interval)
    
    # Update or insert progress
    if progress:
        conn.execute('''
            UPDATE flashcard_progress
            SET easiness_factor = ?, interval = ?, repetitions = ?,
                next_review_date = ?, last_reviewed = datetime('now')
            WHERE flashcard_id = ? AND user_id = ?
        ''', (ef, interval, repetitions, next_review, card_id, session['user_id']))
    else:
        conn.execute('''
            INSERT INTO flashcard_progress
            (flashcard_id, user_id, easiness_factor, interval, repetitions, next_review_date, last_reviewed)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        ''', (card_id, session['user_id'], ef, interval, repetitions, next_review))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'next_review': next_review.isoformat(),
        'interval_days': interval
    })

# ============================================
# USER PROFILES & SETTINGS
# ============================================

# ============================================
# USER PROFILE ROUTES
# ============================================

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    """View a user's profile with stats and recent activity.
    
    Shows public information and statistics for any user.
    Shows additional private information when viewing own profile.
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get user info
    user = c.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        flash('User not found')
        return redirect(url_for('index'))
    
    # Get user stats
    stats = c.execute('SELECT * FROM user_stats WHERE user_id = ?', (user_id,)).fetchone()
    
    # Get recent sessions created
    recent_sessions = c.execute('''
        SELECT * FROM sessions
        WHERE creator_id = ?
        ORDER BY created_at DESC
        LIMIT 5
    ''', (user_id,)).fetchall()
    
    # Get recent notes
    recent_notes = c.execute('''
        SELECT * FROM notes
        WHERE user_id = ? AND is_public = 1
        ORDER BY created_at DESC
        LIMIT 5
    ''', (user_id,)).fetchall()
    
    conn.close()
    
    is_own_profile = (user_id == session['user_id'])
    
    return render_template('profile.html', 
                         user=user, 
                         stats=stats,
                         recent_sessions=recent_sessions,
                         recent_notes=recent_notes,
                         is_own_profile=is_own_profile)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile"""
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        bio = request.form.get('bio', '').strip()
        
        if not full_name:
            flash('Full name is required')
            return redirect(url_for('edit_profile'))
        
        conn = get_db()
        
        # Handle avatar upload
        avatar_filename = None
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename and allowed_file(file.filename):
                # Create avatars directory
                avatar_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars')
                if not os.path.exists(avatar_dir):
                    os.makedirs(avatar_dir)
                
                # Generate unique filename
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                avatar_filename = f"avatar_{session['user_id']}_{timestamp}_{filename}"
                filepath = os.path.join(avatar_dir, avatar_filename)
                
                # Delete old avatar if exists
                old_user = conn.execute('SELECT avatar_filename FROM users WHERE id = ?', 
                                       (session['user_id'],)).fetchone()
                if old_user and old_user['avatar_filename']:
                    old_path = os.path.join(avatar_dir, old_user['avatar_filename'])
                    if os.path.exists(old_path):
                        os.remove(old_path)
                
                file.save(filepath)
                
                # Update with avatar
                conn.execute('''
                    UPDATE users 
                    SET full_name = ?, bio = ?, avatar_filename = ?
                    WHERE id = ?
                ''', (full_name, bio, avatar_filename, session['user_id']))
            else:
                # Update without avatar
                conn.execute('''
                    UPDATE users 
                    SET full_name = ?, bio = ?
                    WHERE id = ?
                ''', (full_name, bio, session['user_id']))
        else:
            # Update without avatar
            conn.execute('''
                UPDATE users 
                SET full_name = ?, bio = ?
                WHERE id = ?
            ''', (full_name, bio, session['user_id']))
        
        # Update session name
        session['full_name'] = full_name
        
        conn.commit()
        conn.close()
        
        flash('Profile updated successfully!')
        return redirect(url_for('profile', user_id=session['user_id']))
    
    # GET - show form
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('edit_profile.html', user=user)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings page"""
    if request.method == 'POST':
        conn = get_db()
        
        # Update settings
        email_notifications = 1 if request.form.get('email_notifications') else 0
        push_notifications = 1 if request.form.get('push_notifications') else 0
        session_reminders = 1 if request.form.get('session_reminders') else 0
        message_notifications = 1 if request.form.get('message_notifications') else 0
        reminder_timing = int(request.form.get('reminder_timing', 1))
        notification_sound = request.form.get('notification_sound', 'default')
        theme = request.form.get('theme', 'dark')
        preferred_language = request.form.get('preferred_language', 'en')
        auto_translate = 1 if request.form.get('auto_translate') else 0
        
        # Check if settings exist
        existing = conn.execute('SELECT id FROM user_settings WHERE user_id = ?', 
                               (session['user_id'],)).fetchone()
        
        if existing:
            conn.execute('''
                UPDATE user_settings
                SET email_notifications = ?,
                    push_notifications = ?,
                    session_reminders = ?,
                    message_notifications = ?,
                    reminder_timing = ?,
                    notification_sound = ?,
                    theme = ?,
                    preferred_language = ?,
                    auto_translate = ?
                WHERE user_id = ?
            ''', (email_notifications, push_notifications, session_reminders, 
                  message_notifications, reminder_timing, notification_sound,
                  theme, preferred_language, auto_translate, session['user_id']))
        else:
            conn.execute('''
                INSERT INTO user_settings (user_id, email_notifications, push_notifications,
                                          session_reminders, message_notifications,
                                          reminder_timing, notification_sound, theme,
                                          preferred_language, auto_translate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (session['user_id'], email_notifications, push_notifications,
                  session_reminders, message_notifications, reminder_timing,
                  notification_sound, theme, preferred_language, auto_translate))
        
        conn.commit()
        conn.close()
        
        flash('Settings saved successfully!')
        return redirect(url_for('settings'))
    
    # GET - show settings
    conn = get_db()
    user_settings = conn.execute('''
        SELECT * FROM user_settings WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Create default settings if they don't exist
    if not user_settings:
        conn.execute('''
            INSERT INTO user_settings (user_id, email_notifications, session_reminders, 
                                      message_notifications, theme, preferred_language, auto_translate)
            VALUES (?, 1, 1, 1, 'dark', 'en', 0)
        ''', (session['user_id'],))
        conn.commit()
        
        user_settings = conn.execute('''
            SELECT * FROM user_settings WHERE user_id = ?
        ''', (session['user_id'],)).fetchone()
    
    conn.close()
    
    return render_template('settings.html', settings=user_settings)

@app.route('/api/settings/theme', methods=['POST'])
@login_required
def update_theme():
    """Update user's theme preference"""
    data = request.get_json()
    theme = data.get('theme', 'dark')
    
    conn = get_db()
    conn.execute('''
        UPDATE user_settings SET theme = ? WHERE user_id = ?
    ''', (theme, session['user_id']))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'theme': theme})

@app.route('/api/push/subscribe', methods=['POST'])
@login_required
def subscribe_push():
    """Subscribe to push notifications"""
    subscription_data = request.json
    
    conn = get_db()
    
    # Store subscription in database
    conn.execute('''
        INSERT OR REPLACE INTO push_subscriptions 
        (user_id, endpoint, p256dh_key, auth_key)
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], 
          subscription_data.get('endpoint'),
          subscription_data.get('keys', {}).get('p256dh'),
          subscription_data.get('keys', {}).get('auth')))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/push/unsubscribe', methods=['POST'])
@login_required
def unsubscribe_push():
    """Unsubscribe from push notifications"""
    conn = get_db()
    
    conn.execute('''
        DELETE FROM push_subscriptions WHERE user_id = ?
    ''', (session['user_id'],))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/push/vapid-public-key')
def get_vapid_public_key():
    """Get VAPID public key for push notifications"""
    # This would be your actual VAPID public key
    # Generate with: python -c "from py_vapid import Vapid; v = Vapid(); v.generate_keys(); print(v.public_key)"
    return jsonify({
        'publicKey': app.config.get('VAPID_PUBLIC_KEY', '')
    })

# ============================================
# TRANSLATION API ROUTES
# ============================================

@app.route('/api/translate', methods=['POST'])
@login_required
def api_translate():
    """Translate text to user's preferred language"""
    data = request.json
    text = data.get('text', '')
    target_lang = data.get('target_lang')
    
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    
    # Get user's preferred language if not specified
    if not target_lang:
        target_lang, _ = get_user_language_preference(session['user_id'])
    
    # Detect source language
    detected_lang = detect_language(text)
    
    # Translate text
    translated = translate_text(text, target_lang=target_lang)
    
    return jsonify({
        'original': text,
        'translated': translated,
        'source_lang': detected_lang,
        'target_lang': target_lang
    })

@app.route('/api/detect-language', methods=['POST'])
@login_required
def api_detect_language():
    """Detect the language of a text"""
    data = request.json
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'No text provided'}), 400
    
    detected = detect_language(text)
    
    return jsonify({
        'text': text,
        'language': detected
    })

@app.route('/uploads/avatars/<filename>')
def serve_avatar(filename):
    """Serve avatar images"""
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], 'avatars'), filename)

# ============================================
# SESSION RECORDINGS ROUTES
# ============================================

@app.route('/session/<int:session_id>/upload-recording', methods=['POST'])
@login_required
def upload_recording(session_id):
    """Upload an audio or video recording of a study session.
    
    Supported formats: mp3, wav, ogg, webm, mp4, avi, mov, m4a
    Only session participants can upload recordings.
    Optional: include transcription and duration metadata.
    """
    conn = get_db()
    
    # Verify user is a session participant
    rsvp = conn.execute(
        'SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
        (session_id, session['user_id'])
    ).fetchone()
    
    if not rsvp:
        conn.close()
        flash('You must be a participant to upload recordings')
        return redirect(url_for('detail', session_id=session_id))
    
    if 'recording' not in request.files:
        conn.close()
        flash('No recording file selected')
        return redirect(url_for('detail', session_id=session_id))
    
    file = request.files['recording']
    
    if file.filename == '':
        conn.close()
        flash('No recording file selected')
        return redirect(url_for('detail', session_id=session_id))
    
    # Get file extension and validate
    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    allowed_extensions = {'mp3', 'wav', 'ogg', 'webm', 'mp4', 'avi', 'mov', 'm4a'}
    
    if file_ext not in allowed_extensions:
        conn.close()
        flash('Invalid file type. Allowed: mp3, wav, ogg, webm, mp4, avi, mov, m4a')
        return redirect(url_for('detail', session_id=session_id))
    
    # Generate unique filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_filename = f"{timestamp}_{file.filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    
    # Save file
    file.save(filepath)
    file_size = os.path.getsize(filepath)
    
    # Get optional transcription and duration from form
    transcription = request.form.get('transcription', '')
    duration = request.form.get('duration', None)
    recording_type = 'video' if file_ext in {'mp4', 'avi', 'mov', 'webm'} else 'audio'
    
    # Save to database
    conn.execute('''
        INSERT INTO session_recordings 
        (session_id, user_id, filename, original_filename, file_size, duration, transcription, recording_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (session_id, session['user_id'], safe_filename, file.filename, file_size, 
          duration, transcription, recording_type))
    
    conn.commit()
    conn.close()
    
    flash(f'{recording_type.capitalize()} recording uploaded successfully!')
    return redirect(url_for('detail', session_id=session_id))

@app.route('/recording/<int:recording_id>/download')
@login_required
def download_recording(recording_id):
    """Download a session recording"""
    conn = get_db()
    recording = conn.execute('''
        SELECT r.*, s.id as session_id
        FROM session_recordings r
        JOIN sessions s ON r.session_id = s.id
        WHERE r.id = ?
    ''', (recording_id,)).fetchone()
    
    if not recording:
        conn.close()
        flash('Recording not found')
        return redirect(url_for('index'))
    
    # Verify user is participant
    rsvp = conn.execute('SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
                       (recording['session_id'], session['user_id'])).fetchone()
    
    conn.close()
    
    if not rsvp:
        flash('You must be a participant to access recordings')
        return redirect(url_for('detail', session_id=recording['session_id']))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], recording['filename'],
                              as_attachment=True, download_name=recording['original_filename'])

@app.route('/recording/<int:recording_id>/delete', methods=['POST'])
@login_required
def delete_recording(recording_id):
    """Delete a session recording"""
    conn = get_db()
    recording = conn.execute('SELECT * FROM session_recordings WHERE id = ?', (recording_id,)).fetchone()
    
    if not recording:
        conn.close()
        flash('Recording not found')
        return redirect(url_for('index'))
    
    session_id = recording['session_id']
    
    # Only uploader or session creator can delete
    study_session = conn.execute('SELECT creator_id FROM sessions WHERE id = ?', (session_id,)).fetchone()
    
    if recording['user_id'] == session['user_id'] or study_session['creator_id'] == session['user_id']:
        # Remove from disk
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], recording['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Remove from database
        conn.execute('DELETE FROM session_recordings WHERE id = ?', (recording_id,))
        conn.commit()
        flash('Recording deleted successfully')
    else:
        flash('You can only delete your own recordings')
    
    conn.close()
    return redirect(url_for('detail', session_id=session_id))

@app.route('/recording/<int:recording_id>/transcription', methods=['POST'])
@login_required
def update_transcription(recording_id):
    """Update or add transcription to a recording"""
    conn = get_db()
    recording = conn.execute('SELECT * FROM session_recordings WHERE id = ?', (recording_id,)).fetchone()
    
    if not recording:
        conn.close()
        return jsonify({'error': 'Recording not found'}), 404
    
    # Verify user is uploader or session creator
    study_session = conn.execute('SELECT creator_id FROM sessions WHERE id = ?',
                                 (recording['session_id'],)).fetchone()
    
    if recording['user_id'] != session['user_id'] and study_session['creator_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403
    
    transcription = request.json.get('transcription', '')
    
    conn.execute('UPDATE session_recordings SET transcription = ? WHERE id = ?',
                (transcription, recording_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'transcription': transcription})

# ============================================
# INVITATION RESPONSE ROUTE
# ============================================

@app.route('/invitation/<int:invitation_id>/respond', methods=['POST'])
@login_required
def respond_invitation(invitation_id):
    """Accept or decline a session invitation.
    
    When accepting:
    - Verifies session has capacity
    - Creates RSVP automatically
    - Marks invitation as accepted
    
    When declining:
    - Simply marks invitation as declined
    """
    response = request.form.get('response')  # 'accept' or 'decline'
    
    conn = get_db()
    invitation = conn.execute('''
        SELECT i.*, s.max_participants
        FROM invitations i
        JOIN sessions s ON i.session_id = s.id
        WHERE i.id = ? AND i.invitee_id = ?
    ''', (invitation_id, session['user_id'])).fetchone()
    
    if invitation:
        if response == 'accept':
            # verify session isn't full before accepting
            current_count = conn.execute('SELECT COUNT(*) as count FROM rsvps WHERE session_id = ?',
                                        (invitation['session_id'],)).fetchone()['count']
            
            if current_count >= invitation['max_participants']:
                flash('Sorry, this session is now full!')
                conn.execute('UPDATE invitations SET status = ? WHERE id = ?', ('declined', invitation_id))
            else:
                # add RSVP and mark invitation accepted
                try:
                    conn.execute('INSERT INTO rsvps (session_id, user_id) VALUES (?, ?)',
                               (invitation['session_id'], session['user_id']))
                    conn.execute('UPDATE invitations SET status = ? WHERE id = ?', ('accepted', invitation_id))
                    flash('Invitation accepted! You have been added to the session.')
                except sqlite3.IntegrityError:
                    flash('You have already RSVP\'d to this session!')
        else:
            conn.execute('UPDATE invitations SET status = ? WHERE id = ?', ('declined', invitation_id))
            flash('Invitation declined.')
        
        conn.commit()
    
    conn.close()
    return redirect(url_for('index'))

# ============================================
# BACKGROUND TASK - AUTOMATIC REMINDERS
# ============================================

def check_and_send_reminders():
    """Background task to send automatic reminders for upcoming sessions.
    
    Sends reminders at three intervals:
    - 1 week before session
    - 1 day before session  
    - 1 hour before session
    
    Tracks sent reminders to prevent duplicates.
    Called periodically by background scheduler.
    """
    conn = get_db()
    now = datetime.now()
    
    # Get all future sessions that haven't occurred yet
    sessions = conn.execute('''
        SELECT id, title, session_date, creator_id
        FROM sessions
        WHERE session_date > ?
    ''', (now.isoformat(),)).fetchall()
    
    for sess in sessions:
        if not sess['session_date']:
            continue
        
        try:
            session_date = datetime.fromisoformat(sess['session_date'].replace('T', ' '))
        except:
            continue
        
        time_until = session_date - now
        
        # determine which reminder to send based on time remaining
        reminder_type = None
        reminder_text = None
        
        # 1 week reminder (between 7 days and 6 days 23 hours)
        if timedelta(days=6, hours=23) <= time_until <= timedelta(days=7, hours=1):
            reminder_type = 'week'
            reminder_text = f'1 week until "{sess["title"]}" starts!'
        # 1 day reminder (between 23 hours and 25 hours)
        elif timedelta(hours=23) <= time_until <= timedelta(hours=25):
            reminder_type = 'day'
            reminder_text = f'1 day until "{sess["title"]}" starts!'
        # 1 hour reminder (between 59 minutes and 61 minutes)
        elif timedelta(minutes=59) <= time_until <= timedelta(minutes=61):
            reminder_type = 'hour'
            reminder_text = f'1 hour until "{sess["title"]}" starts!'
        
        if reminder_type and reminder_text:
            # check if this reminder type has already been sent for this session
            already_sent = conn.execute('''
                SELECT id FROM auto_reminders_sent 
                WHERE session_id = ? AND reminder_type = ?
            ''', (sess['id'], reminder_type)).fetchone()
            
            if not already_sent:
                # create the reminder
                conn.execute('''
                    INSERT INTO reminders (session_id, reminder_text, sent_by)
                    VALUES (?, ?, ?)
                ''', (sess['id'], reminder_text, sess['creator_id']))
                
                # mark this reminder type as sent
                conn.execute('''
                    INSERT INTO auto_reminders_sent (session_id, reminder_type)
                    VALUES (?, ?)
                ''', (sess['id'], reminder_type))
                
                conn.commit()
    
    conn.close()

# ============================================
# COLLABORATIVE NOTES ROUTES
# ============================================

@app.route('/notes')
def notes():
    """Browse and search notes.
    
    Supports filtering by:
    - Search query (title, description, content)
    - Subject
    - View (all, my_notes, public)
    """
    conn = get_db()
    
    # get search and filter params
    search_query = request.args.get('search', '').strip()
    subject_filter = request.args.get('subject', '').strip()
    view_filter = request.args.get('view', 'all').strip()  # all, my_notes, public
    
    # Build query based on active filters
    query = '''
        SELECT n.*, u.full_name as author_name, u.username as author_username,
               (SELECT COUNT(*) FROM note_comments WHERE note_id = n.id) as comment_count
        FROM notes n
        JOIN users u ON n.user_id = u.id
        WHERE 1=1
    '''
    params = []
    
    # Apply view filter (my notes, public only, or all accessible)
    if 'user_id' in session:
        if view_filter == 'my_notes':
            query += ' AND n.user_id = ?'
            params.append(session['user_id'])
        elif view_filter == 'public':
            query += ' AND n.is_public = 1'
        else:  # all
            query += ' AND (n.is_public = 1 OR n.user_id = ?)'
            params.append(session['user_id'])
    else:
        # Not logged in: show only public notes
        query += ' AND n.is_public = 1'
    
    # Apply search filter
    if search_query:
        query += ' AND (n.title LIKE ? OR n.description LIKE ? OR n.content LIKE ?)'
        params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])
    
    # Apply subject filter
    if subject_filter:
        query += ' AND n.subject = ?'
        params.append(subject_filter)
    
    query += ' ORDER BY n.created_at DESC'
    
    notes_list = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('notes.html', notes=notes_list, view_filter=view_filter)

@app.route('/notes/create', methods=['GET', 'POST'])
@login_required
def create_note():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        content = request.form['content']
        subject = request.form.get('subject', 'General')
        is_public = 1 if request.form.get('is_public') == 'on' else 0
        
        conn = get_db()
        cursor = conn.execute('''
            INSERT INTO notes (user_id, title, description, content, subject, is_public)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], title, description, content, subject, is_public))
        note_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        flash('Note created successfully!')
        return redirect(url_for('view_note', note_id=note_id))
    
    return render_template('create_note.html')

@app.route('/notes/<int:note_id>')
def view_note(note_id):
    conn = get_db()
    
    # get note details
    note = conn.execute('''
        SELECT n.*, u.full_name as author_name, u.username as author_username, u.id as author_id
        FROM notes n
        JOIN users u ON n.user_id = u.id
        WHERE n.id = ?
    ''', (note_id,)).fetchone()
    
    if not note:
        conn.close()
        flash('Note not found!')
        return redirect(url_for('notes'))
    
    # check if user can view this note
    if not note['is_public'] and ('user_id' not in session or note['user_id'] != session['user_id']):
        conn.close()
        flash('This note is private!')
        return redirect(url_for('notes'))
    
    # get comments
    comments = conn.execute('''
        SELECT c.*, u.full_name, u.username
        FROM note_comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.note_id = ?
        ORDER BY c.created_at ASC
    ''', (note_id,)).fetchall()
    
    # get attached files
    files = conn.execute('''
        SELECT nf.*, u.full_name, u.username
        FROM note_files nf
        JOIN users u ON nf.user_id = u.id
        WHERE nf.note_id = ?
        ORDER BY nf.uploaded_at DESC
    ''', (note_id,)).fetchall()
    
    conn.close()
    
    is_author = 'user_id' in session and note['user_id'] == session['user_id']
    
    return render_template('view_note.html', note=note, comments=comments, files=files, is_author=is_author)

@app.route('/notes/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    conn = get_db()
    note = conn.execute('SELECT * FROM notes WHERE id = ?', (note_id,)).fetchone()
    
    if not note:
        conn.close()
        flash('Note not found!')
        return redirect(url_for('notes'))
    
    if note['user_id'] != session['user_id']:
        conn.close()
        flash('You can only edit your own notes!')
        return redirect(url_for('view_note', note_id=note_id))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        content = request.form['content']
        subject = request.form.get('subject', 'General')
        is_public = 1 if request.form.get('is_public') == 'on' else 0
        
        conn.execute('''
            UPDATE notes 
            SET title = ?, description = ?, content = ?, subject = ?, is_public = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (title, description, content, subject, is_public, note_id))
        conn.commit()
        conn.close()
        
        flash('Note updated successfully!')
        return redirect(url_for('view_note', note_id=note_id))
    
    conn.close()
    return render_template('edit_note.html', note=note)

@app.route('/notes/<int:note_id>/autosave', methods=['POST'])
@login_required
def autosave_note(note_id):
    """Auto-save note content during editing"""
    conn = get_db()
    note = conn.execute('SELECT user_id FROM notes WHERE id = ?', (note_id,)).fetchone()
    
    if not note or note['user_id'] != session['user_id']:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    content = data.get('content', '')
    title = data.get('title', '')
    
    conn.execute('''
        UPDATE notes 
        SET content = ?, title = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (content, title, note_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'timestamp': datetime.now().isoformat()})

@app.route('/notes/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    conn = get_db()
    note = conn.execute('SELECT user_id FROM notes WHERE id = ?', (note_id,)).fetchone()
    
    if note and note['user_id'] == session['user_id']:
        # delete attached files from disk
        files = conn.execute('SELECT filename FROM note_files WHERE note_id = ?', (note_id,)).fetchall()
        for file_record in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['filename'])
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # delete related records
        conn.execute('DELETE FROM note_files WHERE note_id = ?', (note_id,))
        conn.execute('DELETE FROM note_comments WHERE note_id = ?', (note_id,))
        conn.execute('DELETE FROM notes WHERE id = ?', (note_id,))
        conn.commit()
        flash('Note deleted successfully!')
    else:
        flash('You can only delete your own notes!')
    
    conn.close()
    return redirect(url_for('notes'))

@app.route('/notes/<int:note_id>/comment', methods=['POST'])
@login_required
def add_note_comment(note_id):
    comment_text = request.form.get('comment_text', '').strip()
    
    if comment_text:
        conn = get_db()
        note = conn.execute('SELECT id, is_public FROM notes WHERE id = ?', (note_id,)).fetchone()
        
        if note:
            conn.execute('INSERT INTO note_comments (note_id, user_id, comment_text) VALUES (?, ?, ?)',
                       (note_id, session['user_id'], comment_text))
            conn.commit()
            flash('Comment added!')
        
        conn.close()
    
    return redirect(url_for('view_note', note_id=note_id))

@app.route('/notes/<int:note_id>/upload', methods=['POST'])
@login_required
def upload_note_file(note_id):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', '')
    
    if 'file' not in request.files:
        if is_ajax:
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        flash('No file selected')
        return redirect(url_for('view_note', note_id=note_id))
    
    file = request.files['file']
    
    if file.filename == '':
        if is_ajax:
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        flash('No file selected')
        return redirect(url_for('view_note', note_id=note_id))
    
    conn = get_db()
    note = conn.execute('SELECT user_id FROM notes WHERE id = ?', (note_id,)).fetchone()
    
    if not note or note['user_id'] != session['user_id']:
        error_msg = 'You can only upload files to your own notes'
        conn.close()
        if is_ajax:
            return jsonify({'success': False, 'error': error_msg}), 403
        flash(error_msg)
        return redirect(url_for('view_note', note_id=note_id))
    
    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"note_{timestamp}_{original_filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(file_path)
        
        file_size = os.path.getsize(file_path)
        file_type = original_filename.rsplit('.', 1)[1].lower()
        
        conn.execute('''
            INSERT INTO note_files (note_id, user_id, filename, original_filename, file_size, file_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (note_id, session['user_id'], filename, original_filename, file_size, file_type))
        conn.commit()
        conn.close()
        
        if is_ajax:
            return jsonify({'success': True, 'message': f'File "{original_filename}" uploaded successfully!'}), 200
        flash(f'File "{original_filename}" uploaded successfully!')
    else:
        error_msg = 'Invalid file type'
        conn.close()
        if is_ajax:
            return jsonify({'success': False, 'error': error_msg}), 400
        flash(error_msg)
    
    return redirect(url_for('view_note', note_id=note_id))

@app.route('/notes/file/<int:file_id>/download')
@login_required
def download_note_file(file_id):
    conn = get_db()
    file_record = conn.execute('''
        SELECT nf.*, n.is_public, n.user_id as note_owner
        FROM note_files nf
        JOIN notes n ON nf.note_id = n.id
        WHERE nf.id = ?
    ''', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        flash('File not found')
        return redirect(url_for('notes'))
    
    # can download if note is public or user is the owner
    if not file_record['is_public'] and file_record['note_owner'] != session['user_id']:
        conn.close()
        flash('You cannot download files from private notes')
        return redirect(url_for('notes'))
    
    conn.close()
    return send_from_directory(app.config['UPLOAD_FOLDER'], file_record['filename'],
                              as_attachment=True, download_name=file_record['original_filename'])

@app.route('/notes/file/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_note_file(file_id):
    conn = get_db()
    file_record = conn.execute('''
        SELECT nf.*, n.user_id as note_owner
        FROM note_files nf
        JOIN notes n ON nf.note_id = n.id
        WHERE nf.id = ?
    ''', (file_id,)).fetchone()
    
    if not file_record:
        conn.close()
        flash('File not found')
        return redirect(url_for('notes'))
    
    note_id = file_record['note_id']
    
    if file_record['note_owner'] == session['user_id']:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
        
        conn.execute('DELETE FROM note_files WHERE id = ?', (file_id,))
        conn.commit()
        flash('File deleted successfully')
    else:
        flash('You can only delete files from your own notes')
    
    conn.close()
    return redirect(url_for('view_note', note_id=note_id))

# ============================================
# AI ASSISTANT ROUTES
# ============================================

@app.route('/api/ai-assist', methods=['POST'])
@login_required
def ai_assist():
    """AI assistant endpoint for various study-related tasks
    
    Handles:
    - Generate quiz questions from content
    - Summarize documents
    - Explain complex topics
    - Create study guides
    - Answer questions about content
    """
    if not openai_client:
        return jsonify({
            'success': False,
            'error': 'AI Assistant is not enabled. Please configure OPENAI_API_KEY.'
        }), 503
    
    data = request.json
    action = data.get('action')
    content = data.get('content', '')
    question = data.get('question', '')
    
    if not action:
        return jsonify({'success': False, 'error': 'Action is required'}), 400
    
    try:
        # Prepare system prompts based on action
        system_prompts = {
            'quiz': "You are a helpful study assistant. Generate quiz questions based on the provided content. Create 5 multiple-choice questions with 4 options each, and include the correct answers. Format the output clearly with question numbers.",
            'summarize': "You are a helpful study assistant. Provide a clear, concise summary of the provided content. Focus on key points, main ideas, and important concepts. Use bullet points where appropriate.",
            'explain': "You are a helpful study assistant. Explain the following topic or question in simple, easy-to-understand terms. Break down complex concepts and provide examples where helpful.",
            'study_guide': "You are a helpful study assistant. Create a comprehensive study guide from the provided content. Include: key concepts, definitions, important points to remember, and suggested review questions. Use clear formatting with headers and bullet points.",
            'answer': "You are a helpful study assistant. Answer the question based on the provided content. Be clear, accurate, and concise. If the content doesn't contain enough information to answer, state that clearly."
        }
        
        system_prompt = system_prompts.get(action, system_prompts['explain'])
        
        # Build user message
        if action == 'answer':
            user_message = f"Question: {question}\n\nContent:\n{content}"
        else:
            user_message = content
        
        # Call OpenAI API
        response = openai_client.chat.completions.create(
            model=Config.AI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            max_tokens=Config.AI_MAX_TOKENS,
            temperature=0.7
        )
        
        ai_response = response.choices[0].message.content
        
        # Log usage for tracking
        tokens_used = response.usage.total_tokens
        print(f"AI Assistant used {tokens_used} tokens for action: {action}")
        
        return jsonify({
            'success': True,
            'response': ai_response,
            'tokens_used': tokens_used
        })
        
    except Exception as e:
        print(f"AI Assistant error: {e}")
        return jsonify({
            'success': False,
            'error': f'AI request failed: {str(e)}'
        }), 500

@app.route('/api/ai-chat', methods=['POST'])
@login_required
def ai_chat():
    """Interactive AI chat for study assistance
    
    Maintains conversation context for follow-up questions
    """
    if not openai_client:
        return jsonify({
            'success': False,
            'error': 'AI Assistant is not enabled.'
        }), 503
    
    data = request.json
    messages = data.get('messages', [])
    context = data.get('context', '')  # Optional: note content for context
    
    if not messages:
        return jsonify({'success': False, 'error': 'Messages are required'}), 400
    
    try:
        # Add system message with context if provided
        api_messages = [
            {"role": "system", "content": f"You are a helpful study assistant. Help the user understand and learn from their study materials. {'Context: ' + context if context else 'Answer questions clearly and concisely.'}"}
        ]
        
        # Add conversation history
        api_messages.extend(messages)
        
        # Call OpenAI API
        response = openai_client.chat.completions.create(
            model=Config.AI_MODEL,
            messages=api_messages,
            max_tokens=Config.AI_MAX_TOKENS,
            temperature=0.7
        )
        
        ai_response = response.choices[0].message.content
        tokens_used = response.usage.total_tokens
        
        return jsonify({
            'success': True,
            'response': ai_response,
            'tokens_used': tokens_used
        })
        
    except Exception as e:
        print(f"AI Chat error: {e}")
        return jsonify({
            'success': False,
            'error': f'AI chat failed: {str(e)}'
        }), 500

# set up background scheduler to run every 30 minutes
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_and_send_reminders, trigger="interval", minutes=30)
scheduler.start()

# Shut down scheduler gracefully when app exits
atexit.register(lambda: scheduler.shutdown())

# ============================================
# WEBSOCKET EVENT HANDLERS
# ============================================

@socketio.on('join_session')
def handle_join_session(data):
    """Handle user joining a session room for real-time chat and updates."""
    session_id = data.get('session_id')
    user_id = data.get('user_id')
    user_name = data.get('user_name')
    
    if session_id:
        room = f'session_{session_id}'
        join_room(room)
        print(f"User {user_name} (ID: {user_id}) joined room: {room}")
        
        # Broadcast user presence to others in the room
        if user_id and user_name:
            socketio.emit('user_joined', {
                'user_id': user_id,
                'user_name': user_name
            }, room=room, include_self=False)

@socketio.on('leave_session')
def handle_leave_session(data):
    """User leaves a session room"""
    session_id = data.get('session_id')
    user_id = data.get('user_id')
    user_name = data.get('user_name')
    
    if session_id:
        room = f'session_{session_id}'
        leave_room(room)
        print(f"User {user_name} (ID: {user_id}) left room: {room}")
        
        # Broadcast user departure to others in the room
        if user_id:
            socketio.emit('user_left', {
                'user_id': user_id,
                'user_name': user_name
            }, room=room, include_self=False)

@socketio.on('new_file_uploaded')
def handle_file_upload(data):
    """Broadcast new file upload to all users in session"""
    session_id = data.get('session_id')
    if session_id:
        room = f'session_{session_id}'
        socketio.emit('file_uploaded', data, room=room)

@socketio.on('typing')
def handle_typing(data):
    """Broadcast typing indicator to all users in session except sender"""
    session_id = data.get('session_id')
    user_name = data.get('user_name')
    is_typing = data.get('is_typing', True)
    
    if session_id and user_name:
        room = f'session_{session_id}'
        # Broadcast to room, sender will be excluded by client-side logic
        socketio.emit('user_typing', {
            'user_name': user_name,
            'is_typing': is_typing
        }, room=room, include_self=False)

@socketio.on('join_user_room')
def handle_join_user_room(data):
    """User joins their personal notification room"""
    user_id = data.get('user_id')
    if user_id:
        room = f'user_{user_id}'
        join_room(room)
        print(f"User {user_id} joined personal notification room")

@socketio.on('leave_user_room')
def handle_leave_user_room(data):
    """User leaves their personal notification room"""
    user_id = data.get('user_id')
    if user_id:
        room = f'user_{user_id}'
        leave_room(room)
        print(f"User {user_id} left personal notification room")

# Track note viewers
note_viewers = {}  # {note_id: [{user_id, username, sid}, ...]}

@socketio.on('join_note_room')
def handle_join_note_room(data):
    """User joins a note room to view it"""
    note_id = data.get('note_id')
    user_id = data.get('user_id')
    username = data.get('username', 'Anonymous')
    
    if note_id:
        room = f'note_{note_id}'
        join_room(room)
        
        # Add to viewers list
        if note_id not in note_viewers:
            note_viewers[note_id] = []
        
        # Remove existing entry for this user if any
        note_viewers[note_id] = [v for v in note_viewers[note_id] if v['user_id'] != user_id]
        
        # Add current viewer
        note_viewers[note_id].append({
            'user_id': user_id,
            'username': username,
            'sid': request.sid
        })
        
        # Broadcast updated viewer list
        socketio.emit('note_viewers_update', {
            'viewers': [{'username': v['username']} for v in note_viewers[note_id]]
        }, room=room)
        
        print(f"User {username} joined note {note_id} room. Total viewers: {len(note_viewers[note_id])}")

@socketio.on('leave_note_room')
def handle_leave_note_room(data):
    """User leaves a note room"""
    note_id = data.get('note_id')
    user_id = data.get('user_id')
    
    if note_id:
        room = f'note_{note_id}'
        leave_room(room)
        
        # Remove from viewers list
        if note_id in note_viewers:
            note_viewers[note_id] = [v for v in note_viewers[note_id] if v['user_id'] != user_id]
            
            # Broadcast updated viewer list
            socketio.emit('note_viewers_update', {
                'viewers': [{'username': v['username']} for v in note_viewers[note_id]]
            }, room=room)
            
            # Clean up empty lists
            if not note_viewers[note_id]:
                del note_viewers[note_id]
        
        print(f"User {user_id} left note {note_id} room")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle user disconnect - clean up from all note rooms"""
    sid = request.sid
    
    # Remove from all note viewer lists
    for note_id in list(note_viewers.keys()):
        original_count = len(note_viewers[note_id])
        note_viewers[note_id] = [v for v in note_viewers[note_id] if v['sid'] != sid]
        
        if len(note_viewers[note_id]) < original_count:
            # User was viewing this note, broadcast update
            room = f'note_{note_id}'
            socketio.emit('note_viewers_update', {
                'viewers': [{'username': v['username']} for v in note_viewers[note_id]]
            }, room=room)
        
        # Clean up empty lists
        if not note_viewers[note_id]:
            del note_viewers[note_id]

# ============================================
# WHITEBOARD ROUTES
# ============================================

@app.route('/whiteboard/<int:session_id>')
@login_required
def whiteboard(session_id):
    """View collaborative whiteboard for a session"""
    conn = get_db()
    
    # Check if user has access to session
    session_access = conn.execute('''
        SELECT s.id, s.title
        FROM sessions s
        LEFT JOIN rsvps r ON s.id = r.session_id
        WHERE s.id = ? AND (s.creator_id = ? OR r.user_id = ?)
    ''', (session_id, session['user_id'], session['user_id'])).fetchone()
    
    if not session_access:
        conn.close()
        flash('Access denied to this session')
        return redirect(url_for('index'))
    
    # Get or create whiteboard for this session
    whiteboard_data = conn.execute('''
        SELECT * FROM whiteboards WHERE session_id = ?
    ''', (session_id,)).fetchone()
    
    if not whiteboard_data:
        # Create new whiteboard
        conn.execute('''
            INSERT INTO whiteboards (session_id, title, canvas_data, created_by)
            VALUES (?, ?, ?, ?)
        ''', (session_id, f"Whiteboard - {session_access['title']}", '{}', session['user_id']))
        conn.commit()
        
        whiteboard_data = conn.execute('''
            SELECT * FROM whiteboards WHERE session_id = ?
        ''', (session_id,)).fetchone()
    
    conn.close()
    
    return render_template('whiteboard.html', 
                         whiteboard=whiteboard_data,
                         session_id=session_id,
                         session_title=session_access['title'])

@app.route('/whiteboard/<int:whiteboard_id>/save', methods=['POST'])
@login_required
def save_whiteboard(whiteboard_id):
    """Save whiteboard canvas data"""
    conn = get_db()
    
    # Verify access
    whiteboard = conn.execute('''
        SELECT w.*, s.creator_id
        FROM whiteboards w
        JOIN sessions s ON w.session_id = s.id
        LEFT JOIN rsvps r ON s.id = r.session_id
        WHERE w.id = ? AND (s.creator_id = ? OR r.user_id = ?)
    ''', (whiteboard_id, session['user_id'], session['user_id'])).fetchone()
    
    if not whiteboard:
        conn.close()
        return jsonify({'error': 'Access denied'}), 403
    
    canvas_data = request.json.get('canvas_data', '{}')
    
    conn.execute('''
        UPDATE whiteboards 
        SET canvas_data = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (canvas_data, whiteboard_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/whiteboard/<int:whiteboard_id>/export/<format>')
@login_required
def export_whiteboard(whiteboard_id, format):
    """Export whiteboard as PNG or PDF"""
    # This will be handled client-side with Fabric.js
    # This route just verifies access
    conn = get_db()
    
    whiteboard = conn.execute('''
        SELECT w.*, s.creator_id
        FROM whiteboards w
        JOIN sessions s ON w.session_id = s.id
        LEFT JOIN rsvps r ON s.id = r.session_id
        WHERE w.id = ? AND (s.creator_id = ? OR r.user_id = ?)
    ''', (whiteboard_id, session['user_id'], session['user_id'])).fetchone()
    
    conn.close()
    
    if not whiteboard:
        flash('Access denied')
        return redirect(url_for('index'))
    
    return jsonify({'success': True, 'whiteboard_id': whiteboard_id})

# ============================================
# WHITEBOARD SOCKET.IO HANDLERS
# ============================================

@socketio.on('join_whiteboard')
def handle_join_whiteboard(data):
    """Join whiteboard room for real-time collaboration"""
    whiteboard_id = data.get('whiteboard_id')
    username = data.get('username', 'Anonymous')
    
    room = f'whiteboard_{whiteboard_id}'
    join_room(room)
    
    emit('user_joined_whiteboard', {
        'username': username,
        'message': f'{username} joined the whiteboard'
    }, room=room, include_self=False)
    
    print(f"User {username} joined whiteboard {whiteboard_id}")

@socketio.on('whiteboard_draw')
def handle_whiteboard_draw(data):
    """Broadcast drawing action to all users in whiteboard"""
    whiteboard_id = data.get('whiteboard_id')
    room = f'whiteboard_{whiteboard_id}'
    
    emit('whiteboard_action', {
        'action': 'draw',
        'data': data
    }, room=room, include_self=False)

@socketio.on('whiteboard_object_added')
def handle_object_added(data):
    """Broadcast new object (shape, text, etc.) to all users"""
    whiteboard_id = data.get('whiteboard_id')
    room = f'whiteboard_{whiteboard_id}'
    
    emit('whiteboard_action', {
        'action': 'object_added',
        'data': data
    }, room=room, include_self=False)

@socketio.on('whiteboard_object_modified')
def handle_object_modified(data):
    """Broadcast object modifications to all users"""
    whiteboard_id = data.get('whiteboard_id')
    room = f'whiteboard_{whiteboard_id}'
    
    emit('whiteboard_action', {
        'action': 'object_modified',
        'data': data
    }, room=room, include_self=False)

@socketio.on('whiteboard_object_removed')
def handle_object_removed(data):
    """Broadcast object removal to all users"""
    whiteboard_id = data.get('whiteboard_id')
    room = f'whiteboard_{whiteboard_id}'
    
    emit('whiteboard_action', {
        'action': 'object_removed',
        'data': data
    }, room=room, include_self=False)

@socketio.on('whiteboard_clear')
def handle_whiteboard_clear(data):
    """Broadcast canvas clear to all users"""
    whiteboard_id = data.get('whiteboard_id')
    room = f'whiteboard_{whiteboard_id}'
    
    emit('whiteboard_action', {
        'action': 'clear',
        'data': data
    }, room=room, include_self=False)

@socketio.on('whiteboard_cursor')
def handle_cursor_movement(data):
    """Broadcast cursor position to other users"""
    whiteboard_id = data.get('whiteboard_id')
    room = f'whiteboard_{whiteboard_id}'
    
    emit('cursor_moved', data, room=room, include_self=False)

@socketio.on('leave_whiteboard')
def handle_leave_whiteboard(data):
    """Leave whiteboard room"""
    whiteboard_id = data.get('whiteboard_id')
    username = data.get('username', 'Anonymous')
    
    room = f'whiteboard_{whiteboard_id}'
    leave_room(room)
    
    emit('user_left_whiteboard', {
        'username': username,
        'message': f'{username} left the whiteboard'
    }, room=room)

# ============================================
# POMODORO TIMER ROUTES
# ============================================

@app.route('/api/pomodoro/start', methods=['POST'])
@login_required
def start_pomodoro():
    """Start a new Pomodoro session"""
    data = request.get_json()
    session_id = data.get('session_id')  # Optional - for group timers
    timer_type = data.get('type', 'work')  # 'work', 'short_break', 'long_break'
    duration = data.get('duration', 25)
    
    conn = get_db()
    
    # Insert new pomodoro session
    cursor = conn.execute('''
        INSERT INTO pomodoro_sessions (user_id, session_id, duration_minutes, type)
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], session_id, duration, timer_type))
    
    pomodoro_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Broadcast to session if it's a group timer
    if session_id:
        socketio.emit('pomodoro_started', {
            'user_id': session['user_id'],
            'username': session['full_name'],
            'type': timer_type,
            'duration': duration,
            'pomodoro_id': pomodoro_id
        }, room=f'session_{session_id}')
    
    return jsonify({
        'success': True,
        'pomodoro_id': pomodoro_id,
        'message': f'{timer_type.replace("_", " ").title()} started!'
    })

@app.route('/api/pomodoro/complete/<int:pomodoro_id>', methods=['POST'])
@login_required
def complete_pomodoro(pomodoro_id):
    """Mark a Pomodoro session as completed"""
    conn = get_db()
    
    # Get pomodoro details
    pomodoro = conn.execute('''
        SELECT * FROM pomodoro_sessions WHERE id = ? AND user_id = ?
    ''', (pomodoro_id, session['user_id'])).fetchone()
    
    if not pomodoro:
        conn.close()
        return jsonify({'success': False, 'message': 'Pomodoro not found'}), 404
    
    # Update completion
    conn.execute('''
        UPDATE pomodoro_sessions
        SET is_completed = 1, completed_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (pomodoro_id,))
    
    # Update focus statistics
    today = datetime.now().date()
    
    if pomodoro['type'] == 'work':
        conn.execute('''
            INSERT INTO focus_statistics (user_id, date, total_focus_minutes, pomodoros_completed)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(user_id, date) DO UPDATE SET
                total_focus_minutes = total_focus_minutes + ?,
                pomodoros_completed = pomodoros_completed + 1
        ''', (session['user_id'], today, pomodoro['duration_minutes'], pomodoro['duration_minutes']))
    else:
        conn.execute('''
            INSERT INTO focus_statistics (user_id, date, total_breaks_minutes)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, date) DO UPDATE SET
                total_breaks_minutes = total_breaks_minutes + ?
        ''', (session['user_id'], today, pomodoro['duration_minutes'], pomodoro['duration_minutes']))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'message': 'Pomodoro completed! Great job! 🎉'
    })

@app.route('/api/pomodoro/statistics')
@login_required
def get_pomodoro_statistics():
    """Get user's Pomodoro statistics"""
    conn = get_db()
    
    # Get today's stats
    today = datetime.now().date()
    today_stats = conn.execute('''
        SELECT * FROM focus_statistics WHERE user_id = ? AND date = ?
    ''', (session['user_id'], today)).fetchone()
    
    # Get last 7 days
    week_stats = conn.execute('''
        SELECT * FROM focus_statistics 
        WHERE user_id = ? AND date >= date('now', '-7 days')
        ORDER BY date DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get all-time totals
    all_time = conn.execute('''
        SELECT 
            SUM(total_focus_minutes) as total_focus,
            SUM(pomodoros_completed) as total_pomodoros,
            SUM(total_breaks_minutes) as total_breaks
        FROM focus_statistics
        WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    # Get current streak
    streak = 0
    check_date = datetime.now().date()
    while True:
        has_activity = conn.execute('''
            SELECT 1 FROM focus_statistics 
            WHERE user_id = ? AND date = ? AND pomodoros_completed > 0
        ''', (session['user_id'], check_date)).fetchone()
        
        if not has_activity:
            break
        streak += 1
        check_date = check_date - timedelta(days=1)
    
    conn.close()
    
    return jsonify({
        'success': True,
        'today': {
            'focus_minutes': today_stats['total_focus_minutes'] if today_stats else 0,
            'pomodoros': today_stats['pomodoros_completed'] if today_stats else 0,
            'breaks_minutes': today_stats['total_breaks_minutes'] if today_stats else 0
        },
        'week': [{
            'date': stat['date'],
            'focus_minutes': stat['total_focus_minutes'],
            'pomodoros': stat['pomodoros_completed']
        } for stat in week_stats],
        'all_time': {
            'total_focus': all_time['total_focus'] or 0,
            'total_pomodoros': all_time['total_pomodoros'] or 0,
            'total_breaks': all_time['total_breaks'] or 0
        },
        'streak': streak
    })

@app.route('/api/pomodoro/preferences', methods=['GET', 'POST'])
@login_required
def pomodoro_preferences():
    """Get or update Pomodoro preferences"""
    conn = get_db()
    
    if request.method == 'POST':
        data = request.get_json()
        
        # Update or create preferences
        conn.execute('''
            INSERT INTO pomodoro_preferences 
            (user_id, work_duration, short_break_duration, long_break_duration,
             auto_start_breaks, auto_start_pomodoros, dnd_mode, ambient_sound)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                work_duration = ?,
                short_break_duration = ?,
                long_break_duration = ?,
                auto_start_breaks = ?,
                auto_start_pomodoros = ?,
                dnd_mode = ?,
                ambient_sound = ?
        ''', (
            session['user_id'],
            data.get('work_duration', 25),
            data.get('short_break_duration', 5),
            data.get('long_break_duration', 15),
            1 if data.get('auto_start_breaks') else 0,
            1 if data.get('auto_start_pomodoros') else 0,
            1 if data.get('dnd_mode') else 0,
            data.get('ambient_sound', 'none'),
            # For UPDATE clause
            data.get('work_duration', 25),
            data.get('short_break_duration', 5),
            data.get('long_break_duration', 15),
            1 if data.get('auto_start_breaks') else 0,
            1 if data.get('auto_start_pomodoros') else 0,
            1 if data.get('dnd_mode') else 0,
            data.get('ambient_sound', 'none')
        ))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Preferences saved'})
    
    # GET request
    prefs = conn.execute('''
        SELECT * FROM pomodoro_preferences WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    
    conn.close()
    
    if prefs:
        return jsonify({
            'success': True,
            'preferences': {
                'work_duration': prefs['work_duration'],
                'short_break_duration': prefs['short_break_duration'],
                'long_break_duration': prefs['long_break_duration'],
                'auto_start_breaks': bool(prefs['auto_start_breaks']),
                'auto_start_pomodoros': bool(prefs['auto_start_pomodoros']),
                'dnd_mode': bool(prefs['dnd_mode']),
                'ambient_sound': prefs['ambient_sound']
            }
        })
    else:
        # Return defaults
        return jsonify({
            'success': True,
            'preferences': {
                'work_duration': 25,
                'short_break_duration': 5,
                'long_break_duration': 15,
                'auto_start_breaks': False,
                'auto_start_pomodoros': False,
                'dnd_mode': True,
                'ambient_sound': 'none'
            }
        })

# ============================================
# VIDEO/AUDIO CALL ROUTES
# ============================================

@app.route('/call/<int:session_id>')
@login_required
def video_call(session_id):
    """Video/audio call interface for a session"""
    conn = get_db()
    
    # Check if user has access to session
    session_access = conn.execute('''
        SELECT s.id, s.title, s.session_type
        FROM sessions s
        LEFT JOIN rsvps r ON s.id = r.session_id
        WHERE s.id = ? AND (s.creator_id = ? OR r.user_id = ?)
    ''', (session_id, session['user_id'], session['user_id'])).fetchone()
    
    if not session_access:
        conn.close()
        flash('Access denied to this session')
        return redirect(url_for('index'))
    
    # Get or create active call session
    active_call = conn.execute('''
        SELECT * FROM call_sessions 
        WHERE session_id = ? AND ended_at IS NULL
        ORDER BY started_at DESC LIMIT 1
    ''', (session_id,)).fetchone()
    
    if not active_call:
        # Create new call session
        cursor = conn.execute('''
            INSERT INTO call_sessions (session_id, call_type, started_by)
            VALUES (?, ?, ?)
        ''', (session_id, 'video', session['user_id']))
        call_session_id = cursor.lastrowid
        conn.commit()
        
        # Add creator as participant
        conn.execute('''
            INSERT INTO call_participants (call_session_id, user_id)
            VALUES (?, ?)
        ''', (call_session_id, session['user_id']))
        conn.commit()
    else:
        call_session_id = active_call['id']
        
        # Check if user already in call
        existing_participant = conn.execute('''
            SELECT id FROM call_participants
            WHERE call_session_id = ? AND user_id = ? AND left_at IS NULL
        ''', (call_session_id, session['user_id'])).fetchone()
        
        if not existing_participant:
            # Add user as participant
            conn.execute('''
                INSERT INTO call_participants (call_session_id, user_id)
                VALUES (?, ?)
            ''', (call_session_id, session['user_id']))
            conn.commit()
    
    # Get all participants in the call
    participants = conn.execute('''
        SELECT cp.*, u.full_name, u.username
        FROM call_participants cp
        JOIN users u ON cp.user_id = u.id
        WHERE cp.call_session_id = ? AND cp.left_at IS NULL
    ''', (call_session_id,)).fetchall()
    
    conn.close()
    
    return render_template('video_call.html',
                         session_id=session_id,
                         session_title=session_access['title'],
                         call_session_id=call_session_id,
                         participants=participants,
                         user_id=session['user_id'],
                         username=session.get('full_name', 'Anonymous'))

@app.route('/call/<int:call_session_id>/end', methods=['POST'])
@login_required
def end_call(call_session_id):
    """End a call session"""
    conn = get_db()
    
    call = conn.execute('SELECT * FROM call_sessions WHERE id = ?', (call_session_id,)).fetchone()
    
    if not call:
        conn.close()
        return jsonify({'error': 'Call not found'}), 404
    
    # Calculate duration
    started_at = datetime.strptime(call['started_at'], '%Y-%m-%d %H:%M:%S')
    duration = int((datetime.now() - started_at).total_seconds())
    
    # Update call session
    conn.execute('''
        UPDATE call_sessions
        SET ended_at = CURRENT_TIMESTAMP, duration = ?
        WHERE id = ?
    ''', (duration, call_session_id))
    
    # Update all active participants
    conn.execute('''
        UPDATE call_participants
        SET left_at = CURRENT_TIMESTAMP,
            duration = CAST((julianday(CURRENT_TIMESTAMP) - julianday(joined_at)) * 86400 AS INTEGER)
        WHERE call_session_id = ? AND left_at IS NULL
    ''', (call_session_id,))
    
    conn.commit()
    conn.close()
    
    # Notify all participants via WebSocket
    socketio.emit('call_ended', {
        'call_session_id': call_session_id,
        'message': 'Call has ended'
    }, room=f'call_{call_session_id}')
    
    return jsonify({'success': True, 'duration': duration})

@app.route('/call/<int:call_session_id>/leave', methods=['POST'])
@login_required
def leave_call(call_session_id):
    """Leave a call session"""
    conn = get_db()
    
    participant = conn.execute('''
        SELECT * FROM call_participants
        WHERE call_session_id = ? AND user_id = ? AND left_at IS NULL
    ''', (call_session_id, session['user_id'])).fetchone()
    
    if participant:
        # Calculate participant duration
        joined_at = datetime.strptime(participant['joined_at'], '%Y-%m-%d %H:%M:%S')
        duration = int((datetime.now() - joined_at).total_seconds())
        
        conn.execute('''
            UPDATE call_participants
            SET left_at = CURRENT_TIMESTAMP, duration = ?
            WHERE id = ?
        ''', (duration, participant['id']))
        conn.commit()
    
    conn.close()
    
    return jsonify({'success': True})

@app.route('/session/<int:session_id>/call-history')
@login_required
def call_history(session_id):
    """Get call history for a session"""
    conn = get_db()
    
    calls = conn.execute('''
        SELECT cs.*, u.full_name as started_by_name,
               (SELECT COUNT(*) FROM call_participants WHERE call_session_id = cs.id) as participant_count
        FROM call_sessions cs
        JOIN users u ON cs.started_by = u.id
        WHERE cs.session_id = ?
        ORDER BY cs.started_at DESC
    ''', (session_id,)).fetchall()
    
    conn.close()
    
    return jsonify({
        'calls': [{
            'id': c['id'],
            'call_type': c['call_type'],
            'started_by': c['started_by_name'],
            'started_at': c['started_at'],
            'ended_at': c['ended_at'],
            'duration': c['duration'],
            'participant_count': c['participant_count']
        } for c in calls]
    })

# ============================================
# WHITEBOARD ROUTES
# ============================================

@app.route('/whiteboard/<int:session_id>')
@login_required
def whiteboard(session_id):
    """Collaborative whiteboard for a study session"""
    conn = get_db()
    
    # Verify session exists and user has access
    study_session = conn.execute('SELECT * FROM sessions WHERE id = ?', (session_id,)).fetchone()
    if not study_session:
        flash('Session not found', 'error')
        conn.close()
        return redirect(url_for('home'))
    
    # Check if user is participant or creator
    is_creator = study_session['creator_id'] == session['user_id']
    has_rsvp = conn.execute('SELECT * FROM rsvps WHERE session_id = ? AND user_id = ?',
                            (session_id, session['user_id'])).fetchone() is not None
    
    if not is_creator and not has_rsvp:
        flash('You must RSVP to access the whiteboard', 'error')
        conn.close()
        return redirect(url_for('detail', session_id=session_id))
    
    # Get or create whiteboard for this session
    whiteboard = conn.execute('SELECT * FROM whiteboards WHERE session_id = ?', (session_id,)).fetchone()
    
    if not whiteboard:
        # Create new whiteboard
        conn.execute('''
            INSERT INTO whiteboards (session_id, title, created_by)
            VALUES (?, ?, ?)
        ''', (session_id, f"{study_session['title']} - Whiteboard", session['user_id']))
        conn.commit()
        whiteboard = conn.execute('SELECT * FROM whiteboards WHERE session_id = ?', (session_id,)).fetchone()
    
    conn.close()
    
    return render_template('whiteboard.html', 
                         study_session=study_session, 
                         whiteboard=whiteboard,
                         session_id=session_id)

@app.route('/api/whiteboard/load/<int:session_id>')
@login_required
def load_whiteboard(session_id):
    """Load whiteboard data for a session"""
    conn = get_db()
    
    # Get whiteboard
    whiteboard = conn.execute('SELECT * FROM whiteboards WHERE session_id = ?', (session_id,)).fetchone()
    
    if not whiteboard:
        conn.close()
        return jsonify({'success': False, 'message': 'Whiteboard not found'})
    
    # Get latest whiteboard data
    whiteboard_data = conn.execute('''
        SELECT * FROM whiteboard_data 
        WHERE whiteboard_id = ? 
        ORDER BY version DESC 
        LIMIT 1
    ''', (whiteboard['id'],)).fetchone()
    
    conn.close()
    
    if whiteboard_data:
        return jsonify({
            'success': True,
            'data': whiteboard_data['data_json'],
            'version': whiteboard_data['version'],
            'saved_at': whiteboard_data['saved_at']
        })
    else:
        return jsonify({
            'success': True,
            'data': '[]',  # Empty canvas
            'version': 0
        })

@app.route('/api/whiteboard/save', methods=['POST'])
@login_required
def save_whiteboard():
    """Save whiteboard data"""
    data = request.get_json()
    session_id = data.get('session_id')
    canvas_data = data.get('data')
    
    if not session_id or canvas_data is None:
        return jsonify({'success': False, 'message': 'Missing required fields'})
    
    conn = get_db()
    
    # Get whiteboard
    whiteboard = conn.execute('SELECT * FROM whiteboards WHERE session_id = ?', (session_id,)).fetchone()
    
    if not whiteboard:
        conn.close()
        return jsonify({'success': False, 'message': 'Whiteboard not found'})
    
    # Get current version
    current_version = conn.execute('''
        SELECT MAX(version) as max_version 
        FROM whiteboard_data 
        WHERE whiteboard_id = ?
    ''', (whiteboard['id'],)).fetchone()
    
    next_version = (current_version['max_version'] or 0) + 1
    
    # Save new version
    conn.execute('''
        INSERT INTO whiteboard_data (whiteboard_id, data_json, version, saved_by)
        VALUES (?, ?, ?, ?)
    ''', (whiteboard['id'], canvas_data, next_version, session['user_id']))
    
    # Update whiteboard updated_at
    conn.execute('''
        UPDATE whiteboards 
        SET updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (whiteboard['id'],))
    
    conn.commit()
    conn.close()
    
    # Broadcast update via WebSocket
    socketio.emit('whiteboard_updated', {
        'session_id': session_id,
        'user_id': session['user_id'],
        'version': next_version
    }, room=f'whiteboard_{session_id}')
    
    return jsonify({
        'success': True,
        'version': next_version,
        'message': 'Whiteboard saved successfully'
    })

# ============================================
# WEBRTC SIGNALING SOCKET.IO HANDLERS
# ============================================

@socketio.on('join_call')
def handle_join_call(data):
    """User joins a call room"""
    call_session_id = data.get('call_session_id')
    user_id = data.get('user_id')
    username = data.get('username', 'Anonymous')
    
    room = f'call_{call_session_id}'
    join_room(room)
    
    # Notify others that a new user joined
    emit('user_joined_call', {
        'user_id': user_id,
        'username': username,
        'message': f'{username} joined the call'
    }, room=room, include_self=False)
    
    print(f"User {username} (ID: {user_id}) joined call {call_session_id}")

@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    """Forward WebRTC offer to target peer"""
    target_user_id = data.get('target_user_id')
    offer = data.get('offer')
    sender_user_id = data.get('sender_user_id')
    call_session_id = data.get('call_session_id')
    
    # Emit to specific user in the call room
    emit('webrtc_offer', {
        'offer': offer,
        'sender_user_id': sender_user_id
    }, room=f'call_{call_session_id}', skip_sid=request.sid)

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    """Forward WebRTC answer to target peer"""
    target_user_id = data.get('target_user_id')
    answer = data.get('answer')
    sender_user_id = data.get('sender_user_id')
    call_session_id = data.get('call_session_id')
    
    emit('webrtc_answer', {
        'answer': answer,
        'sender_user_id': sender_user_id
    }, room=f'call_{call_session_id}', skip_sid=request.sid)

@socketio.on('webrtc_ice_candidate')
def handle_ice_candidate(data):
    """Forward ICE candidate to target peer"""
    candidate = data.get('candidate')
    sender_user_id = data.get('sender_user_id')
    call_session_id = data.get('call_session_id')
    
    emit('webrtc_ice_candidate', {
        'candidate': candidate,
        'sender_user_id': sender_user_id
    }, room=f'call_{call_session_id}', skip_sid=request.sid)

@socketio.on('toggle_audio')
def handle_toggle_audio(data):
    """Broadcast audio toggle status"""
    call_session_id = data.get('call_session_id')
    user_id = data.get('user_id')
    is_muted = data.get('is_muted')
    
    emit('user_audio_toggled', {
        'user_id': user_id,
        'is_muted': is_muted
    }, room=f'call_{call_session_id}', include_self=False)

@socketio.on('toggle_video')
def handle_toggle_video(data):
    """Broadcast video toggle status"""
    call_session_id = data.get('call_session_id')
    user_id = data.get('user_id')
    is_video_off = data.get('is_video_off')
    
    emit('user_video_toggled', {
        'user_id': user_id,
        'is_video_off': is_video_off
    }, room=f'call_{call_session_id}', include_self=False)

@socketio.on('screen_share_started')
def handle_screen_share_started(data):
    """Notify others that screen sharing started"""
    call_session_id = data.get('call_session_id')
    user_id = data.get('user_id')
    username = data.get('username')
    
    emit('user_screen_share_started', {
        'user_id': user_id,
        'username': username
    }, room=f'call_{call_session_id}', include_self=False)

@socketio.on('screen_share_stopped')
def handle_screen_share_stopped(data):
    """Notify others that screen sharing stopped"""
    call_session_id = data.get('call_session_id')
    user_id = data.get('user_id')
    
    emit('user_screen_share_stopped', {
        'user_id': user_id
    }, room=f'call_{call_session_id}', include_self=False)

@socketio.on('leave_call')
def handle_leave_call_socket(data):
    """User leaves call room"""
    call_session_id = data.get('call_session_id')
    user_id = data.get('user_id')
    username = data.get('username', 'Anonymous')
    
    room = f'call_{call_session_id}'
    leave_room(room)
    
    emit('user_left_call', {
        'user_id': user_id,
        'username': username,
        'message': f'{username} left the call'
    }, room=room)
    
    print(f"User {username} left call {call_session_id}")

# ============================================
# WHITEBOARD SOCKET.IO HANDLERS
# ============================================

@socketio.on('join_whiteboard')
def handle_join_whiteboard(data):
    """User joins a whiteboard room"""
    session_id = data.get('session_id')
    user_id = data.get('user_id')
    username = data.get('username', 'Anonymous')
    
    room = f'whiteboard_{session_id}'
    join_room(room)
    
    emit('user_joined_whiteboard', {
        'user_id': user_id,
        'username': username
    }, room=room, include_self=False)
    
    print(f"User {username} joined whiteboard for session {session_id}")

@socketio.on('leave_whiteboard')
def handle_leave_whiteboard(data):
    """User leaves whiteboard room"""
    session_id = data.get('session_id')
    user_id = data.get('user_id')
    username = data.get('username', 'Anonymous')
    
    room = f'whiteboard_{session_id}'
    leave_room(room)
    
    emit('user_left_whiteboard', {
        'user_id': user_id,
        'username': username
    }, room=room)
    
    print(f"User {username} left whiteboard for session {session_id}")

@socketio.on('whiteboard_draw')
def handle_whiteboard_draw(data):
    """Broadcast drawing actions to other users in real-time"""
    session_id = data.get('session_id')
    draw_data = data.get('draw_data')
    user_id = data.get('user_id')
    
    room = f'whiteboard_{session_id}'
    
    # Broadcast to others in the room
    emit('whiteboard_draw', {
        'user_id': user_id,
        'draw_data': draw_data
    }, room=room, skip_sid=request.sid)

@socketio.on('whiteboard_cursor')
def handle_whiteboard_cursor(data):
    """Broadcast cursor position to other users"""
    session_id = data.get('session_id')
    user_id = data.get('user_id')
    username = data.get('username', 'Anonymous')
    x = data.get('x')
    y = data.get('y')
    
    room = f'whiteboard_{session_id}'
    
    emit('whiteboard_cursor', {
        'user_id': user_id,
        'username': username,
        'x': x,
        'y': y
    }, room=room, skip_sid=request.sid)

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)