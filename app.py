"""
StudyFlow - Collaborative Study Session Platform

A comprehensive Flask application for managing study sessions with real-time chat,
flashcards, notes, analytics, and user profiles.

Author: StudyFlow Team
Version: 1.15.0
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
import atexit

# ============================================
# APPLICATION CONFIGURATION
# ============================================
app = Flask(__name__)

# Security: Secret key for session management and CSRF protection
app.secret_key = 'f47cba5d7844e3b4cc01994acb8de040c559faf14e9284d5530eeb02055d150b'
app.config['SECRET_KEY'] = app.secret_key

# WebSocket: Initialize SocketIO for real-time features
socketio = SocketIO(app, cors_allowed_origins="*")

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
    deck = c.execute('''
        SELECT d.*, u.full_name as creator_name
        FROM flashcard_decks d
        LEFT JOIN users u ON d.user_id = u.id
        WHERE d.id = ? AND (d.user_id = ? OR d.is_public = 1)
    ''', (deck_id, session['user_id'])).fetchone()
    
    if not deck:
        flash('Deck not found or access denied')
        return redirect(url_for('flashcards'))
    
    # Get cards due for review (SM-2 algorithm)
    cards = c.execute('''
        SELECT f.*, p.easiness_factor, p.interval, p.repetitions, p.next_review_date
        FROM flashcards f
        LEFT JOIN flashcard_progress p ON f.id = p.flashcard_id AND p.user_id = ?
        WHERE f.deck_id = ?
        AND (p.next_review_date IS NULL OR p.next_review_date <= datetime('now'))
        ORDER BY p.next_review_date ASC
    ''', (session['user_id'], deck_id)).fetchall()
    
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
        session_reminders = 1 if request.form.get('session_reminders') else 0
        message_notifications = 1 if request.form.get('message_notifications') else 0
        theme = request.form.get('theme', 'purple')
        
        conn.execute('''
            UPDATE user_settings
            SET email_notifications = ?,
                session_reminders = ?,
                message_notifications = ?,
                theme = ?
            WHERE user_id = ?
        ''', (email_notifications, session_reminders, message_notifications, 
              theme, session['user_id']))
        
        conn.commit()
        conn.close()
        
        flash('Settings saved successfully!')
        return redirect(url_for('settings'))
    
    # GET - show settings
    conn = get_db()
    user_settings = conn.execute('''
        SELECT * FROM user_settings WHERE user_id = ?
    ''', (session['user_id'],)).fetchone()
    conn.close()
    
    return render_template('settings.html', settings=user_settings)

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
    \"\"\"Handle user joining a session room for real-time chat and updates.\"\"\"
    session_id = data.get('session_id')
    user_id = data.get('user_id')
    user_name = data.get('user_name')
    
    if session_id:
        room = f'session_{session_id}'
        join_room(room)
        print(f\"User {user_name} (ID: {user_id}) joined room: {room}\")
        
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

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)