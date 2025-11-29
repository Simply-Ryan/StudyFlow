from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'sessions.db'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Helper function to format session dates
def format_time_remaining(session_date_str):
    """Calculate time remaining until session and return formatted string"""
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

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db()
    sessions_query = conn.execute('''
        SELECT s.*, u.full_name as creator_name 
        FROM sessions s
        LEFT JOIN users u ON s.creator_id = u.id
        ORDER BY s.created_at DESC
    ''').fetchall()
    
    # Get user's invitations if logged in
    invitations = []
    if 'user_id' in session:
        invitations = conn.execute('''
            SELECT i.*, s.title as session_title, u.full_name as inviter_name
            FROM invitations i
            JOIN sessions s ON i.session_id = s.id
            JOIN users u ON i.inviter_id = u.id
            WHERE i.invitee_id = ? AND i.status = 'pending'
        ''', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('index.html', sessions=sessions_query, invitations=invitations)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        
        conn = get_db()
        # Check if username or email already exists
        existing_user = conn.execute('SELECT id FROM users WHERE username = ? OR email = ?', 
                                     (username, email)).fetchone()
        
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
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form['title']
        session_type = request.form['session_type']
        subject = request.form.get('subject', 'General')
        session_date = request.form.get('session_date', '')
        max_participants = request.form.get('max_participants', 10)
        meeting_link = request.form.get('meeting_link', '')
        location = request.form.get('location', '')
        
        conn = get_db()
        cursor = conn.execute('INSERT INTO sessions (title, session_type, subject, session_date, max_participants, meeting_link, location, creator_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (title, session_type, subject, session_date, max_participants, meeting_link, location, session['user_id']))
        session_id = cursor.lastrowid
        
        # Automatically RSVP the creator
        conn.execute('INSERT INTO rsvps (session_id, user_id) VALUES (?, ?)',
                     (session_id, session['user_id']))
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
    
    # Check if session exists
    if not study_session:
        conn.close()
        flash('Session not found!')
        return redirect(url_for('index'))
    
    rsvps = conn.execute('''
        SELECT r.*, u.full_name, u.username
        FROM rsvps r
        JOIN users u ON r.user_id = u.id
        WHERE r.session_id = ?
    ''', (session_id,)).fetchall()
    
    if request.method == 'POST':
        if 'rsvp' in request.form and 'user_id' in session:
            # Check if session is full
            current_count = len(rsvps)
            max_participants = study_session['max_participants'] if study_session['max_participants'] else 10
            
            # Check if user already RSVP'd
            user_rsvp = conn.execute('SELECT id FROM rsvps WHERE session_id = ? AND user_id = ?',
                                    (session_id, session['user_id'])).fetchone()
            
            if user_rsvp:
                flash('You have already RSVP\'d to this session!')
            elif current_count >= max_participants:
                flash('Sorry, this session is full!')
            else:
                conn.execute('INSERT INTO rsvps (session_id, user_id) VALUES (?, ?)',
                             (session_id, session['user_id']))
                conn.commit()
                flash('RSVP submitted successfully!')
        return redirect(url_for('detail', session_id=session_id))
    
    messages = conn.execute('''
        SELECT m.*, u.full_name, u.username
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.session_id = ?
        ORDER BY m.created_at ASC
    ''', (session_id,)).fetchall()
    
    # Get all users for invitation dropdown (exclude already invited/RSVP'd users)
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
    
    conn.close()
    
    # Calculate capacity info
    current_count = len(rsvps)
    max_participants = study_session['max_participants'] if study_session['max_participants'] else 10
    is_full = current_count >= max_participants
    spots_left = max_participants - current_count
    
    # Check if current user has RSVP'd
    user_has_rsvp = False
    if 'user_id' in session:
        user_has_rsvp = any(r['user_id'] == session['user_id'] for r in rsvps)
    
    is_creator = 'user_id' in session and study_session['creator_user_id'] == session['user_id']
    
    return render_template('detail.html', session=study_session, rsvps=rsvps, messages=messages,
                         current_count=current_count, max_participants=max_participants,
                         is_full=is_full, spots_left=spots_left, user_has_rsvp=user_has_rsvp,
                         is_creator=is_creator, all_users=all_users)

@app.route('/session/<int:session_id>/message', methods=['POST'])
@login_required
def post_message(session_id):
    message_text = request.form.get('message_text', '')
    
    if message_text.strip():
        conn = get_db()
        conn.execute('INSERT INTO messages (session_id, user_id, message_text) VALUES (?, ?, ?)',
                     (session_id, session['user_id'], message_text))
        conn.commit()
        conn.close()
        flash('Message posted!')
    
    return redirect(url_for('detail', session_id=session_id))

@app.route('/session/<int:session_id>/invite', methods=['POST'])
@login_required
def invite_user(session_id):
    invitee_id = request.form.get('invitee_id')
    
    if invitee_id:
        conn = get_db()
        
        # Verify the current user is the session creator
        study_session = conn.execute('SELECT creator_id FROM sessions WHERE id = ?', 
                                     (session_id,)).fetchone()
        
        if study_session and study_session['creator_id'] == session['user_id']:
            try:
                conn.execute('''INSERT INTO invitations (session_id, inviter_id, invitee_id) 
                               VALUES (?, ?, ?)''',
                           (session_id, session['user_id'], invitee_id))
                conn.commit()
                flash('Invitation sent successfully!')
            except sqlite3.IntegrityError:
                flash('User has already been invited!')
        else:
            flash('Only the session creator can send invitations!')
        
        conn.close()
    
    return redirect(url_for('detail', session_id=session_id))

@app.route('/invitation/<int:invitation_id>/respond', methods=['POST'])
@login_required
def respond_invitation(invitation_id):
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
            # Check if session is full
            current_count = conn.execute('SELECT COUNT(*) as count FROM rsvps WHERE session_id = ?',
                                        (invitation['session_id'],)).fetchone()['count']
            
            if current_count >= invitation['max_participants']:
                flash('Sorry, this session is now full!')
                conn.execute('UPDATE invitations SET status = ? WHERE id = ?', ('declined', invitation_id))
            else:
                # Add RSVP and update invitation status
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

if __name__ == '__main__':
    app.run(debug=True)