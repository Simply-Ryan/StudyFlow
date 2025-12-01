# Main app redirection file. MESSY SO WATCH OUT

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

app = Flask(__name__)
app.secret_key = 'f47cba5d7844e3b4cc01994acb8de040c559faf14e9284d5530eeb02055d150b' # Generated. Important according to StackOverflow

DATABASE = 'sessions.db'
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'zip', 'rar'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# need to create uploads folder for file storage
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# decorator to protect routes that need authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# helper to show countdown to session
def format_time_remaining(session_date_str):
    """calculate how much time until session starts"""
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
    """check if uploaded file type is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_size_str(size_bytes):
    """convert bytes to readable size (KB, MB, etc)"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"

app.jinja_env.globals.update(get_file_size_str=get_file_size_str)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    conn = get_db()
    
    # grab search and filter params from URL
    search_query = request.args.get('search', '').strip()
    subject_filter = request.args.get('subject', '').strip()
    
    # build SQL query dynaMically based on filters
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
    return render_template('index.html', sessions=sessions_query, invitations=invitations, reminders=reminders)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']
        
        conn = get_db()
        # make sure username/email isn't already taken
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
        
        # auto-RSVP the creator to their own session
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
    
    # verify session exists
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
            # check if capacity reached
            current_count = len(rsvps)
            max_participants = study_session['max_participants'] if study_session['max_participants'] else 10
            
            # prevent duplicate RSVPs
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
    
    # fetch all files uploaded to this session
    files = conn.execute('''
        SELECT f.*, u.full_name, u.username
        FROM files f
        JOIN users u ON f.user_id = u.id
        WHERE f.session_id = ?
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
                         is_creator=is_creator, all_users=all_users, files=files)

@app.route('/session/<int:session_id>/message', methods=['POST'])
@login_required
def post_message(session_id):
    message_text = request.form.get('message_text', '')
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    if message_text.strip():
        conn = get_db()
        conn.execute('INSERT INTO messages (session_id, user_id, message_text) VALUES (?, ?, ?)',
                     (session_id, session['user_id'], message_text))
        conn.commit()
        
        # get the newly created message for AJAX response
        new_message = conn.execute('''
            SELECT m.*, u.full_name, u.username
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.session_id = ? AND m.user_id = ?
            ORDER BY m.created_at DESC
            LIMIT 1
        ''', (session_id, session['user_id'])).fetchone()
        conn.close()
        
        if is_ajax:
            return jsonify({
                'success': True,
                'message': {
                    'id': new_message['id'],
                    'full_name': new_message['full_name'],
                    'username': new_message['username'],
                    'message_text': new_message['message_text'],
                    'created_at': new_message['created_at'],
                    'user_id': new_message['user_id']
                }
            })
        
        flash('Message posted!')
    
    if is_ajax:
        return jsonify({'success': False, 'error': 'Empty message'})
    
    return redirect(url_for('detail', session_id=session_id))

@app.route('/session/<int:session_id>/messages')
def get_messages(session_id):
    """API endpoint to fetch messages for real-time updates"""
    last_message_id = request.args.get('last_id', 0, type=int)
    
    conn = get_db()
    messages = conn.execute('''
        SELECT m.*, u.full_name, u.username
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.session_id = ? AND m.id > ?
        ORDER BY m.created_at ASC
    ''', (session_id, last_message_id)).fetchall()
    conn.close()
    
    return jsonify({
        'messages': [{
            'id': msg['id'],
            'full_name': msg['full_name'],
            'username': msg['username'],
            'message_text': msg['message_text'],
            'created_at': msg['created_at'],
            'user_id': msg['user_id']
        } for msg in messages]
    })

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

@app.route('/session/<int:session_id>/delete', methods=['POST'])
@login_required
def delete_session(session_id):
    conn = get_db()
    
    # Verify the current user is the session creator
    study_session = conn.execute('SELECT creator_id FROM sessions WHERE id = ?', 
                                 (session_id,)).fetchone()
    
    if study_session and study_session['creator_id'] == session['user_id']:
        # remove uploaded files from disk first
        files = conn.execute('SELECT filename FROM files WHERE session_id = ?', (session_id,)).fetchall()
        for file_record in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_record['filename'])
            if os.path.exists(file_path):
                os.remove(file_path)
        
        # clean up database records
        conn.execute('DELETE FROM files WHERE session_id = ?', (session_id,))
        conn.execute('DELETE FROM messages WHERE session_id = ?', (session_id,))
        conn.execute('DELETE FROM rsvps WHERE session_id = ?', (session_id,))
        conn.execute('DELETE FROM invitations WHERE session_id = ?', (session_id,))
        # Delete the session itself
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
    reminder_text = request.form.get('reminder_text', '').strip()
    
    if not reminder_text:
        flash('Please enter a reminder message!')
        return redirect(url_for('detail', session_id=session_id))
    
    conn = get_db()
    
    # Verify the current user is the session creator
    study_session = conn.execute('SELECT creator_id FROM sessions WHERE id = ?', 
                                 (session_id,)).fetchone()
    
    if study_session and study_session['creator_id'] == session['user_id']:
        # Insert the reminder
        conn.execute('INSERT INTO reminders (session_id, reminder_text, sent_by) VALUES (?, ?, ?)',
                   (session_id, reminder_text, session['user_id']))
        conn.commit()
        flash(f'Reminder sent to all participants: "{reminder_text}"')
    else:
        flash('Only the session creator can send reminders!')
    
    conn.close()
    return redirect(url_for('detail', session_id=session_id))

@app.route('/reminder/<int:reminder_id>/dismiss', methods=['POST'])
@login_required
def dismiss_reminder(reminder_id):
    conn = get_db()
    
    try:
        # mark reminder as dismissed for this user
        conn.execute('INSERT INTO dismissed_reminders (reminder_id, user_id) VALUES (?, ?)',
                   (reminder_id, session['user_id']))
        conn.commit()
        flash('Reminder dismissed')
    except sqlite3.IntegrityError:
        # reminder already dismissed
        pass
    
    conn.close()
    return redirect(url_for('index'))

@app.route('/session/<int:session_id>/upload', methods=['POST'])
@login_required
def upload_file(session_id):
    # detect if request is AJAX (from JS) or regular form
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' or 'application/json' in request.headers.get('Accept', '')
    
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
        cursor = conn.execute('''INSERT INTO files (session_id, user_id, filename, original_filename, file_size, file_type) 
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (session_id, session['user_id'], filename, original_filename, file_size, file_type))
        file_id = cursor.lastrowid
        conn.commit()
        
        # get user info for AJAX response
        user_info = conn.execute('SELECT full_name, username FROM users WHERE id = ?', 
                                 (session['user_id'],)).fetchone()
        conn.close()
        
        if is_ajax:
            return jsonify({
                'success': True, 
                'message': f'File "{original_filename}" uploaded successfully!',
                'file': {
                    'id': file_id,
                    'original_filename': original_filename,
                    'file_size': file_size,
                    'file_type': file_type,
                    'full_name': user_info['full_name'],
                    'username': user_info['username'],
                    'uploaded_at': datetime.now().isoformat()
                }
            }), 200
        flash(f'File "{original_filename}" uploaded successfully!')
    else:
        error_msg = 'Invalid file type. Allowed types: images, PDFs, Office documents, text files, archives'
        conn.close()
        if is_ajax:
            return jsonify({'success': False, 'error': error_msg}), 400
        flash(error_msg)
    
    return redirect(url_for('detail', session_id=session_id))

@app.route('/session/<int:session_id>/files')
def get_files(session_id):
    """API endpoint to fetch files for real-time updates"""
    last_file_id = request.args.get('last_id', 0, type=int)
    
    conn = get_db()
    files = conn.execute('''
        SELECT f.*, u.full_name, u.username
        FROM files f
        JOIN users u ON f.user_id = u.id
        WHERE f.session_id = ? AND f.id > ?
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

@app.route('/invitation/<int:invitation_id>/respond', methods=['POST'])
@login_required
def respond_invitation(invitation_id):
    response = request.form.get('response')  # accept or decline
    
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

# check for upcoming sessions and send automatic reminders
def check_and_send_reminders():
    """background task to check for sessions and send automatic reminders at 1 week, 1 day, 1 hour"""
    conn = get_db()
    now = datetime.now()
    
    # get all upcoming sessions that haven't been completed yet
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

# NOTES ROUTES

@app.route('/notes')
def notes():
    conn = get_db()
    
    # get search and filter params
    search_query = request.args.get('search', '').strip()
    subject_filter = request.args.get('subject', '').strip()
    view_filter = request.args.get('view', 'all').strip()  # all, my_notes, public
    
    # build query based on filters
    query = '''
        SELECT n.*, u.full_name as author_name, u.username as author_username,
               (SELECT COUNT(*) FROM note_comments WHERE note_id = n.id) as comment_count
        FROM notes n
        JOIN users u ON n.user_id = u.id
        WHERE 1=1
    '''
    params = []
    
    # view filter
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
        query += ' AND n.is_public = 1'
    
    if search_query:
        query += ' AND (n.title LIKE ? OR n.description LIKE ? OR n.content LIKE ?)'
        params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])
    
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

# shut down scheduler when app exits
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    app.run(debug=True)