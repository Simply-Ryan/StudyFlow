import sqlite3

# Connect to database
conn = sqlite3.connect('sessions.db')
cursor = conn.cursor()

# Create session_recordings table
cursor.execute('''
CREATE TABLE IF NOT EXISTS session_recordings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    duration INTEGER,
    transcription TEXT,
    recording_type TEXT DEFAULT 'audio',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

conn.commit()
conn.close()

print("✓ Created session_recordings table")
print("Migration completed successfully!")
