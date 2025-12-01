#!/usr/bin/env python3
"""
Migration script to add user profile and settings tables.
"""

import sqlite3

def migrate():
    conn = sqlite3.connect('sessions.db')
    cursor = conn.cursor()
    
    print("👤 Starting user profiles & settings migration...")
    
    # Add profile columns to users table
    columns_to_add = [
        ("avatar_filename", "TEXT"),
        ("bio", "TEXT"),
        ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("last_login", "TIMESTAMP")
    ]
    
    for column_name, column_type in columns_to_add:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")
            print(f"✓ Added column: {column_name}")
        except sqlite3.OperationalError:
            print(f"⊘ Column {column_name} already exists, skipping")
    
    # Create user_settings table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        email_notifications INTEGER DEFAULT 1,
        session_reminders INTEGER DEFAULT 1,
        message_notifications INTEGER DEFAULT 1,
        theme TEXT DEFAULT 'purple',
        language TEXT DEFAULT 'en',
        timezone TEXT DEFAULT 'UTC',
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')
    print("✓ Created user_settings table")
    
    # Create default settings for existing users
    cursor.execute('''
    INSERT OR IGNORE INTO user_settings (user_id)
    SELECT id FROM users
    ''')
    print("✓ Created default settings for existing users")
    
    # Create user_stats table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        total_sessions_created INTEGER DEFAULT 0,
        total_sessions_joined INTEGER DEFAULT 0,
        total_messages_sent INTEGER DEFAULT 0,
        total_notes_created INTEGER DEFAULT 0,
        total_flashcards_studied INTEGER DEFAULT 0,
        study_streak_days INTEGER DEFAULT 0,
        last_study_date DATE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    ''')
    print("✓ Created user_stats table")
    
    # Initialize stats for existing users
    cursor.execute('''
    INSERT OR IGNORE INTO user_stats (user_id, total_sessions_created, total_sessions_joined, total_messages_sent, total_notes_created)
    SELECT 
        u.id,
        (SELECT COUNT(*) FROM sessions WHERE creator_id = u.id),
        (SELECT COUNT(*) FROM rsvps WHERE user_id = u.id),
        (SELECT COUNT(*) FROM messages WHERE user_id = u.id),
        (SELECT COUNT(*) FROM notes WHERE user_id = u.id)
    FROM users u
    ''')
    print("✓ Initialized stats for existing users")
    
    conn.commit()
    conn.close()
    
    print("\n✅ User profiles & settings migration completed successfully!")
    print("   - Added profile columns: avatar_filename, bio, created_at, last_login")
    print("   - user_settings: Email preferences, theme, language, timezone")
    print("   - user_stats: Activity tracking and study streaks")

if __name__ == '__main__':
    migrate()
