#!/usr/bin/env python3
"""Migration script to add FTS5 search tables"""

import sqlite3

DATABASE = 'sessions.db'

def migrate():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    try:
        # Create FTS5 virtual table for sessions
        c.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS sessions_fts USING fts5(
                title,
                subject,
                location,
                content='sessions',
                content_rowid='id'
            )
        ''')
        print("✓ Created sessions_fts table")
        
        # Create FTS5 virtual table for messages
        c.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                message_text,
                content='messages',
                content_rowid='id'
            )
        ''')
        print("✓ Created messages_fts table")
        
        # Create FTS5 virtual table for notes
        c.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(
                title,
                content,
                content='notes',
                content_rowid='id'
            )
        ''')
        print("✓ Created notes_fts table")
        
        # Create FTS5 virtual table for files
        c.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS files_fts USING fts5(
                original_filename,
                content='files',
                content_rowid='id'
            )
        ''')
        print("✓ Created files_fts table")
        
        # Populate FTS tables with existing data
        c.execute('''
            INSERT INTO sessions_fts(rowid, title, subject, location)
            SELECT id, title, subject, COALESCE(location, '') FROM sessions
        ''')
        print("✓ Populated sessions_fts")
        
        c.execute('''
            INSERT INTO messages_fts(rowid, message_text)
            SELECT id, message_text FROM messages
        ''')
        print("✓ Populated messages_fts")
        
        c.execute('''
            INSERT INTO notes_fts(rowid, title, content)
            SELECT id, title, COALESCE(content, '') FROM notes
        ''')
        print("✓ Populated notes_fts")
        
        c.execute('''
            INSERT INTO files_fts(rowid, original_filename)
            SELECT id, original_filename FROM files
        ''')
        print("✓ Populated files_fts")
        
        # Create triggers to keep FTS tables in sync
        
        # Sessions triggers
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS sessions_ai AFTER INSERT ON sessions BEGIN
                INSERT INTO sessions_fts(rowid, title, subject, location)
                VALUES (new.id, new.title, new.subject, COALESCE(new.location, ''));
            END
        ''')
        
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS sessions_ad AFTER DELETE ON sessions BEGIN
                DELETE FROM sessions_fts WHERE rowid = old.id;
            END
        ''')
        
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS sessions_au AFTER UPDATE ON sessions BEGIN
                DELETE FROM sessions_fts WHERE rowid = old.id;
                INSERT INTO sessions_fts(rowid, title, subject, location)
                VALUES (new.id, new.title, new.subject, COALESCE(new.location, ''));
            END
        ''')
        print("✓ Created sessions triggers")
        
        # Messages triggers
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
                INSERT INTO messages_fts(rowid, message_text)
                VALUES (new.id, new.message_text);
            END
        ''')
        
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
                DELETE FROM messages_fts WHERE rowid = old.id;
            END
        ''')
        
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
                DELETE FROM messages_fts WHERE rowid = old.id;
                INSERT INTO messages_fts(rowid, message_text)
                VALUES (new.id, new.message_text);
            END
        ''')
        print("✓ Created messages triggers")
        
        # Notes triggers
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS notes_ai AFTER INSERT ON notes BEGIN
                INSERT INTO notes_fts(rowid, title, content)
                VALUES (new.id, new.title, COALESCE(new.content, ''));
            END
        ''')
        
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS notes_ad AFTER DELETE ON notes BEGIN
                DELETE FROM notes_fts WHERE rowid = old.id;
            END
        ''')
        
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS notes_au AFTER UPDATE ON notes BEGIN
                DELETE FROM notes_fts WHERE rowid = old.id;
                INSERT INTO notes_fts(rowid, title, content)
                VALUES (new.id, new.title, COALESCE(new.content, ''));
            END
        ''')
        print("✓ Created notes triggers")
        
        # Files triggers
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS files_ai AFTER INSERT ON files BEGIN
                INSERT INTO files_fts(rowid, original_filename)
                VALUES (new.id, new.original_filename);
            END
        ''')
        
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS files_ad AFTER DELETE ON files BEGIN
                DELETE FROM files_fts WHERE rowid = old.id;
            END
        ''')
        
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS files_au AFTER UPDATE ON files BEGIN
                DELETE FROM files_fts WHERE rowid = old.id;
                INSERT INTO files_fts(rowid, original_filename)
                VALUES (new.id, new.original_filename);
            END
        ''')
        print("✓ Created files triggers")
        
        conn.commit()
        print("\nMigration completed successfully!")
        
    except sqlite3.OperationalError as e:
        print(f"Note: {e}")
        print("FTS tables may already exist")
    
    finally:
        conn.close()

if __name__ == '__main__':
    migrate()
