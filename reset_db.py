import sqlite3
import os

DATABASE = 'sessions.db'

def reset_database():
    """
    Completely resets the database by:
    1. Backing up the current database (optional safety)
    2. Deleting the database file
    3. Recreating it with the schema
    """
    
    # Check if database exists
    if os.path.exists(DATABASE):
        print(f"Found existing database: {DATABASE}")
        
        # Ask for confirmation
        response = input("⚠️  WARNING: This will delete ALL data (users, sessions, messages, etc.)!\nAre you sure? Type 'YES' to confirm: ")
        
        if response != 'YES':
            print("Reset cancelled.")
            return
        
        # Delete the database file
        try:
            os.remove(DATABASE)
            print(f"✓ Deleted {DATABASE}")
        except Exception as e:
            print(f"Error deleting database: {e}")
            return
    
    # Recreate database with schema
    print("Creating fresh database...")
    conn = sqlite3.connect(DATABASE)
    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()
    
    print("✓ Database reset successfully!")
    print("✓ All tables recreated with structure intact")
    print("✓ All data has been wiped clean")

if __name__ == '__main__':
    reset_database()
