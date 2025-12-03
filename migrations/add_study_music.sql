-- Migration: Add Study Music Integration
-- Date: 2025-12-02
-- Description: Adds music preferences and playlist management

-- User music preferences
ALTER TABLE user_settings ADD COLUMN music_enabled INTEGER DEFAULT 0;
ALTER TABLE user_settings ADD COLUMN music_volume INTEGER DEFAULT 50;
ALTER TABLE user_settings ADD COLUMN default_music_type TEXT DEFAULT 'lofi';

-- Study playlists table
CREATE TABLE IF NOT EXISTS study_playlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    playlist_type TEXT NOT NULL, -- 'lofi', 'classical', 'ambient', 'binaural', 'white_noise'
    youtube_url TEXT,
    embed_code TEXT,
    duration INTEGER, -- in minutes
    thumbnail_url TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Session music settings (for synced playback in groups)
CREATE TABLE IF NOT EXISTS session_music (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    playlist_id INTEGER,
    is_playing INTEGER DEFAULT 0,
    current_time INTEGER DEFAULT 0, -- in seconds
    started_by INTEGER,
    started_at TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
    FOREIGN KEY (playlist_id) REFERENCES study_playlists(id),
    FOREIGN KEY (started_by) REFERENCES users(id)
);

-- User playlist favorites
CREATE TABLE IF NOT EXISTS user_playlist_favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    playlist_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (playlist_id) REFERENCES study_playlists(id) ON DELETE CASCADE,
    UNIQUE(user_id, playlist_id)
);

-- Insert default playlists
INSERT INTO study_playlists (name, description, playlist_type, youtube_url, duration) VALUES
    ('Lofi Hip Hop Study Beats', 'Chill lofi beats perfect for studying', 'lofi', 'https://www.youtube.com/watch?v=jfKfPfyJRdk', 600),
    ('Classical Music for Focus', 'Mozart, Bach, and Beethoven for deep concentration', 'classical', 'https://www.youtube.com/watch?v=--tFFaUBa1Y', 480),
    ('Ambient Study Music', 'Peaceful ambient soundscapes', 'ambient', 'https://www.youtube.com/watch?v=kP3oveP0nv8', 360),
    ('White Noise', 'Pure white noise for blocking distractions', 'white_noise', 'https://www.youtube.com/watch?v=nMfPqeZjc2c', 600),
    ('Binaural Beats - Focus', 'Alpha waves for enhanced concentration', 'binaural', 'https://www.youtube.com/watch?v=WPni755-Krg', 480),
    ('Jazz Study Session', 'Smooth jazz for a relaxed study vibe', 'lofi', 'https://www.youtube.com/watch?v=Dx5qFachd3A', 540);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_session_music_session ON session_music(session_id);
CREATE INDEX IF NOT EXISTS idx_user_playlist_favorites_user ON user_playlist_favorites(user_id);
