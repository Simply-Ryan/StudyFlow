-- AI Resource Recommendations Migration
-- Adds tables for storing AI-generated recommendations and user interaction tracking

-- Add AI settings to user_settings
ALTER TABLE user_settings ADD COLUMN ai_recommendations_enabled INTEGER DEFAULT 1;
ALTER TABLE user_settings ADD COLUMN ai_recommendation_frequency TEXT DEFAULT 'daily'; -- 'daily', 'weekly', 'per_session'

-- Table to store AI-generated resource recommendations
CREATE TABLE IF NOT EXISTS ai_recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_id INTEGER, -- NULL for general recommendations
    recommendation_type TEXT NOT NULL, -- 'resource', 'study_technique', 'schedule', 'content'
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    resource_url TEXT,
    resource_type TEXT, -- 'article', 'video', 'book', 'tool', 'technique'
    confidence_score REAL DEFAULT 0.0, -- 0.0 to 1.0
    reasoning TEXT, -- Why this was recommended
    metadata TEXT, -- JSON for additional data
    is_read INTEGER DEFAULT 0,
    is_helpful INTEGER, -- NULL=not rated, 1=helpful, 0=not helpful
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP, -- Optional expiration for time-sensitive recommendations
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

-- Table to track user's study topics and interests
CREATE TABLE IF NOT EXISTS user_study_topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    topic TEXT NOT NULL,
    category TEXT, -- 'math', 'science', 'language', 'programming', etc.
    proficiency_level TEXT DEFAULT 'beginner', -- 'beginner', 'intermediate', 'advanced'
    interest_score REAL DEFAULT 0.5, -- 0.0 to 1.0
    last_studied TIMESTAMP,
    study_count INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, topic)
);

-- Table to track AI recommendation interactions
CREATE TABLE IF NOT EXISTS recommendation_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recommendation_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL, -- 'viewed', 'clicked', 'dismissed', 'rated', 'saved'
    rating INTEGER, -- 1-5 stars for helpful ratings
    feedback_text TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (recommendation_id) REFERENCES ai_recommendations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table to store user's learning patterns for AI analysis
CREATE TABLE IF NOT EXISTS learning_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    pattern_type TEXT NOT NULL, -- 'study_time', 'focus_duration', 'break_frequency', 'preferred_resources'
    pattern_data TEXT NOT NULL, -- JSON with pattern details
    confidence REAL DEFAULT 0.0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, pattern_type)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_user ON ai_recommendations(user_id);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_session ON ai_recommendations(session_id);
CREATE INDEX IF NOT EXISTS idx_ai_recommendations_created ON ai_recommendations(created_at);
CREATE INDEX IF NOT EXISTS idx_user_study_topics_user ON user_study_topics(user_id);
CREATE INDEX IF NOT EXISTS idx_user_study_topics_topic ON user_study_topics(topic);
CREATE INDEX IF NOT EXISTS idx_recommendation_feedback_rec ON recommendation_feedback(recommendation_id);
CREATE INDEX IF NOT EXISTS idx_learning_patterns_user ON learning_patterns(user_id);
