-- Add preferred_language column to user_settings table
ALTER TABLE user_settings ADD COLUMN preferred_language TEXT DEFAULT 'en';

-- Add auto_translate column to user_settings table
ALTER TABLE user_settings ADD COLUMN auto_translate INTEGER DEFAULT 0;
