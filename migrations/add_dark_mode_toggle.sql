-- Migration: Add Dark Mode Toggle
-- Date: 2025-12-02
-- Description: Adds theme preference to user settings

-- Add theme preference column
ALTER TABLE user_settings ADD COLUMN theme TEXT DEFAULT 'dark';
