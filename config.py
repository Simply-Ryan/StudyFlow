import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_default_secret_key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///study_sessions.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # AI Assistant Configuration
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY') or None
    AI_MODEL = os.environ.get('AI_MODEL') or 'gpt-4o-mini'  # Cost-effective model
    AI_MAX_TOKENS = int(os.environ.get('AI_MAX_TOKENS', '1000'))
    AI_ENABLED = os.environ.get('AI_ENABLED', 'False').lower() == 'true'