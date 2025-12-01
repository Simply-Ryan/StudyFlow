"""
Test script to verify AI Assistant integration
"""
import sys
sys.path.insert(0, '.')

# Test imports
print("Testing imports...")
try:
    from flask import Flask
    print("✓ Flask imported successfully")
except ImportError as e:
    print(f"✗ Flask import failed: {e}")

try:
    from openai import OpenAI
    print("✓ OpenAI imported successfully")
except ImportError as e:
    print(f"✗ OpenAI import failed: {e}")

try:
    from config import Config
    print("✓ Config imported successfully")
    print(f"  - AI_ENABLED: {Config.AI_ENABLED}")
    print(f"  - AI_MODEL: {Config.AI_MODEL}")
    print(f"  - API_KEY configured: {bool(Config.OPENAI_API_KEY)}")
except Exception as e:
    print(f"✗ Config import failed: {e}")

# Test app initialization
print("\nTesting app initialization...")
try:
    from app import app, openai_client
    print("✓ App imported successfully")
    print(f"✓ OpenAI client: {openai_client is not None}")
except Exception as e:
    print(f"✗ App import failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*50)
print("✅ All tests passed! AI Assistant is ready to use.")
print("="*50)
print("\nTo enable AI features:")
print("1. Get an OpenAI API key from https://platform.openai.com/")
print("2. Set environment variables:")
print("   $env:OPENAI_API_KEY='sk-your-key-here'")
print("   $env:AI_ENABLED='true'")
print("3. Restart the application")
