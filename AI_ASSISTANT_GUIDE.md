# 🤖 AI Study Assistant - Setup & Usage Guide

## Overview

The AI Study Assistant uses OpenAI's GPT models to help you study more effectively. It can generate quiz questions, summarize content, explain complex topics, create study guides, and answer questions about your notes.

## Features

### 1. **Generate Quiz Questions**
- Automatically creates 5 multiple-choice questions from your note content
- Includes 4 options per question with correct answers
- Perfect for self-testing and exam preparation

### 2. **Summarize Content**
- Condenses long notes into key points
- Highlights main ideas and important concepts
- Saves time when reviewing materials

### 3. **Explain Topics**
- Breaks down complex concepts into simple terms
- Provides examples and analogies
- Great for understanding difficult subjects

### 4. **Create Study Guides**
- Comprehensive guides with key concepts and definitions
- Important points to remember
- Suggested review questions

### 5. **Interactive Q&A**
- Ask specific questions about your notes
- Get context-aware answers
- Natural conversation flow

---

## Setup Instructions

### Step 1: Get an OpenAI API Key

1. Go to [OpenAI Platform](https://platform.openai.com/)
2. Sign up or log in to your account
3. Navigate to **API Keys** section
4. Click **Create new secret key**
5. Copy the key (starts with `sk-...`)
6. **Important:** Store it securely - you won't be able to see it again!

### Step 2: Configure Environment Variables

#### Option A: Using .env file (Recommended)

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your API key:
   ```bash
   OPENAI_API_KEY=sk-your-actual-api-key-here
   AI_ENABLED=true
   AI_MODEL=gpt-4o-mini
   AI_MAX_TOKENS=1000
   ```

3. Install python-dotenv if not already installed:
   ```bash
   pip install python-dotenv
   ```

4. Update `config.py` to load from .env (already configured):
   ```python
   from dotenv import load_dotenv
   load_dotenv()
   ```

#### Option B: Using System Environment Variables

**Windows (PowerShell):**
```powershell
$env:OPENAI_API_KEY="sk-your-api-key-here"
$env:AI_ENABLED="true"
```

**Linux/Mac:**
```bash
export OPENAI_API_KEY="sk-your-api-key-here"
export AI_ENABLED="true"
```

### Step 3: Verify Setup

1. Start the application:
   ```bash
   python app.py
   ```

2. Look for this message in the console:
   ```
   ✅ AI Assistant enabled with OpenAI
   ```

3. If you see:
   ```
   ℹ️ AI Assistant disabled. Set OPENAI_API_KEY and AI_ENABLED=true to enable.
   ```
   → Check your environment variables

---

## Usage Guide

### Accessing the AI Assistant

1. Navigate to any note in StudyFlow
2. Scroll to the **AI Study Assistant** section below the note content
3. Click the dropdown to expand the AI panel

### Using Quick Actions

Click any of the action buttons:

- **📝 Generate Quiz** - Creates quiz questions from the entire note
- **📊 Summarize** - Provides a concise summary of the content
- **💡 Explain Topic** - Explains the subject matter simply
- **📚 Create Study Guide** - Generates a comprehensive study guide

### Asking Custom Questions

1. Type your question in the input field
2. Press **Enter** or click **Ask**
3. The AI will answer based on the note content

**Example Questions:**
- "What are the key points in this note?"
- "Can you explain [specific concept] in simpler terms?"
- "What should I focus on for the exam?"
- "Give me practice problems for this topic"

---

## Configuration Options

### Model Selection

You can change the AI model in `.env`:

```bash
# Fast and cheap (recommended for most users)
AI_MODEL=gpt-4o-mini

# More powerful but slower and costlier
AI_MODEL=gpt-4o

# Legacy models (not recommended)
AI_MODEL=gpt-3.5-turbo
```

### Token Limits

Control response length:

```bash
# Short responses (cheaper)
AI_MAX_TOKENS=500

# Medium responses (recommended)
AI_MAX_TOKENS=1000

# Long responses (for detailed explanations)
AI_MAX_TOKENS=2000
```

**Note:** Higher token limits cost more per request.

---

## Cost Management

### Understanding Costs

OpenAI charges per token (roughly 4 characters = 1 token):

| Model | Input Cost (per 1M tokens) | Output Cost (per 1M tokens) |
|-------|---------------------------|----------------------------|
| gpt-4o-mini | $0.15 | $0.60 |
| gpt-4o | $2.50 | $10.00 |

**Example:** A typical quiz generation (500 input + 500 output tokens):
- **gpt-4o-mini**: ~$0.0004 (less than a penny)
- **gpt-4o**: ~$0.006 (less than a penny)

### Cost Saving Tips

1. **Use gpt-4o-mini** for most tasks (20x cheaper than gpt-4o)
2. **Set lower token limits** if you don't need long responses
3. **Monitor usage** - Check the "Tokens used" displayed after each response
4. **Be specific** - Targeted questions get better answers with fewer tokens

### Setting Budget Limits

In your OpenAI account:
1. Go to **Settings** → **Billing**
2. Set a **monthly budget limit**
3. Enable **email notifications** when approaching limit

---

## Troubleshooting

### "AI Assistant is not enabled"

**Cause:** API key not configured or `AI_ENABLED=false`

**Solutions:**
1. Check `.env` file exists and has correct values
2. Verify `OPENAI_API_KEY` starts with `sk-`
3. Ensure `AI_ENABLED=true` (not `True` or `1`)
4. Restart the Flask application

### "API request failed: Incorrect API key"

**Cause:** Invalid or expired API key

**Solutions:**
1. Generate a new API key from OpenAI dashboard
2. Update `.env` with new key
3. Restart application

### "API request failed: You exceeded your current quota"

**Cause:** No credits or monthly limit exceeded

**Solutions:**
1. Add payment method to OpenAI account
2. Purchase credits
3. Check billing settings for limits

### "Rate limit exceeded"

**Cause:** Too many requests in short time

**Solutions:**
1. Wait 1-2 minutes before trying again
2. Upgrade OpenAI account tier for higher limits
3. Implement request caching (future feature)

### AI responses are not rendering correctly

**Cause:** Markdown/math rendering issue

**Solutions:**
1. Check browser console for JavaScript errors
2. Verify marked.js and KaTeX libraries loaded
3. Clear browser cache and reload

---

## Privacy & Security

### Data Handling

- **Note content** is sent to OpenAI servers for processing
- OpenAI may use data to improve models (unless opted out)
- No data is permanently stored by StudyFlow beyond note content

### Opt-Out of Training

In your OpenAI account:
1. Go to **Settings** → **Data Controls**
2. Disable "**Improve model for everyone**"
3. Your data won't be used for training

### Best Practices

1. **Don't include sensitive information** in notes (SSNs, passwords, etc.)
2. **Review OpenAI's privacy policy** before using
3. **Use school/personal account** appropriately
4. **Monitor API usage** regularly

---

## Advanced Features (Future)

### Planned Enhancements

- [ ] Multi-language support
- [ ] Custom AI instructions per note
- [ ] Conversation history/memory
- [ ] Batch processing (multiple notes at once)
- [ ] AI-generated flashcards
- [ ] Voice input/output
- [ ] Image analysis (diagrams, charts)
- [ ] PDF content extraction and analysis

---

## API Endpoints

For developers wanting to integrate AI features:

### POST `/api/ai-assist`

Generate AI responses for specific actions.

**Request Body:**
```json
{
  "action": "quiz|summarize|explain|study_guide|answer",
  "content": "note content here",
  "question": "optional question for 'answer' action"
}
```

**Response:**
```json
{
  "success": true,
  "response": "AI-generated content",
  "tokens_used": 456
}
```

### POST `/api/ai-chat`

Interactive chat with conversation history.

**Request Body:**
```json
{
  "messages": [
    {"role": "user", "content": "What is photosynthesis?"},
    {"role": "assistant", "content": "Photosynthesis is..."},
    {"role": "user", "content": "Can you explain it simply?"}
  ],
  "context": "optional note content for context"
}
```

**Response:**
```json
{
  "success": true,
  "response": "Simple explanation...",
  "tokens_used": 234
}
```

---

## Support

### Getting Help

1. Check this guide first
2. Review [OpenAI Documentation](https://platform.openai.com/docs)
3. Check StudyFlow GitHub issues
4. Contact StudyFlow support

### Reporting Issues

Include:
- Error message
- Steps to reproduce
- Browser console logs
- AI model being used

---

## License & Attribution

- AI Study Assistant powered by [OpenAI](https://openai.com/)
- StudyFlow is licensed under MIT License
- OpenAI API subject to [OpenAI Terms of Use](https://openai.com/policies/terms-of-use)

---

**Last Updated:** December 1, 2025  
**Version:** 1.0.0
