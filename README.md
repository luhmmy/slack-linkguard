# LinkGuard 🛡️

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Slack](https://img.shields.io/badge/Slack-Bot-4A154B?logo=slack)](https://slack.com)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API-394EFF?logo=virustotal)](https://www.virustotal.com)

**Real-time malicious URL detection bot for Slack workspaces**

LinkGuard automatically scans every URL shared in your Slack channels and alerts your team when malicious links are detected, protecting your organization from phishing attacks and malware.

## Features

- 🔍 Automatic URL scanning with VirusTotal API
- ⚡ LRU caching to reduce API calls
- 🛡️ Trusted domain whitelist
- 🔄 Fallback keyword detection when VirusTotal is unavailable
- 📊 Health check endpoint with cache statistics

## Setup

### 1. Install Dependencies

```bash
# Activate your virtual environment (if using one)
.\venv\Scripts\activate

# Install required packages
pip install -r requirements.txt
```

### 2. Configure Environment Variables

Make sure your `.env` file contains:

```
SLACK_BOT_TOKEN=xoxb-your-token-here
SLACK_SIGNING_SECRET=your-signing-secret-here
VT_API_KEY=your-virustotal-api-key-here
```

### 3. Start the Bot

```bash
python app.py
```

The bot will start on port 5000.

## Slack App Configuration

In your Slack App settings (https://api.slack.com/apps):

1. **OAuth & Permissions** - Add these bot token scopes:
   - `chat:write`
   - `channels:history`
   - `groups:history`
   - `im:history`
   - `mpim:history`

2. **Event Subscriptions**:
   - Enable Events
   - Request URL: `https://your-domain.com/slack/events`
   - Subscribe to bot events:
     - `message.channels`
     - `message.groups`
     - `message.im`
     - `message.mpim`

3. **Install App** to your workspace

## Production Deployment

For production, use a WSGI server like gunicorn:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:flask_app
```

## Health Check

Check bot status:
```bash
curl http://localhost:5000/health
```

## Configuration

Edit the `Config` dataclass in `app.py` to customize:
- `trusted_domains` - Domains to skip scanning
- `malicious_keywords` - Fallback keywords for detection
- `vt_timeout` - VirusTotal API timeout (default: 10s)
- `vt_max_retries` - Max retry attempts (default: 3)
- `cache_maxsize` - LRU cache size (default: 1000)
