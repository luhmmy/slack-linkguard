# Slack LinkGuard

A Slack bot that automatically scans URLs shared in channels for malicious content using the VirusTotal API.

## Features

- 🔍 Automatically detects and scans URLs in Slack messages
- 🛡️ Uses VirusTotal API for comprehensive threat detection
- ⚡ Caches results for faster repeated checks
- 🎯 Skips trusted domains (configurable)
- 🔄 Fallback keyword-based detection when VirusTotal is unavailable
- 📊 Health check endpoint for monitoring

## Prerequisites

- Python 3.7+
- Slack workspace with admin access
- VirusTotal API key (free tier available)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/luhmmy/slack-linkguard.git
cd slack-linkguard
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
```

Edit `.env` and add your credentials:
- `SLACK_BOT_TOKEN` - Your Slack bot token (starts with `xoxb-`)
- `SLACK_SIGNING_SECRET` - Your Slack app signing secret
- `VT_API_KEY` - Your VirusTotal API key

## Slack App Setup

1. Create a new Slack app at https://api.slack.com/apps
2. Enable **Event Subscriptions** and subscribe to `message.channels` event
3. Add **Bot Token Scopes**: `chat:write`, `channels:history`
4. Install the app to your workspace
5. Copy the Bot Token and Signing Secret to your `.env` file

## Usage

Run the bot:
```bash
python app.py
```

The bot will start on port 5000. For production, use a WSGI server like gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:flask_app
```

## Configuration

Edit the `Config` class in `app.py` to customize:
- Trusted domains list
- Malicious keywords for fallback detection
- VirusTotal timeout and retry settings
- Cache size

## Health Check

Access the health endpoint:
```
GET http://localhost:5000/health
```

## License

MIT License
