import os
import re
import logging
import time
import requests
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List, Optional, Union
from slack_bolt import App
from slack_bolt.oauth.oauth_settings import OAuthSettings
from slack_sdk.oauth.installation_store import Installation
from slack_sdk.oauth.state_store import FileOAuthStateStore
from slack_bolt.adapter.flask import SlackRequestHandler
from flask import Flask, request, redirect, render_template_string
from dotenv import load_dotenv
from urllib.parse import urlparse
import database

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration settings for LinkGuard."""
    trusted_domains: List[str] = field(default_factory=lambda: [
        "google.com",
        "microsoft.com",
        "slack.com",
        "github.com",
        "linkedin.com",
    ])
    malicious_keywords: List[str] = field(default_factory=lambda: [
        "phish", "malware", "badsite", "danger", "hack", "virus"
    ])
    vt_timeout: int = 10
    vt_max_retries: int = 3
    vt_retry_delay: float = 2.0
    cache_maxsize: int = 1000


# Global configuration instance
config = Config()

# Environment variables
SLACK_CLIENT_ID = os.environ.get("SLACK_CLIENT_ID")
SLACK_CLIENT_SECRET = os.environ.get("SLACK_CLIENT_SECRET")
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET")
VT_API_KEY = os.environ.get("VT_API_KEY")

# Validate required environment variables
if not SLACK_CLIENT_ID:
    raise EnvironmentError("Missing required environment variable: SLACK_CLIENT_ID")
if not SLACK_CLIENT_SECRET:
    raise EnvironmentError("Missing required environment variable: SLACK_CLIENT_SECRET")
if not SLACK_SIGNING_SECRET:
    raise EnvironmentError("Missing required environment variable: SLACK_SIGNING_SECRET")


# Custom installation store using our database
class DatabaseInstallationStore:
    """Store installations in SQLite database."""
    
    def save(self, installation: Installation):
        """Save installation to database."""
        database.save_workspace(
            team_id=installation.team_id,
            team_name=installation.team_name or "Unknown",
            bot_token=installation.bot_token,
            bot_user_id=installation.bot_user_id
        )
    
    def find_installation(self, *, enterprise_id: Optional[str], team_id: Optional[str], user_id: Optional[str] = None, is_enterprise_install: Optional[bool] = None):
        """Find installation by team_id."""
        if team_id:
            bot_token = database.get_workspace_token(team_id)
            if bot_token:
                return Installation(
                    app_id="",  # Not needed for bot token
                    team_id=team_id,
                    bot_token=bot_token,
                    bot_user_id="",  # Will be populated from database if needed
                    user_id="",  # Required parameter
                )
        return None


# OAuth settings
oauth_settings = OAuthSettings(
    client_id=SLACK_CLIENT_ID,
    client_secret=SLACK_CLIENT_SECRET,
    scopes=["chat:write", "channels:history", "groups:history", "im:history", "mpim:history"],
    installation_store=DatabaseInstallationStore(),
    state_store=FileOAuthStateStore(expiration_seconds=600, base_dir="./oauth_states")
)

# Slack app with OAuth
app = App(
    signing_secret=SLACK_SIGNING_SECRET,
    oauth_settings=oauth_settings
)

# VirusTotal configuration
VT_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls"

# URL regex pattern
URL_REGEX = r"(https?://[^\s<>\"']+)"


def is_valid_url(url: str) -> bool:
    """Check if a URL is properly formatted."""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False


def is_trusted_domain(url: str) -> bool:
    """Check if a URL belongs to a trusted domain."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove 'www.' prefix if present
        if domain.startswith("www."):
            domain = domain[4:]
        # Check if domain ends with any trusted domain
        for trusted in config.trusted_domains:
            if domain == trusted or domain.endswith("." + trusted):
                return True
        return False
    except Exception:
        return False


def _check_virustotal_impl(url: str) -> Union[bool, str]:
    """
    Internal implementation for VirusTotal check.
    Returns: True (malicious), False (safe), or "fallback" (couldn't check)
    """
    if not VT_API_KEY:
        logger.warning("VirusTotal API key not configured")
        return "fallback"
    
    try:
        headers = {"x-apikey": VT_API_KEY}
        
        # First, submit the URL for scanning
        submit_response = requests.post(
            VT_SUBMIT_URL,
            headers=headers,
            data={"url": url},
            timeout=config.vt_timeout
        )
        
        # Check for rate limiting
        if submit_response.status_code == 429:
            logger.warning("VirusTotal rate limit reached")
            return "fallback"
        
        # Check for other errors
        if submit_response.status_code != 200:
            logger.error(f"VirusTotal submit failed: {submit_response.status_code}")
            return "fallback"
        
        # Get the analysis ID from the response
        submit_data = submit_response.json()
        analysis_id = submit_data.get("data", {}).get("id")
        
        if not analysis_id:
            logger.error("No analysis ID returned from VirusTotal")
            return "fallback"
        
        # Poll for analysis results with retries
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        for attempt in range(config.vt_max_retries):
            time.sleep(config.vt_retry_delay)
            
            analysis_response = requests.get(
                analysis_url, 
                headers=headers, 
                timeout=config.vt_timeout
            )
            
            if analysis_response.status_code != 200:
                logger.error(f"VirusTotal analysis failed: {analysis_response.status_code}")
                continue
            
            analysis_data = analysis_response.json()
            attributes = analysis_data.get("data", {}).get("attributes", {})
            status = attributes.get("status")
            
            # Check if analysis is complete
            if status == "completed":
                stats = attributes.get("stats", {})
                # Safe type conversion with fallback
                malicious_count = stats.get("malicious") or 0
                suspicious_count = stats.get("suspicious") or 0
                
                if not isinstance(malicious_count, (int, float)):
                    malicious_count = 0
                if not isinstance(suspicious_count, (int, float)):
                    suspicious_count = 0
                
                # Consider URL malicious if any scanner flagged it
                return (int(malicious_count) + int(suspicious_count)) > 0
            
            logger.info(f"Analysis not complete, attempt {attempt + 1}/{config.vt_max_retries}")
        
        logger.warning("VirusTotal analysis did not complete in time")
        return "fallback"
        
    except requests.exceptions.Timeout:
        logger.error("VirusTotal request timed out")
        return "fallback"
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal network error: {e}")
        return "fallback"
    except Exception as e:
        logger.error(f"VirusTotal check failed unexpectedly: {e}")
        return "fallback"


@lru_cache(maxsize=1000)
def check_virustotal(url: str) -> Union[bool, str]:
    """
    Check a URL against VirusTotal with caching.
    Returns: True (malicious), False (safe), or "fallback" (couldn't check)
    """
    return _check_virustotal_impl(url)


def extract_urls(event: dict) -> List[str]:
    """Extract all URLs from a Slack message (text + rich preview blocks)."""
    urls = []

    # 1. Check plain text
    text = event.get("text", "")
    urls += re.findall(URL_REGEX, text)

    # 2. Check blocks (Slack rich previews)
    blocks = event.get("blocks", [])
    for block in blocks:
        if block.get("type") == "rich_text":
            for elem in block.get("elements", []):
                if elem.get("type") == "rich_text_section":
                    for subelem in elem.get("elements", []):
                        if subelem.get("type") == "text":
                            urls += re.findall(URL_REGEX, subelem.get("text", ""))
                        elif subelem.get("type") == "link":
                            link_url = subelem.get("url")
                            if link_url:
                                urls.append(link_url)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in urls:
        # Clean up the URL (remove trailing punctuation)
        url = url.rstrip('.,;:!?)')
        if url not in seen and is_valid_url(url):
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls


def check_with_fallback(url: str) -> bool:
    """Check URL using keywords when VirusTotal is unavailable."""
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in config.malicious_keywords)


@app.event("message")
def handle_message(event, say, client):
    """Main event listener for Slack messages."""
    
    # Ignore bot messages (prevent infinite loops)
    if event.get("bot_id") or event.get("subtype") == "bot_message":
        return

    user = event.get("user")
    channel = event.get("channel")
    urls = extract_urls(event)
    
    if not urls:
        return  # No URLs to check
    
    logger.info(f"Checking {len(urls)} URL(s) from user {user}")

    for url in urls:
        # Skip trusted domains
        if is_trusted_domain(url):
            logger.info(f"Skipping trusted domain: {url}")
            continue
        
        # Check with VirusTotal (cached)
        vt_result = check_virustotal(url)

        if vt_result == "fallback":
            # VirusTotal unavailable, use keyword check
            is_malicious = check_with_fallback(url)
            check_method = "keyword analysis"
        else:
            is_malicious = vt_result
            check_method = "VirusTotal"

        if is_malicious:
            logger.warning(f"Malicious URL detected ({check_method}): {url}")
            say(
                text=(
                    f"🚨 *Malicious Link Detected*\n"
                    f"<@{user}> shared a suspicious link:\n"
                    f"`{url}`\n\n"
                    f"⚠️ Detected by: {check_method}\n"
                    "❌ Do NOT click this link."
                ),
                channel=channel
            )
        else:
            logger.info(f"URL appears safe: {url}")


# Flask app to handle Slack events and OAuth
flask_app = Flask(__name__)
handler = SlackRequestHandler(app)


@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    """Handle incoming Slack events."""
    return handler.handle(request)


@flask_app.route("/slack/install", methods=["GET"])
def install():
    """Installation page with 'Add to Slack' button."""
    return handler.handle(request)


@flask_app.route("/slack/oauth_redirect", methods=["GET"])
def oauth_redirect():
    """OAuth callback handler."""
    return handler.handle(request)


@flask_app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for monitoring."""
    workspace_count = database.get_workspace_count()
    return {
        "status": "healthy", 
        "service": "LinkGuard",
        "vt_configured": bool(VT_API_KEY),
        "cache_info": check_virustotal.cache_info()._asdict(),
        "workspaces": workspace_count
    }, 200


@flask_app.route("/", methods=["GET"])
def home():
    """Home page with installation button."""
    workspace_count = database.get_workspace_count()
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Slack LinkGuard</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                text-align: center;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }
            .container {
                background: white;
                color: #333;
                padding: 40px;
                border-radius: 10px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            }
            h1 { color: #667eea; margin-bottom: 10px; }
            p { font-size: 18px; line-height: 1.6; }
            .features {
                text-align: left;
                margin: 30px 0;
                display: inline-block;
            }
            .features li {
                margin: 10px 0;
                font-size: 16px;
            }
            .stats {
                background: #f7f7f7;
                padding: 20px;
                border-radius: 5px;
                margin: 20px 0;
            }
            .install-btn {
                margin: 30px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Slack LinkGuard</h1>
            <p>Protect your Slack workspace from malicious URLs</p>
            
            <div class="features">
                <ul>
                    <li>🔍 Automatically scans URLs using VirusTotal</li>
                    <li>⚡ Real-time threat detection</li>
                    <li>🎯 Skips trusted domains</li>
                    <li>🔄 Smart caching for faster checks</li>
                    <li>📊 Fallback keyword detection</li>
                </ul>
            </div>
            
            <div class="stats">
                <strong>{{ workspaces }}</strong> workspace{{ 's' if workspaces != 1 else '' }} protected
            </div>
            
            <div class="install-btn">
                <a href="https://slack.com/oauth/v2/authorize?client_id={{ client_id }}&scope=chat:write,channels:history,groups:history,im:history,mpim:history">
                    <img alt="Add to Slack" height="40" width="139" 
                         src="https://platform.slack-edge.com/img/add_to_slack.png" 
                         srcSet="https://platform.slack-edge.com/img/add_to_slack.png 1x, https://platform.slack-edge.com/img/add_to_slack@2x.png 2x" />
                </a>
            </div>
            
            <p style="font-size: 14px; color: #666; margin-top: 30px;">
                By installing LinkGuard, you agree to our privacy policy and terms of service.
            </p>
        </div>
    </body>
    </html>
    """
    from flask import render_template_string
    return render_template_string(html, workspaces=workspace_count, client_id=SLACK_CLIENT_ID)


def clear_url_cache():
    """Utility function to clear the URL cache if needed."""
    check_virustotal.cache_clear()
    logger.info("URL cache cleared")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"LinkGuard is starting on port {port}...")
    logger.info(f"VirusTotal API configured: {bool(VT_API_KEY)}")
    logger.info(f"Trusted domains: {len(config.trusted_domains)}")
    logger.info(f"Cache size: {config.cache_maxsize}")
    logger.info(f"Installed workspaces: {database.get_workspace_count()}")
    
    # Note: For production, use a proper WSGI server like gunicorn:
    # gunicorn -w 4 -b 0.0.0.0:$PORT app:flask_app
    flask_app.run(host="0.0.0.0", port=port, debug=False)
