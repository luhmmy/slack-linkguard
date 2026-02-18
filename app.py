import os
import re
import logging
import time
import requests
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List, Optional, Union
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from flask import Flask, request
from dotenv import load_dotenv
from urllib.parse import urlparse

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
    vt_timeout: int = 10
    vt_max_retries: int = 3
    vt_retry_delay: float = 2.0
    cache_maxsize: int = 1000
    gsb_timeout: int = 5


# Global configuration instance
config = Config()

# Validate required environment variables at startup
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET")
VT_API_KEY = os.environ.get("VT_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

if not SLACK_BOT_TOKEN:
    raise EnvironmentError("Missing required environment variable: SLACK_BOT_TOKEN")
if not SLACK_SIGNING_SECRET:
    raise EnvironmentError("Missing required environment variable: SLACK_SIGNING_SECRET")

# Slack app
app = App(
    token=SLACK_BOT_TOKEN,
    signing_secret=SLACK_SIGNING_SECRET
)

# VirusTotal configuration
VT_SUBMIT_URL = "https://www.virustotal.com/api/v3/urls"

# Google Safe Browsing configuration
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

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


def check_google_safe_browsing(url: str) -> bool:
    """Check URL against Google Safe Browsing when VirusTotal is unavailable."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        logger.warning("Google Safe Browsing API key not configured")
        return False

    try:
        payload = {
            "client": {
                "clientId": "slack-linkguard",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(
            f"{GSB_API_URL}?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=config.gsb_timeout
        )

        if response.status_code != 200:
            logger.error(f"Google Safe Browsing request failed: {response.status_code}")
            return False

        result = response.json()
        # If matches exist, the URL is malicious
        return bool(result.get("matches"))

    except requests.exceptions.Timeout:
        logger.error("Google Safe Browsing request timed out")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Google Safe Browsing network error: {e}")
        return False
    except Exception as e:
        logger.error(f"Google Safe Browsing check failed unexpectedly: {e}")
        return False


@app.event("message")
def handle_message(event, say):
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
            # VirusTotal unavailable, use Google Safe Browsing
            is_malicious = check_google_safe_browsing(url)
            check_method = "Google Safe Browsing"
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


# Flask app to handle Slack events
flask_app = Flask(__name__)
handler = SlackRequestHandler(app)


@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    """Handle incoming Slack events."""
    return handler.handle(request)


@flask_app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy", 
        "service": "LinkGuard",
        "vt_configured": bool(VT_API_KEY),
        "gsb_configured": bool(GOOGLE_SAFE_BROWSING_API_KEY),
        "cache_info": check_virustotal.cache_info()._asdict()
    }, 200


def clear_url_cache():
    """Utility function to clear the URL cache if needed."""
    check_virustotal.cache_clear()
    logger.info("URL cache cleared")


if __name__ == "__main__":
    logger.info("LinkGuard is starting on port 5000...")
    logger.info(f"VirusTotal API configured: {bool(VT_API_KEY)}")
    logger.info(f"Google Safe Browsing API configured: {bool(GOOGLE_SAFE_BROWSING_API_KEY)}")
    logger.info(f"Trusted domains: {len(config.trusted_domains)}")
    logger.info(f"Cache size: {config.cache_maxsize}")
    
    # Note: For production, use a proper WSGI server like gunicorn:
    # gunicorn -w 4 -b 0.0.0.0:5000 app:flask_app
    flask_app.run(port=5000, debug=False)
