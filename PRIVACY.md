# Privacy Policy for Slack LinkGuard

**Last Updated**: February 6, 2026

## Introduction

Slack LinkGuard ("the Bot") is a security tool that scans URLs shared in Slack workspaces to detect potentially malicious links using the VirusTotal API.

## Information We Collect

### Automatically Collected
- **Workspace Information**: Team ID, team name
- **URLs**: Links shared in channels where the Bot is present
- **Message Metadata**: Channel ID, user ID (for notifications only)

### Not Collected
- ❌ Message content (except URLs)
- ❌ User personal information
- ❌ Private messages (unless Bot is explicitly added)
- ❌ File contents
- ❌ User passwords or credentials

## How We Use Information

### URL Scanning
- URLs are sent to VirusTotal API for malicious content detection
- Results are cached temporarily for performance
- URLs are not stored permanently

### Workspace Management
- OAuth tokens are stored to enable the Bot to function
- Team IDs are stored to identify installations
- Last active timestamps track workspace activity

## Data Storage

### What We Store
- OAuth access tokens (encrypted)
- Workspace team ID and name
- Installation and last active timestamps

### Where We Store It
- SQLite database on Render.com servers
- OAuth state files (temporary, auto-deleted)

### How Long We Store It
- OAuth tokens: Until app is uninstalled
- Workspace data: Until app is uninstalled
- URL cache: Maximum 24 hours (in-memory)

## Data Sharing

### Third-Party Services
- **VirusTotal**: URLs are sent for scanning (see VirusTotal's privacy policy)
- **Slack**: We use Slack's APIs to send messages
- **Render.com**: Hosting provider

### We Do NOT
- ❌ Sell your data
- ❌ Share data with advertisers
- ❌ Use data for marketing
- ❌ Share data with other users

## Your Rights

### Access
You can request information about what data we store for your workspace.

### Deletion
Uninstalling the Bot automatically deletes all stored data for your workspace.

### Control
Workspace admins can uninstall the Bot at any time via Slack settings.

## Security

- OAuth tokens are stored securely
- HTTPS encryption for all communications
- Regular security updates
- Minimal data collection principle

## Children's Privacy

The Bot is not intended for use by children under 13. We do not knowingly collect information from children.

## Changes to This Policy

We may update this privacy policy. Changes will be posted with a new "Last Updated" date.

## Contact

For privacy concerns or data requests:
- Email: [Your Email]
- GitHub: https://github.com/luhmmy/slack-linkguard

## Compliance

This Bot complies with:
- Slack's API Terms of Service
- GDPR (for EU users)
- CCPA (for California users)

## Data Processing

### Legal Basis (GDPR)
- Legitimate interest in providing security services
- Consent via OAuth installation

### Your GDPR Rights
- Right to access your data
- Right to deletion (uninstall)
- Right to data portability
- Right to object to processing

## Cookies

The Bot does not use cookies. OAuth state is stored temporarily server-side.

## Automated Decision Making

The Bot uses automated scanning to detect malicious URLs. Users can ignore warnings at their discretion.

---

By installing Slack LinkGuard, you agree to this privacy policy.
