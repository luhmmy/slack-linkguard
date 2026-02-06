# Deployment Guide: Slack LinkGuard on Render

This guide will help you deploy Slack LinkGuard to Render so other workspaces can install it.

## Prerequisites

- ✅ GitHub repository with your code
- ✅ Render account (free tier available at https://render.com)
- ✅ Slack app created at https://api.slack.com/apps
- ✅ VirusTotal API key

---

## Part 1: Prepare Your Slack App

### 1. Go to Your Slack App Settings
Visit https://api.slack.com/apps and select your app (or create a new one).

### 2. Get OAuth Credentials
Go to **Basic Information** and copy:
- **Client ID**
- **Client Secret**
- **Signing Secret**

### 3. Configure OAuth & Permissions
Go to **OAuth & Permissions**:

**Redirect URLs** - Add:
```
https://your-app-name.onrender.com/slack/oauth_redirect
```
(Replace `your-app-name` with your actual Render app name)

**Bot Token Scopes** - Add these scopes:
- `chat:write`
- `channels:history`
- `groups:history`
- `im:history`
- `mpim:history`

### 4. Enable Event Subscriptions
Go to **Event Subscriptions**:

**Request URL**:
```
https://your-app-name.onrender.com/slack/events
```

**Subscribe to bot events**:
- `message.channels`
- `message.groups`
- `message.im`
- `message.mpim`

### 5. Enable Public Distribution
Go to **Manage Distribution**:
- Click **Activate Public Distribution**
- Fill in required information
- Add privacy policy URL (you'll create this)

---

## Part 2: Deploy to Render

### 1. Push Code to GitHub
Make sure all your changes are committed and pushed:

```powershell
git add .
git commit -m "Add OAuth multi-workspace support"
git push
```

### 2. Create New Web Service on Render

1. Go to https://dashboard.render.com
2. Click **New +** → **Web Service**
3. Connect your GitHub repository
4. Select the `slack-linkguard` repository

### 3. Configure the Service

**Name**: `slack-linkguard` (or your preferred name)

**Environment**: `Python 3`

**Build Command**:
```
pip install -r requirements.txt
```

**Start Command**:
```
gunicorn -w 4 -b 0.0.0.0:$PORT app_oauth:flask_app --timeout 120
```

**Instance Type**: `Free` (or paid if you prefer)

### 4. Add Environment Variables

Click **Advanced** → **Add Environment Variable** and add:

| Key | Value |
|-----|-------|
| `SLACK_CLIENT_ID` | Your Slack Client ID |
| `SLACK_CLIENT_SECRET` | Your Slack Client Secret |
| `SLACK_SIGNING_SECRET` | Your Slack Signing Secret |
| `VT_API_KEY` | Your VirusTotal API key |
| `PYTHON_VERSION` | `3.11.0` |

### 5. Deploy

Click **Create Web Service**

Render will:
- Clone your repository
- Install dependencies
- Start your application
- Provide you with a URL: `https://your-app-name.onrender.com`

---

## Part 3: Update Slack App URLs

Once deployed, go back to your Slack app settings and update:

1. **OAuth & Permissions** → **Redirect URLs**:
   ```
   https://your-actual-render-url.onrender.com/slack/oauth_redirect
   ```

2. **Event Subscriptions** → **Request URL**:
   ```
   https://your-actual-render-url.onrender.com/slack/events
   ```

3. Click **Save Changes**

---

## Part 4: Test Installation

### 1. Visit Your App
Go to: `https://your-app-name.onrender.com`

You should see the LinkGuard installation page.

### 2. Click "Add to Slack"
This will start the OAuth flow.

### 3. Authorize the App
Select a workspace and authorize the bot.

### 4. Test URL Scanning
In your Slack workspace:
- Post a URL in a channel
- The bot should scan it and respond if malicious

---

## Monitoring Your Deployment

### Health Check
Visit: `https://your-app-name.onrender.com/health`

This shows:
- Service status
- Number of installed workspaces
- VirusTotal configuration
- Cache statistics

### Render Logs
View logs in Render dashboard:
- Dashboard → Your Service → Logs
- Monitor installations and URL scans

### Database
The SQLite database (`workspaces.db`) is stored on Render's filesystem.

**Note**: Free tier Render instances may restart, which clears the filesystem. For production, consider:
- Upgrading to a paid plan with persistent disk
- Using PostgreSQL instead of SQLite

---

## Sharing Your App

### Installation URL
Share this URL for others to install:
```
https://your-app-name.onrender.com
```

### Add to Slack Button
The homepage has an "Add to Slack" button that starts the OAuth flow.

### Slack App Directory (Optional)
Submit your app to the Slack App Directory for wider distribution:
1. Complete all required information in your Slack app settings
2. Add privacy policy and terms of service
3. Submit for review

---

## Troubleshooting

### "URL Verification Failed"
- Check that your Render app is running
- Verify the Event Subscriptions URL is correct
- Check Render logs for errors

### "OAuth Error"
- Verify redirect URL matches exactly
- Check that Client ID and Secret are correct
- Ensure all required scopes are added

### "Database Not Persisting"
- Free tier Render instances restart and lose filesystem data
- Upgrade to paid plan or use PostgreSQL

### "Bot Not Responding"
- Check Render logs for errors
- Verify bot has correct permissions in channel
- Test the `/health` endpoint

---

## Next Steps

1. **Add Privacy Policy** - Create `PRIVACY.md` and host it
2. **Add Terms of Service** - Create terms for your app
3. **Monitor Usage** - Check logs and health endpoint regularly
4. **Scale** - Upgrade Render plan as you get more installations
5. **Backup Database** - Regularly backup `workspaces.db`

---

## Important Notes

### Security
- Never commit `.env` file to Git
- Keep your Client Secret secure
- Regularly rotate API keys

### Free Tier Limitations
- Render free tier spins down after inactivity
- First request after spin-down may be slow
- Database resets on restart (upgrade for persistence)

### Support
Monitor your Render logs and Slack app for issues. Users may report problems via your support channel.

---

## Your Deployment Checklist

- [ ] Code pushed to GitHub
- [ ] Render web service created
- [ ] Environment variables configured
- [ ] Slack app OAuth URLs updated
- [ ] Event subscriptions configured
- [ ] Test installation completed
- [ ] Health check verified
- [ ] Privacy policy created
- [ ] Ready to share installation URL!

**Your installation URL**: `https://your-app-name.onrender.com`
