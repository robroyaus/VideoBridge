# Dropbox OAuth Setup Guide

This guide explains how to set up OAuth refresh tokens for Dropbox, which will prevent your access tokens from expiring.

## Why OAuth with Refresh Tokens?

- **Access tokens expire** after 4 hours
- **Refresh tokens don't expire** and can be used to get new access tokens automatically
- Your app will work indefinitely without manual token updates

## Setup Steps

### 1. Get Dropbox App Credentials

1. Go to https://www.dropbox.com/developers/apps
2. Click "Create app"
3. Choose:
   - **API**: Scoped access
   - **Access type**: Full Dropbox (or App folder)
   - **Name**: VideoBridge (or your choice)
4. Click **Create app**
5. In the **Settings** tab:
   - Copy your **App key**
   - Click **Show** next to App secret and copy it
6. In the **Permissions** tab, enable:
   - `files.metadata.write`
   - `files.metadata.read`
   - `files.content.write`
   - `files.content.read`
   - Click **Submit**

### 2. Run the OAuth Setup Script

```bash
# Set your app credentials
export DROPBOX_APP_KEY='your_app_key_here'
export DROPBOX_APP_SECRET='your_app_secret_here'

# Run the setup script
python3 setup_dropbox_oauth.py
```

The script will:
1. Open your browser for authorization
2. Get an authorization code from you
3. Exchange it for access and refresh tokens
4. Automatically update your `.env` file

### 3. Verify Setup

Check that your `.env` file now contains:
```
DROPBOX_APP_KEY=...
DROPBOX_APP_SECRET=...
DROPBOX_REFRESH_TOKEN=...
DROPBOX_ACCESS_TOKEN=...
```

### 4. Test the App

Access your app and try copying a file to Dropbox. The token will automatically refresh when needed!

## How It Works

The app now:
1. First tries to use the refresh token (if available)
2. Automatically gets a new access token when the old one expires
3. Falls back to the static access token if no refresh token is configured

## Troubleshooting

**Error: "No refresh token received"**
- Make sure you selected "Scoped access" when creating the app
- The `token_access_type='offline'` parameter requests refresh tokens

**Access still expiring?**
- Verify all three values are in `.env`: `DROPBOX_APP_KEY`, `DROPBOX_APP_SECRET`, `DROPBOX_REFRESH_TOKEN`
- Check the app logs for any OAuth errors

**Browser doesn't open?**
- Copy and paste the authorization URL manually
- Complete the authorization in your browser
- Copy the authorization code back to the terminal
