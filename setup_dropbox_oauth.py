#!/usr/bin/env python3
"""
Setup script to get Dropbox OAuth refresh token.
This token will allow the app to automatically refresh expired access tokens.
"""

import os
import sys
from dropbox import DropboxOAuth2FlowNoRedirect

def update_env_file(key, value):
    """Update or add a key=value pair in .env file"""
    env_file = '.env'
    
    if not os.path.exists(env_file):
        print(f"Error: {env_file} not found")
        return False
    
    # Read existing .env content
    with open(env_file, 'r') as f:
        lines = f.readlines()
    
    # Update or add the key
    key_found = False
    for i, line in enumerate(lines):
        if line.startswith(f'{key}='):
            lines[i] = f'{key}={value}\n'
            key_found = True
            break
    
    if not key_found:
        lines.append(f'\n{key}={value}\n')
    
    # Write back to .env
    with open(env_file, 'w') as f:
        f.writelines(lines)
    
    return True

def main():
    print("=" * 60)
    print("Dropbox OAuth Setup - Get Refresh Token")
    print("=" * 60)
    print()
    
    # Get app credentials
    app_key = os.getenv('DROPBOX_APP_KEY') or input("Enter your Dropbox App Key: ").strip()
    app_secret = os.getenv('DROPBOX_APP_SECRET') or input("Enter your Dropbox App Secret: ").strip()
    
    if not app_key or not app_secret:
        print("\n❌ Error: App Key and App Secret are required")
        print("\nGet them from: https://www.dropbox.com/developers/apps")
        sys.exit(1)
    
    print(f"\n✓ Using App Key: {app_key[:10]}...")
    
    # Create OAuth flow
    auth_flow = DropboxOAuth2FlowNoRedirect(
        app_key,
        consumer_secret=app_secret,
        token_access_type='offline'  # Request refresh token
    )
    
    # Get authorization URL
    authorize_url = auth_flow.start()
    
    print("\n" + "=" * 60)
    print("STEP 1: Authorize the App")
    print("=" * 60)
    print("\n1. Open this URL in your browser (on your computer):")
    print("\n" + authorize_url)
    print("\n2. Log in to Dropbox if prompted")
    print("3. Click 'Allow' to authorize the app")
    print("4. Copy the authorization code shown on the page\n")
    
    # Get authorization code from user
    auth_code = input("Enter the authorization code: ").strip()
    
    if not auth_code:
        print("\n❌ Error: Authorization code is required")
        sys.exit(1)
    
    try:
        print("\n" + "=" * 60)
        print("STEP 2: Exchange Code for Tokens")
        print("=" * 60)
        
        # Complete OAuth flow
        oauth_result = auth_flow.finish(auth_code)
        
        access_token = oauth_result.access_token
        refresh_token = oauth_result.refresh_token
        
        if not refresh_token:
            print("\n⚠️  Warning: No refresh token received!")
            print("Make sure your app is configured for OAuth with refresh tokens.")
            sys.exit(1)
        
        print(f"\n✓ Access Token: {access_token[:20]}...{access_token[-10:]}")
        print(f"✓ Refresh Token: {refresh_token[:20]}...{refresh_token[-10:]}")
        
        # Update .env file
        print("\n" + "=" * 60)
        print("STEP 3: Update .env File")
        print("=" * 60)
        
        if update_env_file('DROPBOX_APP_KEY', app_key):
            print(f"✓ Updated DROPBOX_APP_KEY")
        
        if update_env_file('DROPBOX_APP_SECRET', app_secret):
            print(f"✓ Updated DROPBOX_APP_SECRET")
        
        if update_env_file('DROPBOX_REFRESH_TOKEN', refresh_token):
            print(f"✓ Updated DROPBOX_REFRESH_TOKEN")
        
        if update_env_file('DROPBOX_ACCESS_TOKEN', access_token):
            print(f"✓ Updated DROPBOX_ACCESS_TOKEN (initial)")
        
        print("\n" + "=" * 60)
        print("✅ Setup Complete!")
        print("=" * 60)
        print("\nYour app will now automatically refresh Dropbox tokens")
        print("when they expire. No more manual token updates needed!")
        print()
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
