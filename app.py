from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response
from flask_cors import CORS
from functools import wraps
import os
from datetime import datetime, timedelta
import secrets
import msal
import requests
import json
import dropbox
from dropbox.exceptions import ApiError

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app)

# Configuration
SHAREPOINT_SITE_URL = os.getenv('SHAREPOINT_SITE_URL', '')
SHAREPOINT_START_FOLDER = os.getenv('SHAREPOINT_START_FOLDER', 'Shared Documents')
PUBLIC_URL = os.getenv('PUBLIC_URL', '')

DROPBOX_ACCESS_TOKEN = os.getenv('DROPBOX_ACCESS_TOKEN', '')
DROPBOX_FOLDER = os.getenv('DROPBOX_FOLDER', '/Public/Videos')
DROPBOX_APP_KEY = os.getenv('DROPBOX_APP_KEY', '')
DROPBOX_APP_SECRET = os.getenv('DROPBOX_APP_SECRET', '')
DROPBOX_REFRESH_TOKEN = os.getenv('DROPBOX_REFRESH_TOKEN', '')

APP_USERNAME = os.getenv('APP_USERNAME', 'admin')
APP_PASSWORD = os.getenv('APP_PASSWORD', 'changeme')

CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph PowerShell app (public client)
AUTHORITY = "https://login.microsoftonline.com/common"
SCOPES = [
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "User.Read"
]
TOKEN_CACHE_FILE = "token_cache.json"

# Initialize Dropbox client
# Initialize Dropbox client
def get_dropbox_client():
    """Get authenticated Dropbox client with automatic token refresh"""
    global DROPBOX_ACCESS_TOKEN
    
    # If we have a refresh token, use OAuth with auto-refresh
    if DROPBOX_REFRESH_TOKEN and DROPBOX_APP_KEY and DROPBOX_APP_SECRET:
        try:
            dbx = dropbox.Dropbox(
                oauth2_refresh_token=DROPBOX_REFRESH_TOKEN,
                app_key=DROPBOX_APP_KEY,
                app_secret=DROPBOX_APP_SECRET
            )
            # Test the connection
            dbx.users_get_current_account()
            return dbx
        except Exception as e:
            print(f"Error with refresh token: {e}")
            # Fall through to try access token
    
    # Fall back to access token if available
    if not DROPBOX_ACCESS_TOKEN:
        return None
    return dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)

def parse_site_url(url):
    """Extract tenant and site path from SharePoint URL"""
    if not url:
        return None, None, None
    parts = url.replace('https://', '').split('/')
    tenant = parts[0].split('.')[0]  # e.g., 'pasanagroup' from 'pasanagroup.sharepoint.com'
    hostname = parts[0]  # e.g., 'pasanagroup.sharepoint.com'
    site_path = '/'.join(parts[1:])  # e.g., 'sites/MediaCommunications'
    return tenant, hostname, site_path

def load_token_cache():
    """Load token cache from file"""
    cache = msal.SerializableTokenCache()
    if os.path.exists(TOKEN_CACHE_FILE):
        with open(TOKEN_CACHE_FILE, 'r') as f:
            cache.deserialize(f.read())
    return cache

def save_token_cache(cache):
    """Save token cache to file"""
    if cache.has_state_changed:
        with open(TOKEN_CACHE_FILE, 'w') as f:
            f.write(cache.serialize())

def get_access_token():
    """Get access token using device code flow"""
    cache = load_token_cache()
    app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY, token_cache=cache)
    
    # Try to get token from cache first
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
        if result:
            save_token_cache(cache)
            return result['access_token']
    
    # Need interactive authentication
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise Exception("Failed to create device flow")
    
    print("\n" + "="*60)
    print("AUTHENTICATION REQUIRED")
    print("="*60)
    print(flow["message"])
    print("="*60 + "\n")
    
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" in result:
        save_token_cache(cache)
        return result['access_token']
    else:
        raise Exception(f"Authentication failed: {result.get('error_description')}")

def get_graph_headers():
    """Get headers for Graph API requests"""
    token = get_access_token()
    return {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

def check_auth(username, password):
    """Check if username/password combination is valid"""
    return username == APP_USERNAME and password == APP_PASSWORD

def authenticate():
    """Send 401 response for basic auth"""
    return Response(
        'Authentication required', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    """Decorator to require basic authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/')
@requires_auth
def index():
    """Home page"""
    if not SHAREPOINT_SITE_URL or not DROPBOX_ACCESS_TOKEN:
        return render_template('setup.html')
    return render_template('index.html')


@app.route('/browse')
@requires_auth
def browse():
    """Browse SharePoint folders and files using Microsoft Graph"""
    folder_path = request.args.get('path', 'Shared Documents')
    
    try:
        headers = get_graph_headers()
        tenant, hostname, site_path = parse_site_url(SHAREPOINT_SITE_URL)
        
        if not tenant or not hostname or not site_path:
            return jsonify({'error': 'Invalid SharePoint site URL'}), 400
        
        # Get site ID
        site_url = f"https://graph.microsoft.com/v1.0/sites/{hostname}:/{site_path}"
        site_response = requests.get(site_url, headers=headers)
        
        if site_response.status_code != 200:
            return jsonify({'error': f'Failed to access site: {site_response.text}'}), site_response.status_code
        
        site_id = site_response.json()['id']
        
        # Get drive (document library)
        drive_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive"
        drive_response = requests.get(drive_url, headers=headers)
        
        if drive_response.status_code != 200:
            return jsonify({'error': f'Failed to access drive: {drive_response.text}'}), drive_response.status_code
        
        drive_id = drive_response.json()['id']
        
        # Convert folder path to Graph API path
        if folder_path == 'Shared Documents' or folder_path == '':
            items_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/root/children"
        else:
            # Remove 'Shared Documents/' prefix if present
            clean_path = folder_path.replace('Shared Documents/', '').replace('Shared Documents', '')
            if clean_path:
                items_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/root:/{clean_path}:/children"
            else:
                items_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/root/children"
        
        items_response = requests.get(items_url, headers=headers)
        
        if items_response.status_code != 200:
            return jsonify({'error': f'Failed to list items: {items_response.text}'}), items_response.status_code
        
        graph_items = items_response.json().get('value', [])
        items = []
        
        for item in graph_items:
            if 'folder' in item:
                # It's a folder
                items.append({
                    'name': item['name'],
                    'type': 'folder',
                    'path': item.get('webUrl', ''),
                    'item_id': item['id']
                })
            elif 'file' in item and item['name'].lower().endswith('.mp4'):
                # It's an MP4 file
                items.append({
                    'name': item['name'],
                    'type': 'file',
                    'path': item.get('webUrl', ''),
                    'size': item.get('size', 0),
                    'item_id': item['id'],
                    'drive_id': drive_id,
                    'site_id': site_id
                })
        
        return jsonify({
            'current_path': folder_path,
            'items': items
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/generate-link', methods=['POST'])
def generate_link():
    """Generate a public direct download link for an MP4 file using Microsoft Graph"""
    data = request.get_json()
    item_id = data.get('item_id')
    drive_id = data.get('drive_id')
    site_id = data.get('site_id')
    
    if not all([item_id, drive_id, site_id]):
        return jsonify({'error': 'Missing required parameters'}), 400
    
    try:
        headers = get_graph_headers()
        
        # First create an anonymous sharing link
        share_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drives/{drive_id}/items/{item_id}/createLink"
        
        expiry = (datetime.now() + timedelta(days=365)).isoformat() + "Z"
        
        share_payload = {
            "type": "view",
            "scope": "anonymous",
            "expirationDateTime": expiry
        }
        
        share_response = requests.post(share_url, headers=headers, json=share_payload)
        
        if share_response.status_code not in [200, 201]:
            return jsonify({'error': f'Failed to create sharing link: {share_response.text}'}), share_response.status_code
        
        share_data = share_response.json()
        sharing_url = share_data.get('link', {}).get('webUrl', '')
        share_id = share_data.get('id', '')
        
        # Convert sharing URL to embed/download URL
        # SharePoint sharing URLs have format: https://[tenant].sharepoint.com/:v:/[path]
        # We need to convert to: https://[tenant].sharepoint.com/[path]?download=1
        
        if 'sharepoint.com' in sharing_url and '/:v:/' in sharing_url:
            # Extract the parts after /:v:/
            parts = sharing_url.split('/:v:/')
            if len(parts) == 2:
                base_url = parts[0]
                path_and_params = parts[1]
                
                # Remove any existing query parameters
                path = path_and_params.split('?')[0]
                
                # Construct direct download URL
                direct_url = f"{base_url}/{path}?download=1"
        elif 'sharepoint.com' in sharing_url and '/:u:/' in sharing_url:
            # For OneDrive-style links
            direct_url = sharing_url.replace('/:u:/', '/')
            if '?download=1' not in direct_url:
                direct_url = direct_url.split('?')[0] + '?download=1'
        else:
            # Fallback: just add download parameter
            direct_url = sharing_url
            if '?download=1' not in direct_url:
                if '?' in direct_url:
                    direct_url += '&download=1'
                else:
                    direct_url += '?download=1'
        
        # Also create an embed URL which some services prefer
        embed_url = direct_url.replace('?download=1', '?embed=1')
        
        # Create proxy URL that streams video directly (for Metricool compatibility)
        from flask import request as flask_request
        # Use PUBLIC_URL if set (for ngrok), otherwise use request URL
        base_url = PUBLIC_URL if PUBLIC_URL else flask_request.url_root.rstrip('/')
        proxy_url = f"{base_url}/video/{site_id}/{drive_id}/{item_id}"
        
        return jsonify({
            'success': True,
            'proxy_url': proxy_url,
            'direct_url': direct_url,
            'embed_url': embed_url,
            'sharing_url': sharing_url,
            'share_id': share_id
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/video/<site_id>/<drive_id>/<item_id>')
def stream_video(site_id, drive_id, item_id):
    """Stream video directly with proper Content-Type header (no redirects)"""
    try:
        headers = get_graph_headers()
        
        # Get the download URL from Graph API
        item_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drives/{drive_id}/items/{item_id}"
        item_response = requests.get(item_url, headers=headers)
        
        if item_response.status_code != 200:
            return jsonify({'error': 'Failed to get file'}), item_response.status_code
        
        item_data = item_response.json()
        download_url = item_data.get('@microsoft.graph.downloadUrl', '')
        
        if not download_url:
            return jsonify({'error': 'No download URL available'}), 404
        
        # Stream the video content directly
        video_response = requests.get(download_url, stream=True)
        
        if video_response.status_code != 200:
            return jsonify({'error': 'Failed to download video'}), video_response.status_code
        
        # Return video with proper headers
        from flask import Response
        return Response(
            video_response.iter_content(chunk_size=8192),
            content_type='video/mp4',
            headers={
                'Content-Length': video_response.headers.get('Content-Length', ''),
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'public, max-age=31536000'
            }
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/test-connection', methods=['POST'])
@requires_auth
def test_connection():
    """Test SharePoint connection using Microsoft Graph"""
    try:
        headers = get_graph_headers()
        tenant, hostname, site_path = parse_site_url(SHAREPOINT_SITE_URL)
        
        if not tenant or not hostname or not site_path:
            return jsonify({'error': 'Invalid SharePoint site URL'}), 400
        
        # Try to get site info
        site_url = f"https://graph.microsoft.com/v1.0/sites/{hostname}:/{site_path}"
        response = requests.get(site_url, headers=headers)
        
        if response.status_code == 200:
            site_data = response.json()
            return jsonify({
                'success': True,
                'site_title': site_data.get('displayName', 'Connected')
            })
        else:
            return jsonify({'error': f'Failed to connect: {response.text}'}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Dropbox Routes

@app.route('/dropbox/list', methods=['GET'])
@requires_auth
def dropbox_list():
    """List MP4 files in Dropbox folder"""
    try:
        dbx = get_dropbox_client()
        if not dbx:
            return jsonify({'error': 'Dropbox not configured'}), 500
        
        # List files in configured folder
        result = dbx.files_list_folder(DROPBOX_FOLDER)
        
        files = []
        for entry in result.entries:
            if isinstance(entry, dropbox.files.FileMetadata) and entry.name.lower().endswith('.mp4'):
                files.append({
                    'name': entry.name,
                    'size': entry.size,
                    'path': entry.path_display,
                    'id': entry.id
                })
        
        
        return jsonify({'files': files})
        
    except ApiError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/dropbox/copy', methods=['POST'])
@requires_auth
def dropbox_copy():
    """Copy file from SharePoint to Dropbox"""
    data = request.get_json()
    item_id = data.get('item_id')
    drive_id = data.get('drive_id')
    site_id = data.get('site_id')
    filename = data.get('filename')
    
    if not all([item_id, drive_id, site_id, filename]):
        return jsonify({'error': 'Missing required parameters'}), 400
    
    try:
        # Get file from SharePoint
        headers = get_graph_headers()
        item_url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drives/{drive_id}/items/{item_id}"
        item_response = requests.get(item_url, headers=headers)
        
        if item_response.status_code != 200:
            return jsonify({'error': 'Failed to get file from SharePoint'}), item_response.status_code
        
        item_data = item_response.json()
        download_url = item_data.get('@microsoft.graph.downloadUrl', '')
        
        if not download_url:
            return jsonify({'error': 'No download URL available'}), 404
        
        # Download file from SharePoint
        file_response = requests.get(download_url, stream=True)
        
        if file_response.status_code != 200:
            return jsonify({'error': 'Failed to download file'}), file_response.status_code
        
        # Upload to Dropbox
        dbx = get_dropbox_client()
        if not dbx:
            return jsonify({'error': 'Dropbox not configured'}), 500
        
        dropbox_path = f"/{filename}" if not DROPBOX_FOLDER else f"{DROPBOX_FOLDER}/{filename}"
        
        # Upload file in chunks
        file_size = int(file_response.headers.get('Content-Length', 0))
        CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunks
        
        if file_size <= CHUNK_SIZE:
            # Small file - upload in one go
            dbx.files_upload(file_response.content, dropbox_path, mode=dropbox.files.WriteMode.overwrite)
        else:
            # Large file - use upload session
            upload_session = dbx.files_upload_session_start(b'')
            cursor = dropbox.files.UploadSessionCursor(upload_session.session_id, 0)
            commit = dropbox.files.CommitInfo(dropbox_path, mode=dropbox.files.WriteMode.overwrite)
            
            for chunk in file_response.iter_content(chunk_size=CHUNK_SIZE):
                if len(chunk) > 0:
                    dbx.files_upload_session_append_v2(chunk, cursor)
                    cursor.offset += len(chunk)
            
            dbx.files_upload_session_finish(b'', cursor, commit)
        
        return jsonify({
            'success': True,
            'message': f'File {filename} copied to Dropbox',
            'path': dropbox_path
        })
        
    except ApiError as e:
        return jsonify({'error': f'Dropbox error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/dropbox/delete', methods=['POST'])
@requires_auth
def dropbox_delete():
    """Delete file from Dropbox"""
    data = request.get_json()
    file_path = data.get('path')
    
    if not file_path:
        return jsonify({'error': 'Missing file path'}), 400
    
    try:
        dbx = get_dropbox_client()
        if not dbx:
            return jsonify({'error': 'Dropbox not configured'}), 500
        
        dbx.files_delete_v2(file_path)
        
        return jsonify({
            'success': True,
            'message': 'File deleted successfully'
        })
        
    except ApiError as e:
        return jsonify({'error': f'Dropbox error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/dropbox/link', methods=['POST'])
@requires_auth
def dropbox_link():
    """Generate direct download link for Dropbox file"""
    data = request.get_json()
    file_path = data.get('path')
    
    if not file_path:
        return jsonify({'error': 'Missing file path'}), 400
    
    try:
        dbx = get_dropbox_client()
        if not dbx:
            return jsonify({'error': 'Dropbox not configured'}), 500
        
        # Get temporary link (expires in 4 hours)
        temp_link = dbx.files_get_temporary_link(file_path)
        link_url = temp_link.link
        
        # Convert to direct download link
        # Change www.dropbox.com to dl.dropboxusercontent.com and remove ?dl=0
        direct_url = link_url.replace('www.dropbox.com', 'dl.dropboxusercontent.com').replace('?dl=0', '')
        
        return jsonify({
            'success': True,
            'link': direct_url,
            'sharing_link': link_url
        })
        
    except ApiError as e:
        return jsonify({'error': f'Dropbox error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
