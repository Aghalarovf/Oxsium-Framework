#!/usr/bin/env python3
"""
Oxsium Certificate Service Flask API
Receives user credentials from GUI, runs template_enumeration.py, and returns results.

Port: 30102 (default; overridable with --port)
Endpoints:
  - POST /api/certificate/enumerate
  - POST /api/certificate/saved-users
  - GET /api/certificate/saved-users
"""

import os
import sys
import json
import subprocess
import re
import time
from pathlib import Path
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

try:
    from setproctitle import setproctitle
    setproctitle("Oxsium:AD CS Enumeration")
except ImportError:
    pass

# ── Configuration ──────────────────────────────────────────────────────────

DEFAULT_PORT = int(os.getenv("PORT", "30102"))

app = Flask(__name__)
CORS(app)

CERT_SERVICE_MODULES_DIR = Path(__file__).parent / "Modules"
TEMPLATE_ENUMERATION_SCRIPT = CERT_SERVICE_MODULES_DIR / "template_enumeration.py"
SAVED_USERS_DB = Path(__file__).parent / "saved_users.json"

# Timeout tracking (10 seconds between enumerations)
ENUMERATE_TIMEOUT = 10  # seconds
last_enumeration_time = [0]  # Use list to allow modification in nested scope

# Ensure paths exist
CERT_SERVICE_MODULES_DIR.mkdir(parents=True, exist_ok=True)
SAVED_USERS_DB.parent.mkdir(parents=True, exist_ok=True)


# ── Helpers ────────────────────────────────────────────────────────────────

def load_saved_users():
    """Load saved users from JSON database."""
    if SAVED_USERS_DB.exists():
        try:
            with open(SAVED_USERS_DB, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading saved users: {e}")
            return []
    return []


def save_users_to_db(users):
    """Save users list to JSON database."""
    try:
        with open(SAVED_USERS_DB, 'w', encoding='utf-8') as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[!] Error saving users: {e}")
        return False


def persist_user(payload):
    """Add or update user in saved users database."""
    users = load_saved_users()
    
    # Check if user already exists (by username + domain)
    user_key = (payload.get('username'), payload.get('domain'))
    existing = next((u for u in users if (u.get('username'), u.get('domain')) == user_key), None)
    
    new_user_entry = {
        'domain': payload.get('domain', ''),
        'name_server': payload.get('name_server', ''),
        'username': payload.get('username', ''),
        'password': payload.get('password', ''),
        'saved_at': datetime.now().isoformat(),
    }
    
    if existing:
        # Update existing entry
        idx = users.index(existing)
        users[idx] = new_user_entry
    else:
        # Add new entry
        users.append(new_user_entry)
    
    save_users_to_db(users)
    return new_user_entry


def extract_ip_from_nameserver(name_server):
    """Extract IP address from Name Server field.
    
    Accepts formats:
    - "10.10.0.12"
    - "10.10.0.12\OXSIUM-CA"
    - "10.10.0.12/OXSIUM-CA"
    """
    if not name_server:
        return None
    
    # Remove any domain\hostname suffix
    ip_part = name_server.split('\\')[0].split('/')[0]
    
    # Validate IP format (simple regex)
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(ip_pattern, ip_part):
        return ip_part
    
    return ip_part  # Return as-is if not recognized


def run_template_enumeration(dc_ip, username, domain, password):
    """Execute template_enumeration.py and return oxs_cert JSON file path."""
    if not TEMPLATE_ENUMERATION_SCRIPT.exists():
        return None, f"template_enumeration.py not found at {TEMPLATE_ENUMERATION_SCRIPT}"
    
    try:
        # Build command
        cmd = [
            sys.executable,
            str(TEMPLATE_ENUMERATION_SCRIPT),
            '-dc-ip', dc_ip,
            '-u', username,
            '-p', password,
            '-domain', domain,
            '-v',  # verbose
            '-q',  # quiet mode: suppress banner/box-drawing chars (avoids cp1252 errors)
        ]
        
        print(f"[*] Running: {' '.join(cmd)}")
        
        # PYTHONUTF8=1 forces UTF-8 output inside the child process.
        # text=False + manual decode avoids Windows cp1252 UnicodeDecodeError
        # in the parent _readerthread (Python 3.13 threading.py).
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"

        # Execute with timeout — read raw bytes, decode manually
        result = subprocess.run(
            cmd,
            cwd=str(CERT_SERVICE_MODULES_DIR),
            capture_output=True,
            text=False,          # raw bytes — no codec involved during read
            timeout=60,
            env=env,
        )

        stdout_str = result.stdout.decode('utf-8', errors='replace') if result.stdout else ''
        stderr_str = result.stderr.decode('utf-8', errors='replace') if result.stderr else ''

        print(f"[*] Return code: {result.returncode}")
        if stdout_str:
            print(f"[*] STDOUT:\n{stdout_str}")
        if stderr_str:
            print(f"[*] STDERR:\n{stderr_str}")

        if result.returncode != 0:
            return None, f"template_enumeration.py failed: {stderr_str}"
        
        # Find the generated oxs_cert_*.json file
        oxs_files = list(CERT_SERVICE_MODULES_DIR.glob("oxs_cert_*.json"))
        if not oxs_files:
            return None, "No oxs_cert_*.json file generated"
        
        # Get the most recently modified file
        latest_file = max(oxs_files, key=lambda p: p.stat().st_mtime)
        return latest_file, None
        
    except subprocess.TimeoutExpired:
        return None, "template_enumeration.py timed out (60s limit)"
    except Exception as e:
        return None, f"Error executing template_enumeration.py: {str(e)}"


def read_oxs_cert_json(file_path):
    """Read and parse oxs_cert JSON report."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        return None, f"Error reading report: {str(e)}"


# ── API Endpoints ──────────────────────────────────────────────────────────

@app.route('/api/certificate/enumerate', methods=['POST'])
def api_enumerate_templates():
    """
    Enumerate certificate templates from domain controller.
    
    Request body:
    {
      "domain": "corp.local",
      "name_server": "10.10.0.12" or "10.10.0.12\OXSIUM-CA",
      "username": "DOMAIN\\username",
      "password": "Password123!"
    }
    
    Response:
    {
      "status": "connected",
      "report_id": "ABC12345",
      "esc_findings": [
        { "esc_type": "ESC1", "description": "..." },
        ...
      ],
      "templates": [...],
      "pki_objects": [...]
    }
    """
    global last_enumeration_time
    
    # Check timeout: must wait 10 seconds between enumerations
    current_time = time.time()
    time_since_last = current_time - last_enumeration_time[0]
    print(f"[DEBUG] Timeout check: last={last_enumeration_time[0]:.2f}, current={current_time:.2f}, diff={time_since_last:.2f}s, limit={ENUMERATE_TIMEOUT}s")
    if time_since_last < ENUMERATE_TIMEOUT:
        wait_time = ENUMERATE_TIMEOUT - time_since_last
        print(f"[!] Timeout triggered: wait {wait_time:.1f}s")
        return jsonify({
            'status': 'error',
            'error': f'Enumeration throttled. Wait {wait_time:.1f}s before next attempt.',
            'retry_after': int(wait_time) + 1
        }), 429
    
    payload = request.get_json() or {}
    
    domain = payload.get('domain', '').strip()
    name_server = payload.get('name_server', '').strip()
    username = payload.get('username', '').strip()
    password = payload.get('password', '').strip()
    
    # Validate input
    if not all([domain, name_server, username, password]):
        return jsonify({
            'status': 'error',
            'error': 'Missing required fields: domain, name_server, username, password'
        }), 400
    
    # Extract IP from name_server field
    dc_ip = extract_ip_from_nameserver(name_server)
    if not dc_ip:
        return jsonify({
            'status': 'error',
            'error': f'Invalid Name Server format: {name_server}'
        }), 400
    
    print(f"\n[*] Enumerate request: domain={domain}, dc_ip={dc_ip}, user={username}")
    
    # Persist user for "Load" button
    persist_user(payload)
    
    # Run template enumeration
    report_file, error = run_template_enumeration(dc_ip, username, domain, password)
    
    if error:
        return jsonify({
            'status': 'error',
            'error': error
        }), 500
    
    # Update last enumeration time (on success)
    last_enumeration_time[0] = time.time()
    print(f"[+] Timeout updated to: {last_enumeration_time[0]:.2f}")
    
    # Read the generated report
    report = read_oxs_cert_json(report_file)
    if isinstance(report, tuple):  # Error case
        return jsonify({
            'status': 'error',
            'error': report[1]
        }), 500
    
    report_id = report.get('report_id', 'UNKNOWN')
    
    # For now, assume no ESC findings (these would come from esc1.py, esc2.py, etc.)
    # In future, integrate ESC analysis modules
    esc_findings = []
    
    return jsonify({
        'status': 'connected',
        'report_id': report_id,
        'esc_findings': esc_findings,
        'templates': report.get('templates', []),
        'pki_objects': report.get('pki_objects', []),
        'summary': report.get('summary', {}),
    }), 200


@app.route('/api/certificate/saved-users', methods=['GET'])
def api_get_saved_users():
    """Retrieve saved users list."""
    users = load_saved_users()
    return jsonify({
        'status': 'ok',
        'saved_users': users
    }), 200


@app.route('/api/certificate/saved-users', methods=['POST'])
def api_save_user():
    """Save a new user entry."""
    payload = request.get_json() or {}
    persist_user(payload)
    return jsonify({
        'status': 'ok',
        'message': 'User saved'
    }), 200


@app.route('/api/esc1', methods=['POST'])
def api_esc1_check():
    """
    ESC1 exploit/check endpoint (placeholder for future integration).
    """
    payload = request.get_json() or {}
    
    # For now, return mock data
    # In future, integrate with esc1.py module
    return jsonify({
        'status': 'connected',
        'esc_findings': [],
        'message': 'ESC1 check not yet fully implemented'
    }), 200


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'service': 'Oxsium Certificate API',
        'port': DEFAULT_PORT
    }), 200


# ── Error Handlers ────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'status': 'error',
        'error': 'Endpoint not found'
    }), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({
        'status': 'error',
        'error': 'Internal server error'
    }), 500


# ── Main ──────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Oxsium Certificate Service API")
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT,
                         help=f"Bind port (default: {DEFAULT_PORT})")
    parser.add_argument('--host', default='127.0.0.1', help="Bind host (default: 127.0.0.1)")
    args = parser.parse_args()

    print(f"[*] Oxsium Certificate Service API starting on http://{args.host}:{args.port}")
    print(f"[*] Modules directory: {CERT_SERVICE_MODULES_DIR}")
    print(f"[*] Saved users DB: {SAVED_USERS_DB}")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)