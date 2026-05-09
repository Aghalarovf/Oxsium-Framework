# & "c:\Users\senag\Desktop\Decision Engine\.venv\bin\python.exe" .\Helpers\root_principal.py server 5000

import json
import subprocess
import sys
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
#  Read Database
# ─────────────────────────────────────────────────────────────────────────────

def get_root_principals(base_dir=None):
    if base_dir is None:
        base_dir = Path(__file__).resolve().parent.parent
    else:
        base_dir = Path(base_dir)

    db_dir         = base_dir / "Domain Object"
    users_file     = db_dir / "domain_users.json"
    computers_file = db_dir / "domain_computers.json"

    result = {"users": [], "computers": [], "all": [], "sources": []}
    result["users"] = _read_field(users_file, list_key="users", field="username")
    result["computers"] = _read_field(computers_file, list_key="computers", field="computer_name")
    result["all"] = sorted(set(result["users"] + result["computers"]))
    result["sources"] = [
        {
            "label": "Users",
            "file": "Domain Object/domain_users.json",
            "list_key": "users",
            "field": "username",
            "count": len(result["users"]),
        },
        {
            "label": "Computers",
            "file": "Domain Object/domain_computers.json",
            "list_key": "computers",
            "field": "computer_name",
            "count": len(result["computers"]),
        },
    ]
    return result


def _read_field(filepath: Path, list_key: str, field: str) -> list:
    if not filepath.exists() or filepath.stat().st_size == 0:
        return []
    try:
        raw  = json.loads(filepath.read_text(encoding="utf-8"))
        rows = raw.get(list_key) if isinstance(raw, dict) else []
        return [
            str(row[field]).strip()
            for row in (rows or [])
            if isinstance(row, dict) and row.get(field)
        ]
    except Exception as exc:
        print(f"[root_principal] {filepath.name} not found: {exc}", file=sys.stderr)
        return []

def start_api_server(port=5100, host="localhost", base_dir=None):
    try:
        from flask import Flask, jsonify, request
    except ImportError:
        print("Flask not found. Please install Flask to run the API server.")
        _test_mode(base_dir)
        return

    try:
        from flask_cors import CORS
        has_cors = True
    except ImportError:
        has_cors = False

    app = Flask(__name__)
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

    if has_cors:
        CORS(app)

    @app.after_request
    def add_cors_headers(response):
        response.headers.setdefault("Access-Control-Allow-Origin", "*")
        response.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        response.headers.setdefault("Access-Control-Max-Age", "3600")
        return response

    @app.route("/api/root-principals", methods=["GET", "OPTIONS"])
    def api_root_principals():

        if request.method == "OPTIONS":
            return ("", 204)

        data = get_root_principals(base_dir)
        resp = jsonify(data)
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"]        = "no-cache"
        resp.headers["Expires"]       = "0"
        return resp

    @app.route("/api/analyze-root", methods=["POST", "OPTIONS"])
    def api_analyze_root():
        if request.method == "OPTIONS":
            return ("", 204)

        body = request.get_json(silent=True) or {}
        sid = str(body.get("sid") or "").strip()
        name = str(body.get("name") or "").strip()
        if not sid:
            return jsonify({"success": False, "error": "Missing sid"}), 400

        # Use the base_dir from outer scope (start_api_server parameter), or resolve it
        actual_base = base_dir if base_dir else Path(__file__).resolve().parent.parent
        actual_base = Path(actual_base).resolve()  # Ensure it's absolute
        
        engine_exe = actual_base / "Engine" / "graph_engine.exe"
        out_file = actual_base / "Engine" / "graph_objects.json"

        print(f"[Analyze] actual_base={actual_base}")
        print(f"[Analyze] engine_exe={engine_exe} exists={engine_exe.exists()}")
        print(f"[Analyze] out_file={out_file}")

        if not engine_exe.exists():
            print(f"[Analyze] Engine executable not found at {engine_exe}")
            return jsonify({"success": False, "error": f"Engine not found: {engine_exe}"}), 404

        cmd = [str(engine_exe), "-r", sid]
        if name:
            cmd += ["-n", name]
        
        # Always add default Hop-1 filters for vulnerable users (with full paths)
        domain_obj_path = actual_base / "Domain Object" / "domain_users.json"
        cmd += ["--hop1-filter", str(domain_obj_path), "kerberoastable", "true"]
        cmd += ["--hop1-filter", str(domain_obj_path), "asrep", "true"]
        cmd += ["--hop1-filter", str(domain_obj_path), "pwd_not_required", "true"]
        
        cmd += ["--out", str(out_file)]

        print(f"[Analyze] Running engine command from cwd={actual_base}")
        print(f"[Analyze] Command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=str(actual_base),
            capture_output=True,
            text=True,
        )
        print(f"[Analyze] Engine returncode={result.returncode}")
        print(f"[Analyze] Engine stdout:\n{result.stdout}")
        print(f"[Analyze] Engine stderr:\n{result.stderr}")

        if result.returncode != 0:
            return jsonify({
                "success": False,
                "error": "Engine execution failed",
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }), 500

        try:
            output = json.loads(out_file.read_text(encoding="utf-8"))
        except Exception as exc:
            return jsonify({"success": False, "error": f"Failed to read output JSON: {exc}"}), 500

        response = jsonify({"success": True, "data": output})
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "root-principal-api"})

    _base = base_dir or Path(__file__).parent.parent
    print(f"[Root Principal API] http://{host}:{port}  |  db: {_base}/Domain Object")
    app.run(host=host, port=port, debug=False, use_reloader=False)


def _test_mode(base_dir):
    data = get_root_principals(base_dir)
    print(json.dumps(data, indent=2, ensure_ascii=False))


# ─────────────────────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    _base = Path(__file__).parent.parent

    parser = argparse.ArgumentParser(description="Root principal helper API")
    parser.add_argument("mode", nargs="?", choices=["server", "test"], default="server", help="Run mode: 'server' (default) or 'test'")
    parser.add_argument("-p", "--port", type=int, default=5100, help="Port to listen on (default: 5100)")
    parser.add_argument("-i", "--ip-address", dest="ip_address", default="127.0.0.1",
                        help="IP address/interface to bind to (default: 127.0.0.1). Use 0.0.0.0 to expose on all interfaces.")
    args = parser.parse_args()

    if args.mode == "test":
        _test_mode(_base)
    else:
        start_api_server(port=args.port, host=args.ip_address, base_dir=_base)