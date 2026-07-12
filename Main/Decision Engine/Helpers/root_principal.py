# & "c:\Users\senag\Desktop\Decision Engine\.venv\bin\python.exe" .\Helpers\root_principal.py server 30101

import json
import platform
import sqlite3
import subprocess
import sys
from pathlib import Path

try:
    from setproctitle import setproctitle
    setproctitle("Oxsium:Decision Engine")
except ImportError:
    pass


PORT = 30101


def resolve_graph_engine_executable(base_dir) -> Path:
    base_path = Path(base_dir).resolve()
    engine_dir = base_path / "Engine"
    if platform.system().lower().startswith("win"):
        return engine_dir / "graph_engine.exe"
    return engine_dir / "graph_engine"


def find_domain_db(start_dir) -> Path:
    """Locate Domain Object/domain_data.db, searching `start_dir` itself and
    then walking up through its parent directories.

    Some deployments keep "Domain Object" *inside* the Decision Engine
    folder; others keep it as a sibling folder next to it
    (ParentFolder/Decision Engine + ParentFolder/Domain Object). This checks
    both layouts (and a few levels beyond) instead of assuming one of them,
    mirroring the same upward search graph_engine.cpp does for its root.
    """
    p = Path(start_dir).resolve()
    checked = []
    for _ in range(8):
        candidate = p / "Domain Object" / "domain_data.db"
        checked.append(candidate)
        if candidate.exists():
            return candidate
        if p.parent == p:
            break
        p = p.parent

    # Nothing found — return the most likely path (inside start_dir) so the
    # caller's "file not found" behaviour / logging still makes sense.
    return checked[0] if checked else Path(start_dir) / "Domain Object" / "domain_data.db"


# ─────────────────────────────────────────────────────────────────────────────
#  Read Database
# ─────────────────────────────────────────────────────────────────────────────

def get_root_principals(base_dir=None):
    if base_dir is None:
        base_dir = Path(__file__).resolve().parent.parent
    else:
        base_dir = Path(base_dir)

    db_file = find_domain_db(base_dir)

    result = {"users": [], "computers": [], "all": [], "sources": []}

    users_rows = _read_table(db_file, table="users", name_field="username")
    computers_rows = _read_table(db_file, table="computers", name_field="computer_name")

    result["users"] = users_rows
    result["computers"] = computers_rows
    result["all"] = sorted(set(
        [u["username"] for u in users_rows] +
        [c["computer_name"] for c in computers_rows]
    ))
    result["sources"] = [
        {
            "label": "Users",
            "file": str(db_file),
            "table": "users",
            "field": "username",
            "count": len(users_rows),
        },
        {
            "label": "Computers",
            "file": str(db_file),
            "table": "computers",
            "field": "computer_name",
            "count": len(computers_rows),
        },
    ]
    return result


def _read_table(db_path: Path, table: str, name_field: str) -> list:
    """Read every row of `table` from the SQLite DB and return a list of
    {name_field, sid, target_attributes} dicts, mirroring the shape the
    old JSON-file based helper used to hand back."""
    if not db_path.exists() or db_path.stat().st_size == 0:
        return []

    try:
        con = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        try:
            cur = con.cursor()
            cur.execute(f'SELECT * FROM "{table}"')
            rows = cur.fetchall()
        finally:
            con.close()

        out = []
        for row in rows:
            attrs = dict(row)
            name = str(attrs.get(name_field) or "").strip()
            sid = str(attrs.get("sid") or "").strip()
            if not name:
                continue
            out.append({name_field: name, "sid": sid, "target_attributes": attrs})
        return out
    except Exception as exc:
        print(f"[root_principal] {db_path.name} ({table}) read failed: {exc}", file=sys.stderr)
        return []

def start_api_server(port=PORT, host="localhost", base_dir=None):
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
        
        engine_exe = resolve_graph_engine_executable(actual_base)
        out_file = actual_base / "Engine" / "graph_objects.json"

        print(f"[Analyze] actual_base={actual_base}")
        print(f"[Analyze] platform={platform.system()}")
        print(f"[Analyze] engine_exe={engine_exe} exists={engine_exe.exists()}")
        print(f"[Analyze] out_file={out_file}")

        if not engine_exe.exists():
            print(f"[Analyze] Engine executable not found at {engine_exe}")
            expected_name = "graph_engine.exe" if platform.system().lower().startswith("win") else "graph_engine"
            return jsonify({"success": False, "error": f"Engine not found: {engine_exe} (expected {expected_name} for this OS)"}), 404

        cmd = [str(engine_exe), "-r", sid]
        if name:
            cmd += ["-n", name]
        
        # Use the native graph_engine flags instead of the old hop1-filter shim.
        cmd += ["--gpos"]
        cmd += ["--ous"]
        cmd += ["--trusts"]
        cmd += ["--kerberoasting"]
        cmd += ["--asrep"]
        cmd += ["--pwd-not-required"]
        cmd += ["--encryption"]
        cmd += ["--key-credential-link"]
        cmd += ["--managed-by"]
        cmd += ["--rbcd"]
        cmd += ["--member-of"]
        cmd += ["--unconstrained"]
        
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
    print(f"[Root Principal API] http://{host}:{port}  |  db: {find_domain_db(_base)}")
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
    parser.add_argument("-p", "--port", type=int, default=PORT, help="Port to listen on (default: 30101)")
    parser.add_argument("-i", "--ip-address", dest="ip_address", default="127.0.0.1",
                        help="IP address/interface to bind to (default: 127.0.0.1). Use 0.0.0.0 to expose on all interfaces.")
    args = parser.parse_args()

    if args.mode == "test":
        _test_mode(_base)
    else:
        start_api_server(port=args.port, host=args.ip_address, base_dir=_base)