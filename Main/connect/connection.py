import os
import sys
import json
import re
import time
import zipfile
import io
import threading
import subprocess
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

# ── sys.path setup: Add Main directory to path ───────────────────────────────────
_PROJECT_ROOT = Path(__file__).parent.parent  # /Main
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Config import ────────────────────────────────────────────────────────────────
from connect.config import Config, logger

# ── Read paths from Config ───────────────────────────────────────────────────────
PROJECT_ROOT = Config.PROJECT_ROOT
DOMAIN_OBJECT_DIR = Config.DOMAIN_OBJECT_DIR
DOMAIN_ACES_PARQUET = Config.DOMAIN_ACES_PARQUET
DOMAIN_ACES_JSON = Config.DOMAIN_ACES_JSON
DOMAIN_EXTENDED_RIGHTS_JSON = Config.DOMAIN_EXTENDED_RIGHTS_JSON
DOMAIN_DANGEROUS_ACE_JSON = Config.DOMAIN_DANGEROUS_ACE_JSON
DOMAIN_USERS_JSON = Config.DOMAIN_USERS_JSON
DOMAIN_COMPUTERS_JSON = Config.DOMAIN_COMPUTERS_JSON
DOMAIN_GROUPS_JSON = Config.DOMAIN_GROUPS_JSON

# Legacy paths (backward compatibility)
LEGACY_DOMAIN_USERS_JSON = Path(PROJECT_ROOT) / "domain_users.json"
LEGACY_DOMAIN_COMPUTERS_JSON = Path(PROJECT_ROOT) / "domain_computers.json"
LEGACY_DOMAIN_OUS_JSON = Path(PROJECT_ROOT) / "domain_ous.json"
LEGACY_DOMAIN_GROUPS_JSON = Path(PROJECT_ROOT) / "domain_groups.json"
LEGACY_DOMAIN_TRUSTS_JSON = Path(PROJECT_ROOT) / "domain_trusts.json"
LEGACY_DOMAIN_GPOS_JSON = Path(PROJECT_ROOT) / "domain_gpos.json"
LEGACY_DOMAIN_ACES_JSON = Path(PROJECT_ROOT) / "domain_aces.json"

# -- SQLite Engine -- subprocess icra (SQLite Engine/sqlite_engine.py) --
# sqlite_engine.py birbaşa subprocess kimi çağırılır:
#   python sqlite_engine.py <DOMAIN_OBJECT_DIR> --output <db_path> --quiet
_SQLITE_ENGINE_CANDIDATES = [
    Path(__file__).parent.parent / 'SQLite Engine' / 'sqlite_engine.py',  # canonical
    Path(__file__).parent / 'SQLite Engine' / 'sqlite_engine.py',         # fallback
    Path(__file__).parent / 'sqlite_engine.py',                            # fallback
]
_SQLITE_ENGINE_PATH = next((p for p in _SQLITE_ENGINE_CANDIDATES if p.exists()), None)

if _SQLITE_ENGINE_PATH is None:
    logger.warning('sqlite_engine not found -- searched: %s',
                   ', '.join(str(p) for p in _SQLITE_ENGINE_CANDIDATES))
else:
    logger.info('sqlite_engine found: %s', _SQLITE_ENGINE_PATH)

# -- Debounced DB builder --
# Snapshots arrive in quick succession; run the engine once, 3 seconds after the last write.
_db_build_timer: threading.Timer | None = None
_db_build_lock  = threading.Lock()
_DB_BUILD_DELAY = 3.0


def _run_sqlite_engine() -> None:
    """sqlite_engine.py-ni subprocess kimi icra edir.

    QEYD: sqlite_reader.py (port 8800) burada artıq AVTOMATİK başladılmır.
    domain_data.db tikildikdən sonra sqlite_reader.py-nin işə salınması
    manual/əl ilə həyata keçirilir (məs. ayrıca terminal/prosesdən:
    `python sqlite_reader.py <db_yolu> --port 8800`)."""
    if _SQLITE_ENGINE_PATH is None:
        logger.warning('sqlite_engine module not available -- DB build skipped')
        return
    db_out = DOMAIN_OBJECT_DIR / 'domain_data.db'
    try:
        result = subprocess.run(
            [sys.executable, str(_SQLITE_ENGINE_PATH),
             str(DOMAIN_OBJECT_DIR),
             '--output', str(db_out),
             '--quiet'],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            logger.info('sqlite_engine: DB created -> %s', db_out)
        else:
            logger.warning('sqlite_engine exited %d: %s',
                           result.returncode, result.stderr.strip())
    except Exception as exc:
        logger.warning('sqlite_engine error: %s', exc)


def _schedule_db_build() -> None:
    """Debounced DB build -- called after a snapshot is written."""
    global _db_build_timer
    with _db_build_lock:
        if _db_build_timer is not None:
            _db_build_timer.cancel()
        _db_build_timer = threading.Timer(_DB_BUILD_DELAY, _run_sqlite_engine)
        _db_build_timer.daemon = True
        _db_build_timer.start()


# -- SQLite Reader -- ayrıca, müstəqil bir Flask prosesi (domain_data.db-ni
# HTTP üzərindən salt-oxuma rejimində serverə qoyur). Bu proses connection.py
# tərəfindən AVTOMATİK başladılmır -- sqlite_reader.py manual olaraq əl ilə
# (məs. ayrıca terminal/prosesdən) işə salınmalıdır:
#   python sqlite_reader.py <domain_data.db yolu> --port 30104
SQLITE_READER_HOST = "127.0.0.1"
SQLITE_READER_PORT = int(os.getenv("SQLITE_READER_PORT", 30104))
SQLITE_READER_BASE = f"http://{SQLITE_READER_HOST}:{SQLITE_READER_PORT}"


from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from setproctitle import setproctitle
    setproctitle("Oxsium:LDAP Engine")
except ImportError:
    pass

# ── Main package imports ──────────────────────────────────────────────────────────
from user import users_dump as users
from computer import computers
from group import groups
from ou import ous
from gpo import gpos
from trust import trusts
from dominfo import get_domain_info
from acl import AclFilterConfig, get_domain_acls
from acl.constants import _DEFAULT_TRUSTEE_RIDS, _DEFAULT_TRUSTEE_SIDS

# ── Connect package imports ───────────────────────────────────────────────────────
from connect.utils         import validate_ip, validate_domain, validate_username
from connect.network       import _tcp_probe, check_port
from connect.ldap_core     import (
    _collect_ldap_environment_with_fallback,
    _collect_counts_via_enumeration_fallback,
    _run_enumeration_with_target_fallback,
)
from connect.protocols     import connect_ldap_fast, connect_local, PROTOCOL_HANDLERS
from connect.shell         import (
    run_local_command,
    _collect_powershell_profile, _apply_powershell_profile,
)
from connect.tools         import run_local_inventory_c_tool, run_smb_checker_tool, run_ntlm_checker_tool, run_kerberos_checker_tool, run_simple_protocol_probe, SIMPLE_PROTOCOL_CHECKERS
from connect.saved_users   import _read_old_users, _write_old_users
from connect.flask_helpers import (
    require_json_fields, is_local_request, get_enumeration_request_data,
)
from connect.connection_fast import run_connect_strategy
from connect.connection_deep import apply_deep_defaults, enrich_with_env_probe
from connect.dcsync        import _read_dcsync_history, run_dcsync_tool, save_kerberos_key



def _probe_ldap_ports(ip: str, timeout: float = 4.0) -> list[dict]:
    ports = []
    for port in (389, 636):
        result = _tcp_probe(ip, port, timeout)
        ports.append({"port": port, "result": result, "port_open": result == "open"})
    return ports


def _ldap_ports_refused(ports: list[dict]) -> bool:
    return bool(ports) and all(port_info.get("result") == "closed" for port_info in ports)



# ---------------------------------------------------------------------------
# Flask app setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(
    app,
    resources={r"/api/*": {"origins": "*"}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"],
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["10000 per day", "1000 per hour"],
    storage_uri=os.getenv("REDIS_URL", "memory://"),
)


# ---------------------------------------------------------------------------
# Helper: normalise enumeration response status codes
# ---------------------------------------------------------------------------

def _enumeration_status(result: dict) -> int:
    status = result.get("code", 500)
    if status not in (400, 401, 403, 404, 500, 503):
        status = 500
    return status


def _local_enumeration_removed(feature: str) -> dict:
    return {
        "success": False,
        "error": f"{feature} enumeration has been removed",
        "code": 400,
    }


def build_decision_graph_snapshot(*, domain_object_dir, project_root, current_user, current_sid, current_type) -> dict:
    return {
        "success": False,
        "error": "Decision graph snapshot builder is unavailable in this workspace",
        "code": 503,
        "domain_object_dir": str(domain_object_dir),
        "project_root": str(project_root),
        "current_user": current_user,
        "current_sid": current_sid,
        "current_type": current_type,
    }


def _is_default_trustee(sid: str) -> bool:
    sid = str(sid or "")
    return sid in _DEFAULT_TRUSTEE_SIDS or any(sid.endswith(rid) for rid in _DEFAULT_TRUSTEE_RIDS)


def _write_domain_users_snapshot(result: dict, is_local: bool) -> None:
    """
    Overwrite domain_users.jsonl on every /api/users request.
    Format: line 1 = metadata, lines 2+ = one user record per line.
    """
    out_path = DOMAIN_OBJECT_DIR / "domain_users.jsonl"

    meta_line = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": "local" if is_local else "domain",
        "success": bool(result.get("success")),
        "count": int(result.get("count") or 0),
        "meta": result.get("meta") or {},
        "error": result.get("error") if not result.get("success") else None,
    }
    users_list = list(result.get("users") or [])

    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)
        _write_acl_jsonl_snapshot(out_path, meta_line, users_list)

        # Remove old JSON-format snapshot if present.
        old_json = DOMAIN_OBJECT_DIR / "domain_users.json"
        if old_json.exists() and old_json != out_path:
            try:
                old_json.unlink()
            except Exception as exc:
                logger.warning("Could not remove old users JSON snapshot %s: %s", old_json, exc)

        # Remove old legacy file in repo root so consumers use a single source.
        if LEGACY_DOMAIN_USERS_JSON.exists() and LEGACY_DOMAIN_USERS_JSON != out_path:
            try:
                LEGACY_DOMAIN_USERS_JSON.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy users snapshot %s: %s", LEGACY_DOMAIN_USERS_JSON, exc)
    except Exception as exc:
        logger.warning("Could not write domain users JSONL snapshot to %s: %s", out_path, exc)
    else:
        _schedule_db_build()  # Snapshot written -- trigger DB build with debounce


def _write_domain_users_proto_snapshot(result: dict, output_path: Path) -> None:
    """
    Best-effort protobuf snapshot writer used when the enumerator didn't write it.
    """
    try:
        from proto_bridge import save_payload as _save_payload
    except Exception as exc:
        logger.warning("Protobuf snapshot writer unavailable, skip %s: %s", output_path, exc)
        return

    try:
        _save_payload(result, str(output_path))
    except Exception as exc:
        logger.warning("Could not write protobuf users snapshot to %s: %s", output_path, exc)


def _write_domain_object_snapshot(
    *,
    filename: str,
    result: dict,
    is_local: bool,
    data_key: str,
    legacy_path: Path | None = None,
) -> None:
    """
    Generic Domain Object snapshot writer — JSONL format.

    Line 1: metadata (generated_at, source, success, count, meta, error).
    Lines 2+: one record per line (groups / ous / trusts / …).

    Uses overwrite semantics on every request so stale context is cleared.
    """
    # Always write to .jsonl regardless of what filename says
    jsonl_filename = Path(filename).with_suffix(".jsonl").name
    out_path = DOMAIN_OBJECT_DIR / jsonl_filename

    meta_line = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": "local" if is_local else "domain",
        "success": bool(result.get("success")),
        "count": int(result.get("count") or 0),
        "meta": result.get("meta") or {},
        "error": result.get("error") if not result.get("success") else None,
    }
    records = list(result.get(data_key) or [])

    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)
        _write_acl_jsonl_snapshot(out_path, meta_line, records)

        # Remove old .json-format snapshot if it still exists alongside the new .jsonl.
        old_json = DOMAIN_OBJECT_DIR / filename
        if old_json.exists() and old_json != out_path:
            try:
                old_json.unlink()
            except Exception as exc:
                logger.warning("Could not remove old JSON snapshot %s: %s", old_json, exc)

        if legacy_path and legacy_path.exists() and legacy_path != out_path:
            try:
                legacy_path.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy snapshot %s: %s", legacy_path, exc)
    except Exception as exc:
        logger.warning("Could not write domain JSONL snapshot to %s: %s", out_path, exc)
    else:
        _schedule_db_build()  # Snapshot written -- trigger DB build with debounce


# ---------------------------------------------------------------------------
# Computers snapshots are stored in JSONL format:
#   - Line 1: metadata object (generated_at, source, success, count, meta, ...)
#   - Subsequent lines: one computer record per line (JSON object)
# This allows large computer lists to be read/written line by line.
# ---------------------------------------------------------------------------

def _write_domain_computers_jsonl_snapshot(result: dict, is_local: bool) -> None:
    """
    Write domain computers to domain_computers.jsonl.

    Format:
      - Line 1: metadata (generated_at, source, success, count, error, meta)
      - Lines 2+: one JSON object per computer record

    Overwrites the previous snapshot on every enumeration so stale data is
    cleared automatically.
    """
    out_path = _jsonl_snapshot_path(DOMAIN_COMPUTERS_JSON)
    computers_list = list(result.get("computers") or [])

    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)

        generated_at = datetime.utcnow().isoformat() + "Z"
        source = "local" if is_local else "domain"
        success = bool(result.get("success"))
        count = int(result.get("count") or 0)
        error = result.get("error") if not success else None

        meta_line = {
            "generated_at": generated_at,
            "source": source,
            "success": success,
            "count": count,
            "error": error,
            "meta": result.get("meta") or {},
        }

        _write_acl_jsonl_snapshot(out_path, meta_line, computers_list)

        # Remove old JSON-format snapshot — JSONL is now the source of truth.
        if DOMAIN_COMPUTERS_JSON.exists() and DOMAIN_COMPUTERS_JSON != out_path:
            try:
                DOMAIN_COMPUTERS_JSON.unlink()
            except Exception as exc:
                logger.warning(
                    "Could not remove legacy computers JSON snapshot %s: %s",
                    DOMAIN_COMPUTERS_JSON, exc,
                )

        # Remove legacy root-level snapshot.
        if LEGACY_DOMAIN_COMPUTERS_JSON.exists() and LEGACY_DOMAIN_COMPUTERS_JSON != out_path:
            try:
                LEGACY_DOMAIN_COMPUTERS_JSON.unlink()
            except Exception as exc:
                logger.warning(
                    "Could not remove legacy computers snapshot %s: %s",
                    LEGACY_DOMAIN_COMPUTERS_JSON, exc,
                )
    except Exception as exc:
        logger.warning("Could not write domain computers JSONL snapshot to %s: %s", out_path, exc)


def _write_domain_info_jsonl_snapshot(result: dict, is_local: bool) -> None:
    """
    Write domain_info.jsonl as a single domain-level record.

    Line 1 is the file metadata envelope, line 2 is the actual domain info row.
    """
    out_path = DOMAIN_OBJECT_DIR / "domain_info.jsonl"
    record = dict(result)

    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)

        meta_line = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source": "local" if is_local else "domain",
            "success": bool(result.get("success")),
            "count": int(result.get("count") or 0),
            "error": result.get("error") if not result.get("success") else None,
            "meta": result.get("meta") or {},
        }

        _write_acl_jsonl_snapshot(out_path, meta_line, [record])

        legacy_json = DOMAIN_OBJECT_DIR / "domain_info.json"
        if legacy_json.exists() and legacy_json != out_path:
            try:
                legacy_json.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy domain info JSON snapshot %s: %s", legacy_json, exc)
    except Exception as exc:
        logger.warning("Could not write domain info JSONL snapshot to %s: %s", out_path, exc)
    else:
        _schedule_db_build()


def _read_domain_computers_jsonl_snapshot() -> dict:
    """
    Read domain computers from domain_computers.jsonl.

    Returns a dict compatible with the standard enumeration result shape:
      {"success": bool, "count": int, "computers": [...], "meta": {...}}
    """
    in_path = _jsonl_snapshot_path(DOMAIN_COMPUTERS_JSON)
    if not in_path.exists():
        return {
            "success": False,
            "error": f"Computers snapshot not found: {in_path}",
            "code": 404,
        }

    try:
        meta_line, rows = _read_acl_jsonl_snapshot(in_path)
        computers_list = [dict(r) for r in rows if isinstance(r, dict)]
        return {
            "success": meta_line.get("success", True),
            "count": meta_line.get("count", len(computers_list)),
            "computers": computers_list,
            "meta": {
                **( meta_line.get("meta") or {} ),
                "snapshot_type": "computers-jsonl",
                "snapshot_path": str(in_path),
                "generated_at": meta_line.get("generated_at"),
                "source": meta_line.get("source"),
            },
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Could not read computers JSONL snapshot: {exc}",
            "code": 500,
        }


# ---------------------------------------------------------------------------
# ACL snapshots are stored in JSONL format:
#   - Line 1: metadata object (generated_at, source, success, count, meta, ...)
#   - Subsequent lines: one ACL record per line (JSON object)
# This allows large ACL lists to be read/written line by line.
# ---------------------------------------------------------------------------

def _jsonl_snapshot_path(json_path: Path) -> Path:
    """Convert a .json path to .jsonl for ACL snapshots."""
    return json_path.with_suffix(".jsonl")


def _write_acl_jsonl_snapshot(out_path: Path, meta_line: dict, records: list[dict]) -> None:
    """Write a JSONL ACL snapshot: first line is metadata, the rest are records."""
    lines = [json.dumps(meta_line, ensure_ascii=False, default=str)]
    lines.extend(json.dumps(r, ensure_ascii=False, default=str) for r in records)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _read_acl_jsonl_snapshot(in_path: Path) -> tuple[dict, list[dict]]:
    """Read a JSONL ACL snapshot, return (metadata, records)."""
    text = in_path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return {}, []
    meta_line = json.loads(lines[0])
    if not isinstance(meta_line, dict):
        meta_line = {}
    records = [json.loads(ln) for ln in lines[1:]]
    return meta_line, records


def _write_domain_aces_snapshot(result: dict, is_local: bool) -> None:
    """
    Write ACL findings to domain_aces.jsonl for human-readable storage.

    On every enumeration run this overwrites the previous JSONL snapshot so stale
    context is cleared automatically.
    """
    out_path = _jsonl_snapshot_path(DOMAIN_ACES_JSON)
    aces = list(result.get("acls") or result.get("aces") or [])

    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)

        generated_at = datetime.utcnow().isoformat() + "Z"
        source = "local" if is_local else "domain"
        success = bool(result.get("success"))
        count = int(result.get("count") or 0)
        error = result.get("error") if not success else None

        meta_line = {
            "generated_at": generated_at,
            "source": source,
            "success": success,
            "count": count,
            "error": error,
            "meta": result.get("meta") or {},
        }

        _write_acl_jsonl_snapshot(out_path, meta_line, aces)

        # Remove old parquet snapshot if it exists.
        if DOMAIN_ACES_PARQUET.exists():
            try:
                DOMAIN_ACES_PARQUET.unlink()
            except Exception as exc:
                logger.warning("Could not remove old ACL parquet snapshot %s: %s", DOMAIN_ACES_PARQUET, exc)

        # Remove the old JSON-format snapshot now that JSONL is the source of truth.
        if DOMAIN_ACES_JSON.exists() and DOMAIN_ACES_JSON != out_path:
            try:
                DOMAIN_ACES_JSON.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy ACL JSON snapshot %s: %s", DOMAIN_ACES_JSON, exc)

        if LEGACY_DOMAIN_ACES_JSON.exists() and LEGACY_DOMAIN_ACES_JSON != out_path:
            try:
                LEGACY_DOMAIN_ACES_JSON.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy ACL snapshot %s: %s", LEGACY_DOMAIN_ACES_JSON, exc)
    except Exception as exc:
        logger.warning("Could not write domain ACL JSONL snapshot to %s: %s", out_path, exc)


def _normalize_object_ace_type_value(value) -> str:
    text = str(value or "").strip()
    if not text or text.lower() == "none":
        return ""
    if text == "00000000-0000-0000-0000-000000000000":
        return ""
    return text


def _canonical_right_name(value) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def _acl_rights_keys(row: dict) -> set[str]:
    out: set[str] = set()
    rights = row.get("rights")
    if isinstance(rights, (list, tuple, set)):
        for right in rights:
            key = _canonical_right_name(right)
            if key:
                out.add(key)

    rights_display = row.get("rights_display")
    if isinstance(rights_display, str):
        for chunk in re.split(r"[,;|]", rights_display):
            key = _canonical_right_name(chunk)
            if key:
                out.add(key)
    elif isinstance(rights_display, (list, tuple, set)):
        for right in rights_display:
            key = _canonical_right_name(right)
            if key:
                out.add(key)
    return out


def _dangerous_has_interesting_right(rights: set[str]) -> bool:
    if not rights:
        return False

    explicit = {
        "genericall",
        "genericwrite",
        "writedacl",
        "writeowner",
        "writeproperty",
        "createchild",
        "deletechild",
        "delete",
        "addmember",
        "forcechangepassword",
        "userforcechangepassword",
        "changepassword",
        "dsreplicationgetchanges",
        "dsreplicationgetchangesall",
        "dsreplicationgetchangesinfilteredset",
        "dsreplicationmanagetopology",
        "dsreplicationsynchronize",
        "selfmembership",
        "writemsdskeycredential",
        "writemsdskeycredentiallink",
    }

    if any(r in explicit for r in rights):
        return True
    blob = " ".join(sorted(rights))
    return any(token in blob for token in ("generic", "write", "create", "delete", "replication"))


_DANGEROUS_EXCL_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-32-544"}
_DANGEROUS_EXCL_RIDS = {500, 502, 512, 516, 519, 520, 526, 527}
_DOMAIN_RID_RE = re.compile(r"^S-1-5-21(?:-\d+){3}-(\d+)$")
_PV_INTERESTING_SID_RE = re.compile(r"^S-1-5-.*-[1-9]\d{3,}$")


def _dangerous_is_excluded_sid(sid: str) -> bool:
    sid = str(sid or "").strip()
    if not sid:
        return True
    if sid in _DANGEROUS_EXCL_SIDS:
        return True
    match = _DOMAIN_RID_RE.match(sid)
    if match and int(match.group(1)) in _DANGEROUS_EXCL_RIDS:
        return True
    return False


def _dangerous_sid_is_interesting(sid: str) -> bool:
    return bool(_PV_INTERESTING_SID_RE.match(str(sid or "").strip()))


def _extract_dangerous_rows(result: dict) -> list[dict]:
    rows: list[dict] = []
    aces = list(result.get("acls") or result.get("aces") or [])
    for ace in aces:
        if not isinstance(ace, dict):
            continue

        sid = str(ace.get("principal_sid") or "").strip()
        disabled = bool(ace.get("principal_is_disabled"))

        # If principal is disabled, include their ACEs regardless of SID filters
        if not disabled:
            if not _dangerous_sid_is_interesting(sid):
                continue
            if _dangerous_is_excluded_sid(sid):
                continue

        rights = _acl_rights_keys(ace)
        if not _dangerous_has_interesting_right(rights):
            continue

        # Ignore non-actionable entries where only ReadProperty/Self-like rights exist.
        if rights and rights.issubset({"readproperty", "self"}):
            continue

        rows.append(dict(ace))
    return rows


def _write_domain_dangerous_ace_snapshot(result: dict, is_local: bool) -> None:
    """Write dangerous ACE subset to domain_dangerous_ace.jsonl for fast reuse."""
    out_path = _jsonl_snapshot_path(DOMAIN_DANGEROUS_ACE_JSON)
    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)

        generated_at = datetime.utcnow().isoformat() + "Z"
        source = "local" if is_local else "domain"
        success = bool(result.get("success"))
        count = int(result.get("count") or 0)
        error = result.get("error") if not success else None
        rows = _extract_dangerous_rows(result) if success else []

        # Filter out default trustee ACEs so snapshots don't contain
        # built-in/default system trustees (e.g. SYSTEM, Administrators).
        try:
            rows = [r for r in rows if not _is_default_trustee(str(r.get("principal_sid") or ""))]
        except Exception:
            # If the helper is unavailable for any reason, fall back to original rows.
            pass

        meta_line = {
            "success": True,
            "count": len(rows),
            "meta": {
                "generated_at": generated_at,
                "source": source,
                "snapshot_type": "dangerous-ace-jsonl",
                "snapshot_path": str(out_path),
                "snapshot_success": success,
                "snapshot_count": count,
                "snapshot_error": error,
                "snapshot_rows": len(rows),
            },
        }

        _write_acl_jsonl_snapshot(out_path, meta_line, rows)

        # Remove the old JSON-format snapshot now that JSONL is the source of truth.
        if DOMAIN_DANGEROUS_ACE_JSON.exists() and DOMAIN_DANGEROUS_ACE_JSON != out_path:
            try:
                DOMAIN_DANGEROUS_ACE_JSON.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy dangerous ACE snapshot %s: %s", DOMAIN_DANGEROUS_ACE_JSON, exc)
    except Exception as exc:
        logger.warning("Could not write dangerous ACE snapshot to %s: %s", out_path, exc)


def _read_domain_dangerous_ace_snapshot() -> dict:
    """Read dangerous ACE subset from domain_dangerous_ace.jsonl."""
    in_path = _jsonl_snapshot_path(DOMAIN_DANGEROUS_ACE_JSON)
    if not in_path.exists():
        return {
            "success": False,
            "error": f"ACL snapshot not found: {in_path}",
            "code": 404,
        }

    try:
        meta_line, rows = _read_acl_jsonl_snapshot(in_path)
        filtered = [dict(r) for r in rows if isinstance(r, dict)]

        meta = meta_line.get("meta") if isinstance(meta_line.get("meta"), dict) else {}
        meta = dict(meta)
        meta.update({
            "snapshot_type": "dangerous-ace-jsonl",
            "snapshot_path": str(in_path),
            "snapshot_rows": len(filtered),
        })

        return {
            "success": True,
            "count": len(filtered),
            "acls": filtered,
            "meta": meta,
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Could not read dangerous ACL snapshot: {exc}",
            "code": 500,
        }


def _read_domain_aces_parquet_snapshot() -> dict:
    """Read full ACL rows from domain_aces.jsonl."""
    in_path = _jsonl_snapshot_path(DOMAIN_ACES_JSON)
    if not in_path.exists():
        return {
            "success": False,
            "error": f"ACL snapshot not found: {in_path}",
            "code": 404,
        }

    try:
        meta_line, rows = _read_acl_jsonl_snapshot(in_path)
        rows = [dict(r) for r in rows if isinstance(r, dict)]

        meta = meta_line.get("meta") if isinstance(meta_line.get("meta"), dict) else {}
        meta = dict(meta)
        meta.update({
            "snapshot_type": "all-aces-jsonl",
            "snapshot_path": str(in_path),
            "snapshot_rows": len(rows),
        })

        return {
            "success": True,
            "count": len(rows),
            "acls": rows,
            "meta": meta,
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Could not read ACL JSONL snapshot: {exc}",
            "code": 500,
        }


def _acl_subset_result(base_result: dict, rows: list[dict], snapshot_type: str, snapshot_path: str) -> dict:
    meta = dict(base_result.get("meta") or {})
    meta.update({
        "snapshot_type": snapshot_type,
        "snapshot_path": snapshot_path,
        "snapshot_rows": len(rows),
    })
    return {
        "success": bool(base_result.get("success", True)),
        "count": len(rows),
        "acls": rows,
        "meta": meta,
    }


def _extract_extended_right_rows(result: dict) -> list[dict]:
    rows: list[dict] = []
    aces = list(result.get("acls") or result.get("aces") or [])
    for ace in aces:
        if not isinstance(ace, dict):
            continue
        object_ace_type = _normalize_object_ace_type_value(
            ace.get("object_ace_type") or ace.get("object_acetype")
        )
        if not object_ace_type:
            continue
        row = dict(ace)
        row["object_ace_type"] = object_ace_type
        row["object_acetype"] = object_ace_type
        rows.append(row)
    return rows


def _write_domain_extended_rights_snapshot(result: dict, is_local: bool) -> None:
    """Write extended-right ACEs to domain_extended_rights.jsonl for fast reuse."""
    out_path = _jsonl_snapshot_path(DOMAIN_EXTENDED_RIGHTS_JSON)
    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)

        generated_at = datetime.utcnow().isoformat() + "Z"
        source = "local" if is_local else "domain"
        success = bool(result.get("success"))
        count = int(result.get("count") or 0)
        error = result.get("error") if not success else None
        rows = _extract_extended_right_rows(result) if success else []

        # Filter out default trustee ACEs from extended-rights snapshots as well.
        try:
            rows = [r for r in rows if not _is_default_trustee(str(r.get("principal_sid") or ""))]
        except Exception:
            pass

        meta_line = {
            "success": True,
            "count": len(rows),
            "meta": {
                "generated_at": generated_at,
                "source": source,
                "snapshot_type": "extended-rights-jsonl",
                "snapshot_path": str(out_path),
                "snapshot_success": success,
                "snapshot_count": count,
                "snapshot_error": error,
                "snapshot_rows": len(rows),
            },
        }

        _write_acl_jsonl_snapshot(out_path, meta_line, rows)

        # Remove the old JSON-format snapshot now that JSONL is the source of truth.
        if DOMAIN_EXTENDED_RIGHTS_JSON.exists() and DOMAIN_EXTENDED_RIGHTS_JSON != out_path:
            try:
                DOMAIN_EXTENDED_RIGHTS_JSON.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy extended-rights snapshot %s: %s", DOMAIN_EXTENDED_RIGHTS_JSON, exc)
    except Exception as exc:
        logger.warning("Could not write extended-rights snapshot to %s: %s", out_path, exc)


def _read_domain_extended_rights_snapshot() -> dict:
    """Read extended-right ACEs from domain_extended_rights.jsonl."""
    in_path = _jsonl_snapshot_path(DOMAIN_EXTENDED_RIGHTS_JSON)
    if not in_path.exists():
        return {
            "success": False,
            "error": f"ACL snapshot not found: {in_path}",
            "code": 404,
        }

    try:
        meta_line, rows = _read_acl_jsonl_snapshot(in_path)
        filtered: list[dict] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            object_ace_type = _normalize_object_ace_type_value(
                row.get("object_ace_type") or row.get("object_acetype")
            )
            if not object_ace_type:
                continue
            row = dict(row)
            row["object_ace_type"] = object_ace_type
            row["object_acetype"] = object_ace_type
            filtered.append(row)

        meta = meta_line.get("meta") if isinstance(meta_line.get("meta"), dict) else {}
        meta = dict(meta)
        meta.update({
            "snapshot_type": "extended-rights-jsonl",
            "snapshot_path": str(in_path),
            "snapshot_rows": len(rows),
            "snapshot_filtered_rows": len(filtered),
        })

        return {
            "success": True,
            "count": len(filtered),
            "acls": filtered,
            "meta": meta,
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Could not read ACL snapshot: {exc}",
            "code": 500,
        }


def _read_snapshot_sids(snapshot_path: Path, list_key: str) -> list[str]:
    """
    Read SID values from a Domain Object snapshot.

    Supports both JSON (legacy) and JSONL formats.
    For JSONL: line 1 is metadata, subsequent lines are individual records.
    Falls back to the JSONL counterpart (.jsonl) when the .json file is absent.
    """
    # Prefer JSONL counterpart if JSON file is gone (computers migrated to JSONL).
    jsonl_path = snapshot_path.with_suffix(".jsonl")
    effective_path = snapshot_path if snapshot_path.exists() else jsonl_path

    if not effective_path.exists():
        return []

    try:
        text = effective_path.read_text(encoding="utf-8")

        # JSONL format: each line is a separate JSON object.
        if effective_path.suffix == ".jsonl":
            lines = [ln for ln in text.splitlines() if ln.strip()]
            # Line 0 is metadata — skip it, records start at line 1.
            items = []
            for ln in lines[1:]:
                try:
                    obj = json.loads(ln)
                    if isinstance(obj, dict):
                        items.append(obj)
                except Exception:
                    continue
        else:
            raw = json.loads(text)
            items = raw.get(list_key) if isinstance(raw, dict) else []
            if not isinstance(items, list):
                return []

        sids: list[str] = []
        for obj in items:
            if not isinstance(obj, dict):
                continue
            sid = str(obj.get("sid", "")).strip().upper()
            if sid:
                sids.append(sid)
        return sids
    except Exception as exc:
        logger.warning("Could not read SID snapshot %s: %s", effective_path, exc)
        return []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0", "protocols": list(PROTOCOL_HANDLERS.keys())})


@app.route("/api/domain-object-sids", methods=["GET"])
def domain_object_sids():
    """
    Return known principal SIDs derived from Domain Object snapshots.
    Used by ACL Dangerous filter to hide orphaned SIDs.
    """
    user_sids = _read_snapshot_sids(DOMAIN_USERS_JSON, "users")
    computer_sids = _read_snapshot_sids(DOMAIN_COMPUTERS_JSON, "computers")
    group_sids = _read_snapshot_sids(DOMAIN_GROUPS_JSON, "groups")

    all_sids = sorted(set(user_sids) | set(computer_sids) | set(group_sids))

    return jsonify({
        "success": True,
        "user_sids": user_sids,
        "computer_sids": computer_sids,
        "group_sids": group_sids,
        "all_sids": all_sids,
        "count": len(all_sids),
    }), 200


@app.route("/api/test", methods=["POST"])
@require_json_fields("ip", "protocol")
def test_connection():
    from flask import g
    req   = g.req
    ip    = req["ip"]
    proto = req.get("protocol", "ldap").lower()

    if not validate_ip(ip):
        return jsonify({"error": "Invalid IP format"}), 400
    if proto not in Config.PROTO_PORTS:
        return jsonify({"error": f"Unknown protocol: {proto}"}), 400

    if proto == "ldap":
        ports = _probe_ldap_ports(ip)
        port_open = any(port_info["port_open"] for port_info in ports)
        detected_via = next((port_info["port"] for port_info in ports if port_info["port_open"]), ports[0]["port"] if ports else 0)

        if port_open:
            return jsonify({
                "host_up": True,
                "detected_via": detected_via,
                "port_open": True,
                "port": 389,
                "protocol": proto,
                "reachable": True,
                "retries": 1,
                "ports": ports,
            })

        return jsonify({
            "error": "LDAP connection refused; ports 389 and 636 are closed",
            "host_up": any(port_info["result"] == "closed" for port_info in ports),
            "detected_via": detected_via,
            "port_open": False,
            "port": 389,
            "protocol": proto,
            "reachable": False,
            "attempts": 1,
            "last_result": ports[-1]["result"] if ports else "filtered",
            "ports": ports,
        }), 503

    port        = Config.PROTO_PORTS[proto]
    max_retries = 3
    last_result = "filtered"

    for attempt in range(1, max_retries + 1):
        target_result = _tcp_probe(ip, port, timeout=4)
        last_result   = target_result
        if target_result == 'open':
            return jsonify({
                "host_up":      True,
                "detected_via": port,
                "port_open":    True,
                "port":         port,
                "protocol":     proto,
                "reachable":    True,
                "retries":      attempt,
            })

    return jsonify({
        "error":        "port closed",
        "host_up":      False,
        "detected_via": 0,
        "port_open":    False,
        "port":         port,
        "protocol":     proto,
        "reachable":    False,
        "attempts":     max_retries,
        "last_result":  last_result,
    }), 503


def _clear_domain_object_dir() -> None:
    """
    Domain Object qovluğundakı bütün faylları silir.

    Hər yeni /api/connect uğurlu olduqda collector pipeline işə düşməzdən
    əvvəl çağırılır ki, köhnə domenə aid JSONL/JSON/DB faylları yeni
    nəticələrlə qarışmasın — təmiz slate üzərindən yazılsın.

    Silmə qaydaları:
      • Yalnız birbaşa fayllar silinir (alt qovluqlar toxunulmaz qalır).
      • Hər silinmə xətası ayrıca loglanır, digər faylların silinməsini
        DAYANDIRMIR.
      • Qovluq mövcud deyilsə heç nə edilmir (mkdir sonradan
        collector-lar tərəfindən çağırılacaq).
    """
    if not DOMAIN_OBJECT_DIR.exists():
        logger.info("clear_domain_object_dir: qovluq mövcud deyil, keçilir — %s", DOMAIN_OBJECT_DIR)
        return

    deleted, failed = 0, 0
    for item in DOMAIN_OBJECT_DIR.iterdir():
        if not item.is_file():
            continue
        try:
            item.unlink()
            deleted += 1
            logger.debug("clear_domain_object_dir: silindi — %s", item.name)
        except Exception as exc:
            failed += 1
            logger.warning("clear_domain_object_dir: silinə bilmədi %s: %s", item.name, exc)

    logger.info(
        "clear_domain_object_dir: %d fayl silindi, %d uğursuz — %s",
        deleted, failed, DOMAIN_OBJECT_DIR,
    )


def _run_full_collector_pipeline(enum_req: dict) -> None:
    """
    Bütün domain collector-larını (users/computers/ous/gpos/groups/trusts/acl)
    ardıcıl olaraq işə salır və hər birinin nəticəsini öz .jsonl snapshot
    faylına yazır. Bu funksiya /api/connect uğurlu olduqdan sonra ayrıca bir
    background thread-də çağırılır (bax: connect()) -- həmin sorğunun HTTP
    cavabını GƏCİKDİRMİR.

    Hər .jsonl yazılışı _schedule_db_build() vasitəsilə debounced DB tikintisi
    planlaşdırır. Bütün collector-lar bitdikdən sonra debounce gözlənilmədən
    DB sinxron tikilir ki, sonuncu snapshot da daxil olsun. sqlite_reader.py
    (port 8800) burada AVTOMATİK başladılmır -- manual olaraq əl ilə işə
    salınmalıdır. Frontend onun hazır olduğunu /api/health (8800) pollinqi
    ilə aşkarlayır.

    Tək bir collector-un uğursuz olması digərlərini DAYANDIRMIR -- hər biri
    öz try/except blokunda işləyir ki, məsələn ACL enumeration uğursuz olsa
    belə Users/Computers snapshot-ları yenə DB-yə düşsün.
    """
    ip = enum_req.get("ip") or enum_req.get("dc") or enum_req.get("domain")
    domain = enum_req.get("domain")
    logger.info("collector pipeline started: ip=%s domain=%s", ip, domain)


    # ── Köhnə faylları təmizlə ───────────────────────────────────────────────
    # Yeni collector nəticələri yazılmadan əvvəl Domain Object qovluğu
    # sıfırlanır ki, əvvəlki domenə aid stale data yeni nəticələrlə qarışmasın.
    _clear_domain_object_dir()
    try:
        domain_info_result = _run_enumeration_with_target_fallback(enum_req, get_domain_info)
        _write_domain_info_jsonl_snapshot(domain_info_result, is_local=False)
    except Exception as exc:
        logger.warning("collector pipeline: dominfo collector failed: %s", exc)

    try:
        # DÜZƏLİŞ: əvvəllər `on_records` ötürülmürdü — bütün DEEP_SCAN (4 NC +
        # 5 critical subtree) bitənə qədər heç nə diskə yazılmırdı və yalnız
        # `acl_result["success"]` True olduqda son nəticə yazılırdı. VPN kimi
        # dar-bant/yüksək-latency mühitlərdə bu, uzun gözləmə və (proses
        # kəsilərsə) heç bir nəticənin qalmaması demək idi. İndi hər hazır
        # batch (bax: collector._PARSE_BATCH_SIZE) dərhal `domain_aces.jsonl`-ə
        # yazılır — `_write_domain_aces_snapshot` ilə eyni formatda (meta
        # sətri + record-lar), sadəcə "partial: true" işarəli ki, yarımçıq
        # olduğu bilinsin. Scan tam bitdikdə fayl son/dəqiq meta ilə üzərinə
        # yazılır.
        acl_stream_lock = threading.Lock()
        acl_streamed: list[dict] = []

        def _acl_stream_write(records: list[dict]) -> None:
            with acl_stream_lock:
                acl_streamed.extend(records)
                try:
                    out_path = _jsonl_snapshot_path(DOMAIN_ACES_JSON)
                    DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)
                    partial_meta = {
                        "generated_at": datetime.utcnow().isoformat() + "Z",
                        "source": "domain",
                        "success": False,
                        "count": len(acl_streamed),
                        "error": None,
                        "meta": {"partial": True, "note": "ACL scan davam edir"},
                    }
                    _write_acl_jsonl_snapshot(out_path, partial_meta, acl_streamed)
                except Exception as stream_exc:
                    logger.warning("acl pipeline stream write failed: %s", stream_exc)

        def _acl_collector(ip_, domain_, username_, password_, config_):
            return get_domain_acls(
                ip_, domain_, username_, password_, config_,
                acl_filter=AclFilterConfig(),
                on_records=_acl_stream_write,
            )

        acl_result = _run_enumeration_with_target_fallback(enum_req, _acl_collector)
        # DÜZƏLİŞ: əvvəllər yalnız `acl_result["success"]` True olduqda yazılırdı.
        # `_build_result` (collector.py) top-level istisna olmadıqca həmişə
        # success=True qaytarsa da, əlavə mühafizə xətti kimi indi ELƏCƏ DƏ
        # streaming zamanı toplanmış nəticə mövcuddursa (top-level uğursuzluq
        # halında belə) final snapshot yazılır — heç bir hal fayl tamamilə
        # boş qalmasın deyə.
        if acl_result.get("success") or acl_streamed:
            final_result = acl_result if acl_result.get("success") else {
                **acl_result,
                "acls": acl_streamed,
                "count": len(acl_streamed),
            }
            _write_domain_aces_snapshot(final_result, is_local=False)
            _write_domain_extended_rights_snapshot(final_result, is_local=False)
            _write_domain_dangerous_ace_snapshot(final_result, is_local=False)
    except Exception as exc:
        logger.warning("collector pipeline: acl collector failed: %s", exc)

    try:
        # get_domain_groups öz içindən domain_groups.jsonl-ə yazır (members: [] boş).
        # _write_domain_object_snapshot ÇAĞIRILMIR — çünki o funksiya faylı
        # boş members-lərlə üzərinə yazar və members mərhələsinin nəticəsini məhv edər.
        _run_enumeration_with_target_fallback(enum_req, groups.get_domain_groups)
    except Exception as exc:
        logger.warning("collector pipeline: groups collector failed: %s", exc)

    # group_member collector — get_domain_groups-dan sonra işləməlidir ki,
    # domain_groups.jsonl mövcud olsun. LDAP-dan members-ləri çəkir və
    # domain_groups.jsonl-i members massivi dolu şəkildə yenidən yazır.
    try:
        _run_enumeration_with_target_fallback(enum_req, groups.get_all_group_members)
    except Exception as exc:
        logger.warning("collector pipeline: group_member collector failed: %s", exc)

    try:
        gpos_result = _run_enumeration_with_target_fallback(enum_req, gpos.get_domain_gpos)
        _write_domain_gpos_snapshot(gpos_result)
    except Exception as exc:
        logger.warning("collector pipeline: gpos collector failed: %s", exc)

    try:
        ous_result = _run_enumeration_with_target_fallback(enum_req, ous.get_domain_ous)
        _write_domain_object_snapshot(
            filename="domain_ous.json",
            result=ous_result,
            is_local=False,
            data_key="ous",
            legacy_path=LEGACY_DOMAIN_OUS_JSON,
        )
    except Exception as exc:
        logger.warning("collector pipeline: ous collector failed: %s", exc)

    try:
        trusts_result = _run_enumeration_with_target_fallback(enum_req, trusts.get_domain_trusts)
        _write_domain_object_snapshot(
            filename="domain_trusts.json",
            result=trusts_result,
            is_local=False,
            data_key="trusts",
            legacy_path=LEGACY_DOMAIN_TRUSTS_JSON,
        )
    except Exception as exc:
        logger.warning("collector pipeline: trusts collector failed: %s", exc)

    try:
        computers_result = _run_enumeration_with_target_fallback(enum_req, computers.get_domain_computers)
        _write_domain_computers_jsonl_snapshot(result=computers_result, is_local=False)
    except Exception as exc:
        logger.warning("collector pipeline: computers collector failed: %s", exc)

    try:
        users_result = _run_enumeration_with_target_fallback(enum_req, users.get_domain_users)
        _write_domain_users_snapshot(users_result, is_local=False)
    except Exception as exc:
        logger.warning("collector pipeline: users collector failed: %s", exc)

    # Bütün collector-lar bitdi -- debounce timer-i ləğv edib DB-ni dərhal
    # (sinxron) tikir ki, son snapshot da daxil olsun. sqlite_reader.py burada
    # avtomatik başladılmır -- manual olaraq əl ilə işə salınmalıdır.
    with _db_build_lock:
        global _db_build_timer
        if _db_build_timer is not None:
            _db_build_timer.cancel()
            _db_build_timer = None
    _run_sqlite_engine()

    logger.info("collector pipeline finished: ip=%s domain=%s", ip, domain)


@app.route("/api/connect", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_CONNECT)
def connect():
    req = request.get_json(silent=True)
    if not req:
        return jsonify({"error": "JSON body is required"}), 400

    mode = req.get("mode", "remote").lower()
    if mode == "local":
        result = connect_local()
        if result.get("success"):
            profile = _collect_powershell_profile(req, result)
            _apply_powershell_profile(result, profile)
        return jsonify(result) if result.get("success") else (jsonify(result), 500)

    missing = [fld for fld in ("ip", "username", "domain") if not req.get(fld)]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    ip           = req["ip"]
    username     = req["username"]
    password     = str(req.get("password", "")).strip()
    hash_value   = str(req.get("hash", "")).strip()
    domain       = req["domain"]
    proto        = req.get("protocol", "ldap").lower()
    connect_mode = str(req.get("connect_mode", "deep")).lower()
    skip_counts  = bool(req.get("skip_counts_probe", False))

    # Debug: log incoming connect mode and skip_counts_probe to help diagnose
    # client/server mismatch issues when Deep connect returns incomplete data.
    logger.info("/api/connect called: ip=%s proto=%s connect_mode=%s skip_counts_probe=%s", ip, proto, connect_mode, skip_counts)

    if password and hash_value:
        return jsonify({"error": "Use either password or NTLM hash, not both"}), 400
    if not password and not hash_value:
        return jsonify({"error": "Missing fields: password or hash"}), 400

    auth_secret = password or hash_value

    if not validate_ip(ip) or not validate_domain(domain) or not validate_username(username):
        return jsonify({"error": "Invalid input formats"}), 400
    if proto not in PROTOCOL_HANDLERS:
        return jsonify({"error": f"Unsupported protocol: {proto}"}), 400

    if proto == "ldap":
        ldap_ports = _probe_ldap_ports(ip, timeout=Config.LDAP_CONNECT_TIMEOUT)
        if _ldap_ports_refused(ldap_ports):
            return jsonify({
                "success": False,
                "error": "LDAP connection refused; ports 389 and 636 are closed",
                "protocol": proto,
                "ports": ldap_ports,
                "port_open": False,
                "host_up": False,
                "reachable": False,
                "code": 503,
            }), 503

    result = run_connect_strategy(
        connect_mode=connect_mode,
        proto=proto,
        ip=ip,
        username=username,
        password=auth_secret,
        domain=domain,
        connect_ldap_fast=connect_ldap_fast,
        protocol_handlers=PROTOCOL_HANDLERS,
    )

    if result.get("success"):
        profile = _collect_powershell_profile(req, result)
        _apply_powershell_profile(result, profile)
        result["connect_mode"] = connect_mode

        if connect_mode != "fast":
            # Port/host məlumatları üçün yüngül probe (env-probe/counts YOX —
            # bunlar artıq aşağıdakı collector pipeline tərəfindən təmin edilir).
            apply_deep_defaults(result, ip, check_port=check_port)

        # ── Collector pipeline tetiklenmesi ─────────────────────────────
        # Connect uğurlu oldu. GUI-yə nə canlı enumeration datası, nə də
        # GLOBAL_STATE ölçüsündə cavab qaytarılmır. Bunun əvəzinə bütün
        # collector-lar (users/computers/ous/gpos/groups/trusts/acl) ayrıca
        # bir background thread-də işə salınır; hər biri bitdikcə öz .jsonl
        # faylını yazır, sonda domain_data.db tikilir (bax:
        # _run_full_collector_pipeline). sqlite_reader.py (port 8800) burada
        # avtomatik başladılmır -- manual olaraq əl ilə işə salınmalıdır.
        # Frontend bunu /api/health (8800) pollinqi ilə izləyir (bax: 00-global.js).
        enum_req = dict(req)
        enum_req["mode"]     = "remote"
        enum_req["ip"]       = ip
        enum_req["domain"]   = domain
        enum_req["username"] = username
        enum_req["password"] = password
        enum_req["hash"]     = hash_value
        enum_req["protocol"] = proto
        enum_req["dc"]       = result.get("dc") or ip

        threading.Thread(
            target=_run_full_collector_pipeline,
            args=(enum_req,),
            daemon=True,
        ).start()

        return jsonify({
            "success": True,
            "message": "Collector tamamlandı. .jsonl faylları SQLite (.db)-yə çevrilir.",
            "status": "processing_db",
            "connect_mode": connect_mode,
            "protocol": proto,
            "ip": ip,
            "domain": domain,
            "dc": result.get("dc") or ip,
            "user": username,
            "db_reader_base": SQLITE_READER_BASE,
        }), 202

    status = 401 if any(k in result.get("error", "") for k in ("password", "Authentication", "credentials")) else 500
    return jsonify(result) if result.get("success") else (jsonify(result), status)


@app.route("/api/users", methods=["POST"])
@app.route("/api/user", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_ENUM)
def list_users():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response

    proto_out_path = Path(PROJECT_ROOT) / "domain_users.pb"

    def _enum_users_with_proto(ip, domain, username, password, config):
        return users.get_domain_users(
            ip,
            domain,
            username,
            password,
            config,
            proto_output_path=str(proto_out_path),
        )

    local_mode = is_local_request(req)
    result = (
        _local_enumeration_removed("User")
        if local_mode
        else _run_enumeration_with_target_fallback(req, _enum_users_with_proto)
    )

    if local_mode:
        _write_domain_users_proto_snapshot(result, proto_out_path)

    _write_domain_users_snapshot(result, is_local=local_mode)

    # connection.py YALNIZ collector-a əmr verir və nəticəni .jsonl-ə yazır
    # (yuxarıda) + DB build-i debounce ilə planlaşdırır (_write_domain_users_snapshot
    # daxilində). Render BURADA BAŞ VERMİR — frontend domain_data.db-dən
    # render üçün birbaşa sqlite_reader.py-nin /api/users endpoint-inə
    # müraciət edir.
    return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))


@app.route("/api/computers", methods=["POST"])
@app.route("/api/computer", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_ENUM)
def list_computers():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response
    result = (
        _local_enumeration_removed("Computer")
        if is_local_request(req)
        else _run_enumeration_with_target_fallback(req, computers.get_domain_computers)
    )
    _write_domain_computers_jsonl_snapshot(result=result, is_local=is_local_request(req))
    return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))


@app.route("/api/ous", methods=["POST"])
@app.route("/api/ou", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_ENUM)
def list_ous():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response
    result = (
        _local_enumeration_removed("OU")
        if is_local_request(req)
        else _run_enumeration_with_target_fallback(req, ous.get_domain_ous)
    )
    _write_domain_object_snapshot(
        filename="domain_ous.json",
        result=result,
        is_local=is_local_request(req),
        data_key="ous",
        legacy_path=LEGACY_DOMAIN_OUS_JSON,
    )
    return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))


def _write_domain_gpos_snapshot(result: dict) -> None:
    """
    Write GPO snapshot to domain_gpos.jsonl, including extra summary lines
    (all_cpasswords, inheritance_blocked, ou_inheritance) appended at the
    end. Used by both the /api/gpo route and the full collector pipeline
    (see _run_full_collector_pipeline) so both paths stay in sync.
    """
    out_path = DOMAIN_OBJECT_DIR / "domain_gpos.jsonl"
    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)
        meta_line = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "source": "domain",
            "success": bool(result.get("success")),
            "count": int(result.get("count") or 0),
            "sysvol_available": result.get("sysvol_available"),
            "error": result.get("error") if not result.get("success") else None,
        }
        gpos_list = list(result.get("gpos") or [])
        _write_acl_jsonl_snapshot(out_path, meta_line, gpos_list)

        # Extra fields (all_cpasswords, inheritance_blocked, ou_inheritance)
        # are appended as an extra line at the end of the file
        extra_lines = []
        if result.get("all_cpasswords"):
            extra_lines.append(
                json.dumps({"all_cpasswords": result["all_cpasswords"]},
                           ensure_ascii=False, default=str)
            )
        inh_line = {
            "inheritance_blocked": result.get("inheritance_blocked", []),
            "ou_inheritance":      result.get("ou_inheritance", []),
        }
        extra_lines.append(json.dumps(inh_line, ensure_ascii=False, default=str))
        if extra_lines:
            with open(out_path, "a", encoding="utf-8") as _f:
                _f.write("\n".join(extra_lines) + "\n")

        # Remove old .json file
        old_json = DOMAIN_OBJECT_DIR / "domain_gpos.json"
        if old_json.exists() and old_json != out_path:
            try:
                old_json.unlink()
            except Exception as exc:
                logger.warning("Could not remove old GPO JSON snapshot %s: %s", old_json, exc)

        if LEGACY_DOMAIN_GPOS_JSON.exists() and LEGACY_DOMAIN_GPOS_JSON != out_path:
            try:
                LEGACY_DOMAIN_GPOS_JSON.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy GPO snapshot %s: %s", LEGACY_DOMAIN_GPOS_JSON, exc)
    except Exception as exc:
        logger.warning("Could not write GPO JSONL snapshot to %s: %s", out_path, exc)
    else:
        _schedule_db_build()  # Snapshot written -- trigger DB build with debounce


@app.route("/api/gpo", methods=["POST"])
@app.route("/api/gpos", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_ENUM)
def list_gpos():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response
    result = (
        _local_enumeration_removed("GPO")
        if is_local_request(req)
        else _run_enumeration_with_target_fallback(req, gpos.get_domain_gpos)
    )

    # Save the full result — extra fields such as all_cpasswords, wmi_filters,
    # inheritance_blocked, ou_inheritance, sysvol_available would be lost by
    # _write_domain_object_snapshot, so we use the dedicated GPO writer.
    _write_domain_gpos_snapshot(result)

    return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))


@app.route("/api/groups", methods=["POST"])
@app.route("/api/group", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_ENUM)
def list_groups():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response

    if is_local_request(req):
        result = _local_enumeration_removed("Group")
        return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))

    # MƏRHƏLƏ 1: get_domain_groups ozunden domain_groups.jsonl-e yazir (members: [] bos).
    # _write_domain_object_snapshot CAĞIRILMIR -- o funksiya faylin uzurine bos members-le
    # yazaraq members merhelesinin neticesini mehv edir.
    result = _run_enumeration_with_target_fallback(req, groups.get_domain_groups)

    # MƏRHƏLƏ 2: members-leri doldur ve domain_groups.jsonl-i yeniden yaz.
    if result.get("success"):
        try:
            members_result = _run_enumeration_with_target_fallback(req, groups.get_all_group_members)
            if members_result.get("success"):
                result = members_result
        except Exception as exc:
            logger.warning("list_groups: group_member collector failed: %s", exc)

    return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))


@app.route("/api/group-members", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_ENUM)
def list_group_members():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response

    if is_local_request(req):
        result = {
            "success": False,
            "error": "Group member expansion is available for domain LDAP sessions only",
            "code": 400,
        }
        return jsonify(result), 400

    group_dn = str(req.get("group_dn", "")).strip()
    if not group_dn:
        group_dn = "__all__"

    def _enum_group_members(ip, domain, username, password, config):
        return groups.get_group_members(ip, domain, username, password, group_dn, config)

    result = _run_enumeration_with_target_fallback(req, _enum_group_members)
    return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))


@app.route("/api/trusts", methods=["POST"])
@app.route("/api/trust", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_ENUM)
def list_trusts():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response
    result = (
        _local_enumeration_removed("Trust")
        if is_local_request(req)
        else _run_enumeration_with_target_fallback(req, trusts.get_domain_trusts)
    )
    _write_domain_object_snapshot(
        filename="domain_trusts.json",
        result=result,
        is_local=is_local_request(req),
        data_key="trusts",
        legacy_path=LEGACY_DOMAIN_TRUSTS_JSON,
    )
    return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))


@app.route("/api/acl", methods=["POST"])
@limiter.limit("10 per minute")
def list_acl_entries():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response
    if is_local_request(req):
        result = {
            "success": False,
            "error":   "ACL enumeration is available for domain LDAP sessions only",
            "code":    400,
        }
    else:
        # ACL filter — frontend-den gelen acl_filter parametrine gore qur
        acl_filter_raw = req.get("acl_filter") or {}
        acl_filter_name = str(req.get("acl_source") or "live").strip().lower()
        acl_filter = AclFilterConfig(
            exclude_inherited  = bool(acl_filter_raw.get("exclude_inherited",  False)),
            exclude_default    = bool(acl_filter_raw.get("exclude_default",    False)),
            interesting_only   = bool(acl_filter_raw.get("interesting_only",   False)),
            self_acl_only      = bool(acl_filter_raw.get("self_acl_only",      False)),
            rights_filter      = list(acl_filter_raw.get("rights_filter",      [])),
            principal_filter   = str(acl_filter_raw.get("principal_filter",    "")),
            target_filter      = str(acl_filter_raw.get("target_filter",       "")),
            target_type_filter = list(acl_filter_raw.get("target_type_filter", [])),
            scope_filter       = list(acl_filter_raw.get("scope_filter",       [])),
        )

        def _get_acls_with_filter(ip, domain, username, password, config):
            return get_domain_acls(
                ip, domain, username, password, config,
                acl_filter=acl_filter,
            )

        should_refresh_snapshots = False
        source_result = None

        if acl_filter_name in {"snapshot", "snapshot-extended"}:
            result = _read_domain_extended_rights_snapshot()
        elif acl_filter_name == "snapshot-all":
            result = _read_domain_aces_parquet_snapshot()
        elif acl_filter_name == "snapshot-dangerous":
            result = _read_domain_dangerous_ace_snapshot()
        elif acl_filter_name == "live-extended":
            source_result = _run_enumeration_with_target_fallback(req, _get_acls_with_filter)
            result = _acl_subset_result(
                source_result,
                _extract_extended_right_rows(source_result),
                "extended-rights-live",
                str(_jsonl_snapshot_path(DOMAIN_EXTENDED_RIGHTS_JSON)),
            ) if source_result.get("success") else source_result
            should_refresh_snapshots = bool(source_result.get("success"))
        elif acl_filter_name == "live-dangerous":
            source_result = _run_enumeration_with_target_fallback(req, _get_acls_with_filter)
            result = _acl_subset_result(
                source_result,
                _extract_dangerous_rows(source_result),
                "dangerous-ace-live",
                str(_jsonl_snapshot_path(DOMAIN_DANGEROUS_ACE_JSON)),
            ) if source_result.get("success") else source_result
            should_refresh_snapshots = bool(source_result.get("success"))
        else:
            source_result = _run_enumeration_with_target_fallback(req, _get_acls_with_filter)
            result = source_result
            should_refresh_snapshots = bool(source_result.get("success"))

    if not is_local_request(req):
        snapshot_source = source_result if source_result is not None else result
        if should_refresh_snapshots and snapshot_source and snapshot_source.get("success"):
            _write_domain_aces_snapshot(snapshot_source, is_local=False)
            _write_domain_extended_rights_snapshot(snapshot_source, is_local=False)
            _write_domain_dangerous_ace_snapshot(snapshot_source, is_local=False)

    return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))


@app.route("/api/shell", methods=["POST"])
def shell_command():
    req = request.get_json(silent=True)
    if not req:
        return jsonify({"error": "JSON body is required"}), 400

    command  = req.get("command", "").strip()
    mode     = req.get("mode", "remote").lower()
    protocol = req.get("protocol", "local").lower()

    if not command:
        return jsonify({"error": "Command is required"}), 400

    if mode == "local":
        result = run_local_command(command)
        return jsonify(result) if result.get("success") else (jsonify(result), 500)

    return jsonify({"success": False, "error": f"Shell is not supported for protocol: {protocol}"}), 400


@app.route("/api/decision-engine/graph", methods=["POST"])
@limiter.limit("20 per minute")
def decision_engine_graph():
    req = request.get_json(silent=True) or {}
    current_user = str(req.get("current_user") or "").strip()
    current_sid = str(req.get("current_sid") or "").strip()
    current_type = str(req.get("current_type") or "").strip()

    result = build_decision_graph_snapshot(
        domain_object_dir=DOMAIN_OBJECT_DIR,
        project_root=Path(PROJECT_ROOT),
        current_user=current_user,
        current_sid=current_sid,
        current_type=current_type,
    )

    code = int(result.get("code") or (200 if result.get("success") else 500))
    if code not in (200, 400, 401, 403, 404, 500, 503):
        code = 500
    return jsonify(result), code


@app.route("/api/enumeration/local-inventory", methods=["POST"])
def enumeration_local_inventory():
    req  = request.get_json(silent=True) or {}
    mode = str(req.get("mode", "")).lower()
    if mode and mode != "local":
        return jsonify({"success": False, "error": "This module is available for local mode only"}), 400
    result = run_local_inventory_c_tool()
    status = 200 if result.get("success") else result.get("code", 500)
    return jsonify(result), status


@app.route("/api/smb-check", methods=["POST"])
@limiter.limit("10 per minute")
def smb_check():
    req  = request.get_json(silent=True) or {}
    mode = str(req.get("mode", "remote")).lower()
    if mode == "local":
        return jsonify({"success": False, "error": "SMB checker requires remote target credentials", "code": 400}), 400
    result = run_smb_checker_tool(req)
    status = 200 if result.get("success") else result.get("code", 500)
    if status not in (200, 400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status


@app.route("/api/ntlm-check", methods=["POST"])
@limiter.limit("10 per minute")
def ntlm_check():
    req  = request.get_json(silent=True) or {}
    mode = str(req.get("mode", "remote")).lower()
    if mode == "local":
        return jsonify({"success": False, "error": "NTLM checker requires remote target credentials", "code": 400}), 400
    result = run_ntlm_checker_tool(req)
    status = 200 if result.get("success") else result.get("code", 500)
    if status not in (200, 400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status


@app.route("/api/kerberos-check", methods=["POST"])
@limiter.limit("10 per minute")
def kerberos_check():
    req  = request.get_json(silent=True) or {}
    mode = str(req.get("mode", "remote")).lower()
    if mode == "local":
        return jsonify({"success": False, "error": "Kerberos checker requires remote target credentials", "code": 400}), 400
    result = run_kerberos_checker_tool(req)
    status = 200 if result.get("success") else result.get("code", 500)
    if status not in (200, 400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status


@app.route("/api/probe-protocols", methods=["POST"])
@limiter.limit("20 per minute")
def probe_protocols():
    req     = request.get_json(silent=True) or {}
    ip      = str(req.get("ip", "")).strip()
    timeout = float(req.get("timeout", 5) or 5)
    requested = req.get("protocols")  # optional list; None means probe all

    if not ip:
        return jsonify({"success": False, "error": "Missing ip", "code": 400}), 400

    all_keys = list(SIMPLE_PROTOCOL_CHECKERS.keys())
    keys     = [k for k in (requested or all_keys) if k in all_keys]

    results = {}
    for key in keys:
        r       = run_simple_protocol_probe(key, ip, timeout)
        summary = r.get("summary", "Unknown") if r.get("success") else "Unknown"
        level   = "good" if summary == "Enabled" else ("bad" if summary == "Disabled" else "unknown")
        results[key] = {"status": summary, "level": level}

    return jsonify({"success": True, "results": results}), 200


@app.route("/api/security-status-quick", methods=["POST"])
@limiter.limit("30 per minute")
def security_status_quick():
    req = request.get_json(silent=True) or {}
    mode = str(req.get("mode", "remote")).lower()

    if mode == "local":
        smb_enabled = check_port("127.0.0.1", 445)
        return jsonify({
            "success": True,
            "source": "quick-port-probe",
            "kerberos_enabled": False,
            "ntlm_enabled": smb_enabled,
            "smb_enabled": smb_enabled,
            "notes": ["Local mode quick probe"],
        }), 200

    ip = str(req.get("ip", "")).strip()
    domain = str(req.get("domain", "")).strip()
    dc = str(req.get("dc", "")).strip() or str(req.get("ldap_host", "")).strip()

    if not ip and not domain and not dc:
        return jsonify({"success": False, "error": "Missing target fields", "code": 400}), 400

    kerberos_target = dc or domain or ip
    smb_target = ip or dc or domain

    kerberos_enabled = check_port(kerberos_target, 88) if kerberos_target else None
    smb_enabled = check_port(smb_target, 445) if smb_target else None

    # Quick signal only: in AD paths NTLM is typically available when SMB auth path is open.
    ntlm_enabled = smb_enabled

    return jsonify({
        "success": True,
        "source": "quick-port-probe",
        "targets": {
            "kerberos": kerberos_target,
            "smb": smb_target,
        },
        "kerberos_enabled": kerberos_enabled,
        "ntlm_enabled": ntlm_enabled,
        "smb_enabled": smb_enabled,
    }), 200


@app.route("/api/dcsync", methods=["POST"])
@limiter.limit("5 per minute")
def dcsync_execute():
    req = request.get_json(silent=True) or {}
    result = run_dcsync_tool(req)
    status = 200 if result.get("success") else result.get("code", 500)
    if status not in (200, 400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status


@app.route("/api/dcsync-history", methods=["GET"])
def dcsync_history():
    items = _read_dcsync_history()
    return jsonify({"success": True, "history": items}), 200


@app.route("/api/kerberos-keys", methods=["POST"])
@limiter.limit("10 per minute")
def kerberos_keys_save():
    req = request.get_json(silent=True) or {}
    result = save_kerberos_key(req)
    status = 200 if result.get("success") else result.get("code", 500)
    if status not in (200, 400, 401, 403, 404, 500, 503):
        status = 500
    return jsonify(result), status


@app.route("/api/saved-users", methods=["GET"])
def get_saved_users():
    items = _read_old_users()
    return jsonify({"success": True, "users": items[:10]}), 200


@app.route("/api/saved-users/save", methods=["POST"])
def save_saved_user():
    req        = request.get_json(silent=True) or {}
    domain     = str(req.get("domain",   "")).strip()
    ip         = str(req.get("ip",       "")).strip()
    username   = str(req.get("username", "")).strip()
    protocol   = str(req.get("protocol", "")).strip().lower()
    password   = str(req.get("password", "")).strip()
    hash_value = str(req.get("hash",     "")).strip()
    dc         = str(req.get("dc",       "")).strip()

    if not domain or not ip or not username:
        return jsonify({"success": False, "error": "Missing required fields"}), 400

    entry = {
        "domain":    domain,
        "ip":        ip,
        "username":  username,
        "saved_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    if dc:
        entry["dc"] = dc
    if password:
        entry["password"] = password
    if hash_value:
        entry["hash"] = hash_value
    if protocol:
        entry["protocol"] = protocol

    existing = _read_old_users()
    protocol_cmp = protocol or ""
    filtered = [
        x for x in existing
        if not (
            str(x.get("domain",   "")).lower() == domain.lower()
            and str(x.get("ip",       "")).lower() == ip.lower()
            and str(x.get("username", "")).lower() == username.lower()
            and str(x.get("protocol", "")).lower() == protocol_cmp
        )
    ]
    updated = ([entry] + filtered)[:10]

    try:
        _write_old_users(updated)
    except Exception as exc:
        return jsonify({"success": False, "error": f"Failed to save old_users.json: {exc}"}), 500

    return jsonify({"success": True, "users": updated}), 200


@app.route("/api/browse-folder", methods=["POST"])
@limiter.limit("30 per minute")
def browse_folder():
    """
    Opens a native Windows folder-picker dialog via tkinter and returns the selected path.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.lift()
        root.attributes("-topmost", True)
        root.focus_force()
        folder = filedialog.askdirectory(title="Select Output Folder", parent=root)
        root.destroy()

        if not folder:
            return jsonify({"success": False, "cancelled": True}), 200

        from pathlib import Path as _Path
        normalised = str(_Path(folder).resolve())
        return jsonify({"success": True, "path": normalised}), 200

    except Exception as exc:
        logger.warning("browse-folder error: %s", exc)
        return jsonify({"success": False, "error": str(exc), "code": 500}), 500


@app.route("/api/resolve-folder", methods=["POST"])
@limiter.limit("30 per minute")
def resolve_folder():
    """
    Helper for the File System Access API path (browser security only exposes
    the directory *name*, not the full path). We search common locations for a
    directory matching the given hint name and return the first match.
    """
    req  = request.get_json(silent=True) or {}
    hint = str(req.get("hint", "")).strip()

    if not hint:
        return jsonify({"success": False, "error": "Missing hint", "code": 400}), 400

    import os as _os
    search_roots = [
        _os.path.expanduser("~\\Desktop"),
        _os.path.expanduser("~\\Documents"),
        _os.path.expanduser("~\\Downloads"),
        _os.path.expanduser("~"),
        "C:\\",
    ]

    for root_dir in search_roots:
        candidate = _os.path.join(root_dir, hint)
        if _os.path.isdir(candidate):
            return jsonify({"success": True, "path": candidate}), 200

    # Could not resolve — just return the hint so the frontend can still use it
    return jsonify({"success": False, "error": f"Could not resolve folder: {hint}"}), 200


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Agent Generator  (async job system)
# ---------------------------------------------------------------------------

import subprocess
import threading
import uuid as _uuid_mod

_AGENT_GENERATOR_DIR = Path(__file__).parent.parent / "Agent Generator"
_BUILD_BAT           = _AGENT_GENERATOR_DIR / "Build.bat"

# job_id -> { status, lines, returncode, error }
_build_jobs: dict = {}
_build_jobs_lock   = threading.Lock()
_active_build_id   = None          # only one build at a time


def _run_build_job(job_id: str, env: dict) -> None:
    global _active_build_id
    try:
        proc = subprocess.Popen(
            ["cmd.exe", "/c", str(_BUILD_BAT)],
            cwd=str(_AGENT_GENERATOR_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,      # merge stderr into stdout
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        logger.info("generate-agent [%s]: PID %s started", job_id, proc.pid)

        # Stream lines in real-time
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\r\n")
            with _build_jobs_lock:
                _build_jobs[job_id]["lines"].append(line)

        proc.wait(timeout=300)
        rc = proc.returncode
        logger.info("generate-agent [%s]: exit=%s", job_id, rc)

        with _build_jobs_lock:
            _build_jobs[job_id]["status"]     = "done"
            _build_jobs[job_id]["returncode"] = rc
            _build_jobs[job_id]["success"]    = (rc == 0)

    except Exception as exc:
        logger.exception("generate-agent [%s] error: %s", job_id, exc)
        with _build_jobs_lock:
            _build_jobs[job_id]["status"] = "done"
            _build_jobs[job_id]["error"]  = str(exc)
            _build_jobs[job_id]["success"] = False
    finally:
        global _active_build_id
        _active_build_id = None


@app.route("/api/generate-agent", methods=["POST"])
@limiter.limit("10 per minute")
def generate_agent():
    global _active_build_id
    req = request.get_json(silent=True) or {}

    fmt         = str(req.get("fmt",      "exe")).strip().lower()
    platform    = str(req.get("platform", "windows")).strip().lower()
    output_path = str(req.get("output",   "")).strip()

    if fmt not in ("exe",):
        return jsonify({"success": False, "error": f"Unsupported format: {fmt}", "code": 400}), 400

    if not _BUILD_BAT.exists():
        return jsonify({"success": False, "error": f"Build.bat not found at {_BUILD_BAT}", "code": 500}), 500

    with _build_jobs_lock:
        if _active_build_id and _build_jobs.get(_active_build_id, {}).get("status") == "running":
            return jsonify({"success": False, "error": "A build is already in progress.", "code": 429}), 429

        job_id = str(_uuid_mod.uuid4())[:8]
        _build_jobs[job_id] = {"status": "running", "lines": [], "returncode": None, "success": None, "error": None}
        _active_build_id = job_id

    env = os.environ.copy()
    env["AG_NAME"]     = str(req.get("name",        "oxsium-agent-001")).strip()
    env["AG_PLATFORM"] = platform
    env["AG_FMT"]      = fmt
    env["AG_OUTPUT"]   = output_path
    env["AG_KEY"]      = str(req.get("key",          "")).strip()
    env["AG_PADDING"]  = str(req.get("paddingSize",  "")).strip()
    env["AG_PAD_UNIT"] = str(req.get("paddingUnit",  "KB")).strip()

    logger.info("generate-agent [%s]: launching %s", job_id, _BUILD_BAT)
    t = threading.Thread(target=_run_build_job, args=(job_id, env), daemon=True)
    t.start()

    return jsonify({"success": True, "job_id": job_id}), 200


@app.route("/api/agent-build-status", methods=["GET"])
def agent_build_status():
    job_id = request.args.get("job_id", "").strip()
    with _build_jobs_lock:
        job = _build_jobs.get(job_id)
    if not job:
        return jsonify({"success": False, "error": "Unknown job_id", "code": 404}), 404

    offset = int(request.args.get("offset", 0))
    lines  = job["lines"][offset:]

    return jsonify({
        "success":    True,
        "status":     job["status"],       # "running" | "done"
        "lines":      lines,
        "offset":     offset + len(lines),
        "returncode": job["returncode"],
        "build_success": job["success"],
        "error":      job["error"],
    }), 200


# ---------------------------------------------------------------------------
# Offline Snapshot Reader  — reads domain_*.jsonl files from the Domain
# Object directory directly, without requiring a connect/LDAP call.
# ---------------------------------------------------------------------------

# section name → (jsonl filename, data key used in the response)
SNAPSHOT_SECTION_MAP = {
    "users":     ("domain_users.jsonl",     "users"),
    "computers": ("domain_computers.jsonl", "computers"),
    "ous":       ("domain_ous.jsonl",       "ous"),
    "gpos":      ("domain_gpos.jsonl",      "gpos"),
    "groups":    ("domain_groups.jsonl",    "groups"),
    "trusts":    ("domain_trusts.jsonl",    "trusts"),
    "acl":       ("domain_aces.jsonl",      "acls"),
}


def _read_generic_jsonl_snapshot(filename: str, data_key: str) -> dict:
    """
    Reads the given domain_*.jsonl file and returns it in the standard
    enumeration response format: {success, count, <data_key>: [...], meta}.

    As with GPO snapshots, extra metadata lines (all_cpasswords,
    inheritance_blocked, ou_inheritance) that are dicts but do not carry the
    expected record fields (e.g. "name"/"username"/"sid") are collected
    separately and added under an "extra" key in the response — they are not
    mixed into the record list.
    """
    in_path = DOMAIN_OBJECT_DIR / filename
    if not in_path.exists():
        return {
            "success": False,
            "error": f"Snapshot file not found: {filename}",
            "code": 404,
        }

    try:
        meta_line, rows = _read_acl_jsonl_snapshot(in_path)
    except Exception as exc:
        return {
            "success": False,
            "error": f"Could not read snapshot ({filename}): {exc}",
            "code": 500,
        }

    records = []
    extra_lines = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        # Extra summary lines written in GPO snapshots (all_cpasswords,
        # inheritance_blocked/ou_inheritance) are separated from the main records.
        if set(row.keys()) <= {"all_cpasswords", "inheritance_blocked", "ou_inheritance"}:
            extra_lines.append(row)
        else:
            records.append(row)

    response = {
        "success": meta_line.get("success", True),
        "count": meta_line.get("count", len(records)),
        data_key: records,
        "meta": {
            **(meta_line.get("meta") or {}),
            "snapshot_type": f"{data_key}-jsonl",
            "snapshot_path": str(in_path),
            "generated_at": meta_line.get("generated_at"),
            "source": meta_line.get("source"),
        },
    }
    if extra_lines:
        merged_extra = {}
        for line in extra_lines:
            merged_extra.update(line)
        response["extra"] = merged_extra

    if not response["success"] and meta_line.get("error"):
        response["error"] = meta_line["error"]

    return response


@app.route("/api/snapshot/<section>", methods=["GET", "POST"])
@limiter.limit("60 per minute")
def read_offline_snapshot(section):
    """
    For ZIP Import (offline) mode — reads domain_<section>.jsonl from the
    Domain Object directory without any LDAP/connect call, and returns it in
    the standard enumeration response format.

    This endpoint does not require a domain connection; after a ZIP import
    the frontend loads all sections (users/computers/ous/gpos/groups/trusts/acl)
    from here.
    """
    section = str(section or "").strip().lower()
    cfg = SNAPSHOT_SECTION_MAP.get(section)
    if not cfg:
        return jsonify({
            "success": False,
            "error": f"Unknown snapshot section: {section}",
            "code": 400,
        }), 400

    filename, data_key = cfg
    result = _read_generic_jsonl_snapshot(filename, data_key)
    status = 200 if result.get("success") else _enumeration_status(result)
    return jsonify(result), status


@app.route("/api/snapshot-status", methods=["GET"])
@limiter.limit("60 per minute")
def snapshot_status():
    """
    Reports which domain_*.jsonl files are present in the Domain Object
    directory — the frontend can use this after a ZIP import to check
    whether offline data is available.
    """
    availability = {}
    for section, (filename, _data_key) in SNAPSHOT_SECTION_MAP.items():
        path = DOMAIN_OBJECT_DIR / filename
        availability[section] = path.exists()
    return jsonify({
        "success": True,
        "domain_object_dir": str(DOMAIN_OBJECT_DIR),
        "available": availability,
        "any_available": any(availability.values()),
    }), 200


# ---------------------------------------------------------------------------
# ZIP Uploader  — extracts files to the Domain Object directory
# ---------------------------------------------------------------------------

@app.route("/api/upload-zip", methods=["POST"])
@limiter.limit("30 per minute")
def upload_zip():
    """
    Extracts the uploaded ZIP file and places all its contents into
    DOMAIN_OBJECT_DIR (/Main/Domain Object/).
    The general Domain Object directory, not the one under Agent Generator.
    """
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file sent.", "code": 400}), 400

    uploaded = request.files["file"]

    if not uploaded.filename:
        return jsonify({"success": False, "error": "Filename is empty.", "code": 400}), 400

    if not uploaded.filename.lower().endswith(".zip"):
        return jsonify({"success": False, "error": "Only ZIP files are accepted.", "code": 400}), 400

    try:
        file_bytes = uploaded.read()
        if len(file_bytes) == 0:
            return jsonify({"success": False, "error": "ZIP file is empty.", "code": 400}), 400

        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            # Zip bomb protection: max 500 MB
            total_size = sum(info.file_size for info in zf.infolist())
            if total_size > 500 * 1024 * 1024:
                return jsonify({"success": False, "error": "ZIP file is too large (max 500 MB).", "code": 400}), 400

            DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)

            extracted_files = []
            skipped = []

            for info in zf.infolist():
                # Skip directories
                if info.filename.endswith("/"):
                    continue

                # Path traversal protection
                safe_name = Path(info.filename).name
                if not safe_name or safe_name.startswith("."):
                    skipped.append(info.filename)
                    continue

                dest_path = DOMAIN_OBJECT_DIR / safe_name

                with zf.open(info) as src, open(dest_path, "wb") as dst:
                    dst.write(src.read())

                extracted_files.append(safe_name)
                logger.info("upload-zip: %s -> %s", info.filename, dest_path)

        # ZIP files extracted to Domain Object directory.
        # Trigger sqlite_engine in the background -- DB is updated immediately.
        threading.Thread(target=_run_sqlite_engine, daemon=True).start()

        return jsonify({
            "success": True,
            "extracted": extracted_files,
            "skipped": skipped,
            "destination": str(DOMAIN_OBJECT_DIR),
            "count": len(extracted_files),
        }), 200

    except zipfile.BadZipFile:
        return jsonify({"success": False, "error": "Invalid ZIP file.", "code": 400}), 400
    except Exception as exc:
        logger.error("upload-zip error: %s", exc)
        return jsonify({"success": False, "error": str(exc), "code": 500}), 500


# ---------------------------------------------------------------------------
# SQLite DB Builder endpoint
# ---------------------------------------------------------------------------

@app.route("/api/build-sqlite-db", methods=["POST"])
@limiter.limit("10 per minute")
def build_sqlite_db():
    """
    Converts hardcoded JSONL files in the Domain Object directory to domain_data.db.
    Called by the frontend after a ZIP import or domain connect.
    Runs in the background -- response is returned immediately.
    """
    if _SQLITE_ENGINE_PATH is None:
        return jsonify({
            "success": False,
            "error": "sqlite_engine.py not found",
        }), 503

    db_out = str(DOMAIN_OBJECT_DIR / "domain_data.db")
    threading.Thread(target=_run_sqlite_engine, daemon=True).start()
    return jsonify({
        "success": True,
        "message": "DB build started in background",
        "output": db_out,
    }), 202


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 30100)),
        debug=False,
        use_reloader=False,
    )