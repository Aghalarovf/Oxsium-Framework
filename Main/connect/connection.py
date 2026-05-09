"""
connection.py — Flask application entry point.

All business logic lives in the `connect/` package:
  connect/config.py        Config class & logging
  connect/utils.py         Validation & LDAP string helpers
  connect/network.py       TCP port probing
  connect/ldap_core.py     LDAP environment collection & enumeration fallback
  connect/protocols.py     Protocol connect functions + PROTOCOL_HANDLERS
  connect/shell.py         Shell command runners & PowerShell profile helpers
  connect/tools.py         External tool runners (C inventory, SMB checker)
  connect/saved_users.py   Saved-user JSON persistence
  connect/flask_helpers.py Flask decorators & shared request parsing
  connect/connection_fast.py  Fast-connect strategy
  connect/connection_deep.py  Deep-connect defaults & env enrichment
"""

import os
import sys
import json
import re
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

DOMAIN_OBJECT_DIR = Path(PROJECT_ROOT) / "Domain Object"
LEGACY_DOMAIN_USERS_JSON = Path(PROJECT_ROOT) / "domain_users.json"
LEGACY_DOMAIN_COMPUTERS_JSON = Path(PROJECT_ROOT) / "domain_computers.json"
LEGACY_DOMAIN_OUS_JSON = Path(PROJECT_ROOT) / "domain_ous.json"
LEGACY_DOMAIN_GROUPS_JSON = Path(PROJECT_ROOT) / "domain_groups.json"
LEGACY_DOMAIN_TRUSTS_JSON = Path(PROJECT_ROOT) / "domain_trusts.json"
LEGACY_DOMAIN_GPOS_JSON = Path(PROJECT_ROOT) / "domain_gpos.json"
LEGACY_DOMAIN_ACES_JSON = Path(PROJECT_ROOT) / "domain_aces.json"
DOMAIN_ACES_PARQUET = DOMAIN_OBJECT_DIR / "domain_aces.parquet"
DOMAIN_ACES_JSON = DOMAIN_OBJECT_DIR / "domain_aces.json"
DOMAIN_EXTENDED_RIGHTS_JSON = DOMAIN_OBJECT_DIR / "domain_extended_rights.json"
DOMAIN_DANGEROUS_ACE_JSON = DOMAIN_OBJECT_DIR / "domain_dangerous_ace.json"
DOMAIN_USERS_JSON = DOMAIN_OBJECT_DIR / "domain_users.json"
DOMAIN_COMPUTERS_JSON = DOMAIN_OBJECT_DIR / "domain_computers.json"
DOMAIN_GROUPS_JSON = DOMAIN_OBJECT_DIR / "domain_groups.json"

from user import users_dump as users
from computer import computers
from group import groups
from group import group_member
from ou import ous
from gpo import gpos
from trust import trusts
from acl import AclFilterConfig, get_domain_acls
from acl.constants import _DEFAULT_TRUSTEE_RIDS, _DEFAULT_TRUSTEE_SIDS

from connect.config        import Config, logger
from connect.utils         import validate_ip, validate_domain, validate_username
from connect.network       import _tcp_probe, check_port
from connect.ldap_core     import (
    _collect_ldap_environment_with_fallback,
    _collect_counts_via_enumeration_fallback,
    _run_enumeration_with_target_fallback,
)
from connect.protocols     import connect_ldap_fast, connect_local, PROTOCOL_HANDLERS
from connect.shell         import (
    run_local_command, run_winrm_command, run_ssh_command,
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
    Overwrite domain_users.json on every /api/users request.
    Keeps all enumerated user attributes (including admin rules/reasons when present).
    """
    out_path = DOMAIN_OBJECT_DIR / "domain_users.json"

    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": "local" if is_local else "domain",
        "success": bool(result.get("success")),
        "count": int(result.get("count") or 0),
        "users": list(result.get("users") or []),
        "meta": result.get("meta") or {},
        "error": result.get("error") if not result.get("success") else None,
    }

    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)
        # `w` mode guarantees old content is replaced on every request.
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

        # Remove old legacy file in repo root so consumers use a single source.
        if LEGACY_DOMAIN_USERS_JSON.exists() and LEGACY_DOMAIN_USERS_JSON != out_path:
            try:
                LEGACY_DOMAIN_USERS_JSON.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy users snapshot %s: %s", LEGACY_DOMAIN_USERS_JSON, exc)
    except Exception as exc:
        logger.warning("Could not write domain users snapshot to %s: %s", out_path, exc)


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
    Generic Domain Object snapshot writer.

    Uses overwrite semantics (`w` mode via write_text) on every request so stale
    context is cleared and replaced with the latest enumeration result.
    """
    out_path = DOMAIN_OBJECT_DIR / filename

    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": "local" if is_local else "domain",
        "success": bool(result.get("success")),
        "count": int(result.get("count") or 0),
        data_key: list(result.get(data_key) or []),
        "meta": result.get("meta") or {},
        "error": result.get("error") if not result.get("success") else None,
    }

    try:
        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

        if legacy_path and legacy_path.exists() and legacy_path != out_path:
            try:
                legacy_path.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy snapshot %s: %s", legacy_path, exc)
    except Exception as exc:
        logger.warning("Could not write domain snapshot to %s: %s", out_path, exc)


def _write_domain_aces_snapshot(result: dict, is_local: bool) -> None:
    """
    Write ACL findings to domain_aces.parquet (ZSTD) for compact storage and fast scans.

    On every enumeration run this overwrites the previous parquet snapshot so stale
    context is cleared automatically.
    """
    out_path = DOMAIN_ACES_PARQUET
    aces = list(result.get("acls") or result.get("aces") or [])

    try:
        import pyarrow as pa  # pyright: ignore[reportMissingImports]
        import pyarrow.parquet as pq  # pyright: ignore[reportMissingImports]

        DOMAIN_OBJECT_DIR.mkdir(parents=True, exist_ok=True)

        generated_at = datetime.utcnow().isoformat() + "Z"
        source = "local" if is_local else "domain"
        success = bool(result.get("success"))
        count = int(result.get("count") or 0)
        error = result.get("error") if not success else None

        # Keep per-record context columns so queries don't need a sidecar file.
        rows: list[dict] = []
        if aces:
            for ace in aces:
                row = dict(ace or {})
                row["generated_at"] = generated_at
                row["source"] = source
                row["snapshot_success"] = success
                row["snapshot_count"] = count
                row["snapshot_error"] = error
                rows.append(row)
        else:
            # Ensure snapshot metadata still exists even when there are no ACE rows.
            rows.append({
                "generated_at": generated_at,
                "source": source,
                "snapshot_success": success,
                "snapshot_count": count,
                "snapshot_error": error,
            })

        table = pa.Table.from_pylist(rows)
        pq.write_table(table, out_path, compression="zstd", use_dictionary=True)

        # Remove old JSON snapshots to avoid storage bloat.
        if DOMAIN_ACES_JSON.exists():
            try:
                DOMAIN_ACES_JSON.unlink()
            except Exception as exc:
                logger.warning("Could not remove old ACL JSON snapshot %s: %s", DOMAIN_ACES_JSON, exc)

        if LEGACY_DOMAIN_ACES_JSON.exists() and LEGACY_DOMAIN_ACES_JSON != out_path:
            try:
                LEGACY_DOMAIN_ACES_JSON.unlink()
            except Exception as exc:
                logger.warning("Could not remove legacy ACL snapshot %s: %s", LEGACY_DOMAIN_ACES_JSON, exc)
    except Exception as exc:
        logger.warning("Could not write domain ACL parquet snapshot to %s: %s", out_path, exc)


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
    """Write dangerous ACE subset to domain_dangerous_ace.json for fast reuse."""
    out_path = DOMAIN_DANGEROUS_ACE_JSON
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

        payload = {
            "success": True,
            "count": len(rows),
            "acls": rows,
            "meta": {
                "generated_at": generated_at,
                "source": source,
                "snapshot_type": "dangerous-ace-json",
                "snapshot_path": str(out_path),
                "snapshot_success": success,
                "snapshot_count": count,
                "snapshot_error": error,
                "snapshot_rows": len(rows),
            },
        }

        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not write dangerous ACE snapshot to %s: %s", out_path, exc)


def _read_domain_dangerous_ace_snapshot() -> dict:
    """Read dangerous ACE subset from domain_dangerous_ace.json."""
    if not DOMAIN_DANGEROUS_ACE_JSON.exists():
        return {
            "success": False,
            "error": f"ACL snapshot not found: {DOMAIN_DANGEROUS_ACE_JSON}",
            "code": 404,
        }

    try:
        raw = json.loads(DOMAIN_DANGEROUS_ACE_JSON.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Invalid ACL snapshot format")

        rows = raw.get("acls") if isinstance(raw.get("acls"), list) else []
        filtered = [dict(r) for r in rows if isinstance(r, dict)]

        meta = raw.get("meta") if isinstance(raw.get("meta"), dict) else {}
        meta = dict(meta)
        meta.update({
            "snapshot_type": "dangerous-ace-json",
            "snapshot_path": str(DOMAIN_DANGEROUS_ACE_JSON),
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
    """Read full ACL rows from domain_aces.parquet."""
    if not DOMAIN_ACES_PARQUET.exists():
        return {
            "success": False,
            "error": f"ACL snapshot not found: {DOMAIN_ACES_PARQUET}",
            "code": 404,
        }

    try:
        import pyarrow.parquet as pq  # pyright: ignore[reportMissingImports]

        table = pq.read_table(DOMAIN_ACES_PARQUET)
        raw_rows = table.to_pylist()
        rows: list[dict] = []
        for row in raw_rows:
            if not isinstance(row, dict):
                continue
            if not any(k in row for k in ("target_name", "target_dn", "principal_sid", "rights")):
                continue
            clean = dict(row)
            for key in ("generated_at", "source", "snapshot_success", "snapshot_count", "snapshot_error"):
                clean.pop(key, None)
            if isinstance(clean.get("rights"), tuple):
                clean["rights"] = list(clean["rights"])
            rows.append(clean)

        return {
            "success": True,
            "count": len(rows),
            "acls": rows,
            "meta": {
                "snapshot_type": "all-aces-parquet",
                "snapshot_path": str(DOMAIN_ACES_PARQUET),
                "snapshot_rows": len(rows),
            },
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Could not read ACL parquet snapshot: {exc}",
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
    """Write extended-right ACEs to domain_extended_rights.json for fast reuse."""
    out_path = DOMAIN_EXTENDED_RIGHTS_JSON
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

        payload = {
            "success": True,
            "count": len(rows),
            "acls": rows,
            "meta": {
                "generated_at": generated_at,
                "source": source,
                "snapshot_type": "extended-rights-json",
                "snapshot_path": str(out_path),
                "snapshot_success": success,
                "snapshot_count": count,
                "snapshot_error": error,
                "snapshot_rows": len(rows),
            },
        }

        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning("Could not write extended-rights snapshot to %s: %s", out_path, exc)


def _read_domain_extended_rights_snapshot() -> dict:
    """Read extended-right ACEs from domain_extended_rights.json."""
    if not DOMAIN_EXTENDED_RIGHTS_JSON.exists():
        return {
            "success": False,
            "error": f"ACL snapshot not found: {DOMAIN_EXTENDED_RIGHTS_JSON}",
            "code": 404,
        }

    try:
        raw = json.loads(DOMAIN_EXTENDED_RIGHTS_JSON.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Invalid ACL snapshot format")

        rows = raw.get("acls") if isinstance(raw.get("acls"), list) else []
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

        meta = raw.get("meta") if isinstance(raw.get("meta"), dict) else {}
        meta = dict(meta)
        meta.update({
            "snapshot_type": "extended-rights-json",
            "snapshot_path": str(DOMAIN_EXTENDED_RIGHTS_JSON),
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
    """Read SID values from a Domain Object snapshot JSON list."""
    if not snapshot_path.exists():
        return []

    try:
        raw = json.loads(snapshot_path.read_text(encoding="utf-8"))
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
        logger.warning("Could not read SID snapshot %s: %s", snapshot_path, exc)
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

    if password and hash_value:
        return jsonify({"error": "Use either password or NTLM hash, not both"}), 400
    if not password and not hash_value:
        return jsonify({"error": "Missing fields: password or hash"}), 400

    auth_secret = password or hash_value

    if not validate_ip(ip) or not validate_domain(domain) or not validate_username(username):
        return jsonify({"error": "Invalid input formats"}), 400
    if proto not in PROTOCOL_HANDLERS:
        return jsonify({"error": f"Unsupported protocol: {proto}"}), 400

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

        if connect_mode == "fast":
            return jsonify(result)

        apply_deep_defaults(result, ip, check_port=check_port)

        if connect_mode == "deep" and skip_counts:
            return jsonify(result)

        enrich_with_env_probe(
            result=result,
            req=req,
            ip=ip,
            collect_ldap_environment_with_fallback=_collect_ldap_environment_with_fallback,
            collect_counts_via_enumeration_fallback=_collect_counts_via_enumeration_fallback,
        )

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
    _write_domain_object_snapshot(
        filename="domain_computers.json",
        result=result,
        is_local=is_local_request(req),
        data_key="computers",
        legacy_path=LEGACY_DOMAIN_COMPUTERS_JSON,
    )
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
    _write_domain_object_snapshot(
        filename="domain_gpos.json",
        result=result,
        is_local=is_local_request(req),
        data_key="gpos",
        legacy_path=LEGACY_DOMAIN_GPOS_JSON,
    )
    return (jsonify(result), 200) if result.get("success") else (jsonify(result), _enumeration_status(result))


@app.route("/api/groups", methods=["POST"])
@app.route("/api/group", methods=["POST"])
@limiter.limit(Config.RATE_LIMIT_ENUM)
def list_groups():
    req, error_response = get_enumeration_request_data()
    if error_response:
        return error_response
    result = (
        _local_enumeration_removed("Group")
        if is_local_request(req)
        else _run_enumeration_with_target_fallback(req, groups.get_domain_groups)
    )
    _write_domain_object_snapshot(
        filename="domain_groups.json",
        result=result,
        is_local=is_local_request(req),
        data_key="groups",
        legacy_path=LEGACY_DOMAIN_GROUPS_JSON,
    )
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
        return group_member.get_group_members(ip, domain, username, password, group_dn, config)

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
                str(DOMAIN_EXTENDED_RIGHTS_JSON),
            ) if source_result.get("success") else source_result
            should_refresh_snapshots = bool(source_result.get("success"))
        elif acl_filter_name == "live-dangerous":
            source_result = _run_enumeration_with_target_fallback(req, _get_acls_with_filter)
            result = _acl_subset_result(
                source_result,
                _extract_dangerous_rows(source_result),
                "dangerous-ace-live",
                str(DOMAIN_DANGEROUS_ACE_JSON),
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
    protocol = req.get("protocol", "winrm").lower()

    if not command:
        return jsonify({"error": "Command is required"}), 400

    if mode == "local":
        result = run_local_command(command)
        return jsonify(result) if result.get("success") else (jsonify(result), 500)

    ip       = req.get("ip")
    domain   = req.get("domain")
    user     = req.get("username")
    password = req.get("password")
    if not ip or not user or not password or not domain:
        return jsonify({"error": "Missing shell connection fields"}), 400

    if protocol == "winrm":
        result = run_winrm_command(ip, user, password, domain, command)
    elif protocol == "ssh":
        result = run_ssh_command(ip, user, password, command)
    else:
        return jsonify({"success": False, "error": f"Shell is not supported for protocol: {protocol}"}), 400

    return jsonify(result) if result.get("success") else (jsonify(result), 500)


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


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=False,
        use_reloader=False,
    )