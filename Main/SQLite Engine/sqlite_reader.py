from __future__ import annotations

import argparse
import json
import logging
import signal
import sqlite3
import sys
import time
from pathlib import Path

from flask import Flask, g, jsonify, request

PARENT_TABLES: dict[str, dict[str, str]] = {
    "users":     {"label": "Users",     "name_col": "username"},
    "computers": {"label": "Computers", "name_col": "computer_name"},
    "groups":    {"label": "Groups",    "name_col": "group_name"},
    "gpos":      {"label": "GPOs",      "name_col": "display_name"},
    "ous":       {"label": "OUs",       "name_col": "name"},
    "trusts":    {"label": "Trusts",    "name_col": "trust_partner"},
}

CHILD_TABLES: dict[str, list[tuple[str, str, str]]] = {
    "users": [
        ("user_member_of", "user_rowid", "Member Of"),
        ("user_admin_rules", "user_rowid", "Admin Rules"),
    ],
    "computers": [],
    "groups": [
        ("group_direct_members", "group_rowid", "Direct Members"),
        ("group_member_users",   "group_rowid", "Member Users"),
    ],
    "gpos": [],
    "ous": [
        ("ou_linked_gpos", "ou_rowid", "Linked GPOs"),
        ("ou_gpo_precedence", "ou_rowid", "GPO Precedence"),
        ("ou_inherited_gpos", "ou_rowid", "Inherited GPOs"),
        ("ou_privileged_users", "ou_rowid", "Privileged Users"),
        ("ou_privileged_computers", "ou_rowid", "Privileged Computers"),
    ],
    "trusts": [
        ("trust_risk_findings", "trust_rowid", "Risk Findings"),
    ],
}

STANDALONE_CANDIDATES = ["aces", "dangerous_ace", "extended_rights", "network_hosts", "domain_info"]

DB_PATH: Path | None = None


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def close_db(_exc=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def list_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [r["name"] for r in rows]


def table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f'PRAGMA table_info("{_safe_ident(table)}")').fetchall()
    return [r["name"] for r in rows]


def row_count(conn: sqlite3.Connection, table: str) -> int:
    return conn.execute(f'SELECT COUNT(*) AS c FROM "{_safe_ident(table)}"').fetchone()["c"]


def _safe_ident(name: str) -> str:
    if not name.isidentifier() and not all(c.isalnum() or c == "_" for c in name):
        raise ValueError(f"Invalid identifier: {name!r}")
    return name


def _maybe_parse_json(value):
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            try:
                return json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                return value
    return value


def row_to_dict(row: sqlite3.Row) -> dict:
    return {k: _maybe_parse_json(row[k]) for k in row.keys()}


def fetch_parent_object(conn: sqlite3.Connection, table: str, obj_id: int) -> dict | None:
    cols = table_columns(conn, table)
    if "id" not in cols:
        return None
    row = conn.execute(
        f'SELECT *, rowid FROM "{_safe_ident(table)}" WHERE rowid = ?', (obj_id,)
    ).fetchone()
    if row is None:
        return None

    result = {"_table": table, "attributes": row_to_dict(row), "children": {}}

    for child_table, fk_col, label in CHILD_TABLES.get(table, []):
        try:
            child_rows = conn.execute(
                f'SELECT * FROM "{_safe_ident(child_table)}" '
                f'WHERE "{_safe_ident(fk_col)}" = ? ORDER BY id',
                (obj_id,),
            ).fetchall()
        except sqlite3.OperationalError:
            continue
        result["children"][child_table] = {
            "label": label,
            "rows": [row_to_dict(r) for r in child_rows],
        }
    return result


app = Flask(__name__)
app.teardown_appcontext(close_db)


@app.before_request
def _log_request_start():
    g._req_started_at = time.monotonic()


@app.after_request
def _log_request_done(resp):
    started = getattr(g, "_req_started_at", None)
    elapsed_ms = f"{(time.monotonic() - started) * 1000:.1f}ms" if started else "?"
    qs = f"?{request.query_string.decode()}" if request.query_string else ""
    logging.info(
        "%s %s%s -> %s (%s) [%s]",
        request.method, request.path, qs, resp.status_code, elapsed_ms,
        request.remote_addr,
    )
    return resp


@app.after_request
def _add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return resp


@app.errorhandler(400)
def err_400(e): return jsonify({"error": "Bad Request", "detail": str(e)}), 400

@app.errorhandler(404)
def err_404(e): return jsonify({"error": "Not Found", "detail": str(e)}), 404

@app.errorhandler(405)
def err_405(e): return jsonify({"error": "Method Not Allowed", "detail": str(e)}), 405

@app.errorhandler(500)
def err_500(e): return jsonify({"error": "Internal Server Error", "detail": str(e)}), 500


@app.route("/api/health")
def api_health():
    try:
        conn = get_db()
        tables = list_tables(conn)
        return jsonify({
            "status": "ok",
            "db_path": str(DB_PATH),
            "table_count": len(tables),
        })
    except Exception as exc:
        return jsonify({"status": "error", "detail": str(exc)}), 500


@app.route("/api/tables")
def api_tables():
    conn = get_db()
    all_tables = list_tables(conn)
    counts = {t: row_count(conn, t) for t in all_tables}

    parents = [t for t in PARENT_TABLES if t in all_tables]
    standalone = [t for t in STANDALONE_CANDIDATES if t in all_tables]
    known_children = {ct for lst in CHILD_TABLES.values() for ct, _, _ in lst}
    other = [t for t in all_tables if t not in parents and t not in standalone
             and t not in known_children]

    return jsonify({
        "db_path": str(DB_PATH),
        "counts": counts,
        "parents": [{"table": t, "label": PARENT_TABLES[t]["label"], "count": counts[t]}
                     for t in parents],
        "standalone": [{"table": t, "count": counts[t]} for t in standalone],
        "other": [{"table": t, "count": counts[t]} for t in other],
    })


def _child_field_name(child_table: str, fk_col: str) -> str:
    """Derives the JSON field name for a child table (e.g. 'user_admin_rules'
    + 'user_rowid' -> 'admin_rules'), matching the convention used by
    _export_parent_records."""
    prefix = fk_col[:-len("_rowid")] if fk_col.endswith("_rowid") else fk_col
    return (
        child_table[len(prefix) + 1:]
        if child_table.startswith(prefix + "_")
        else child_table
    )


def _attach_child_data(conn: sqlite3.Connection, table: str, rows: list[dict]) -> None:
    """Mutates `rows` (parent records) in place, adding one key per child
    table registered for `table` in CHILD_TABLES (e.g. 'admin_rules',
    'member_of'), populated only for the given page of parent ids.

    This mirrors what _export_parent_records does for the full table, but is
    scoped to just the ids present in `rows` so it stays cheap for paginated
    /api/list calls.
    """
    child_specs = CHILD_TABLES.get(table, [])
    if not child_specs or not rows:
        return

    ids = [r["id"] for r in rows if "id" in r]
    if not ids:
        return
    by_id = {r["id"]: r for r in rows if "id" in r}
    id_placeholders = ", ".join("?" for _ in ids)

    for child_table, fk_col, _label in child_specs:
        field_name = _child_field_name(child_table, fk_col)
        # Default every row to an empty list so the frontend always sees the key.
        for rec in rows:
            rec.setdefault(field_name, [])

        try:
            child_cols = table_columns(conn, child_table)
            child_rows = conn.execute(
                f'SELECT * FROM "{_safe_ident(child_table)}" '
                f'WHERE "{_safe_ident(fk_col)}" IN ({id_placeholders}) '
                f'ORDER BY id',
                ids,
            ).fetchall()
        except sqlite3.OperationalError:
            continue

        value_cols = [c for c in child_cols if c not in ("id", fk_col)]
        for r in child_rows:
            d = row_to_dict(r)
            fk_val = d.get(fk_col)
            parent = by_id.get(fk_val)
            if parent is None:
                continue
            if len(value_cols) == 1:
                item = d.get(value_cols[0])
            else:
                item = {c: d.get(c) for c in value_cols}
            parent[field_name].append(item)


@app.route("/api/list/<table>")
def api_list(table: str):
    conn = get_db()
    if table not in list_tables(conn):
        return jsonify({"error": f"Table not found: {table}"}), 404

    cols = table_columns(conn, table)
    q = request.args.get("q", "").strip()
    target_q = request.args.get("target", "").strip()
    principal_q = request.args.get("principal", "").strip()
    offset = max(int(request.args.get("offset", 0)), 0)
    limit = min(max(int(request.args.get("limit", 2000)), 1), 500000)
    order_col = request.args.get("order", "id" if "id" in cols else cols[0])
    direction = "DESC" if request.args.get("dir", "asc").lower() == "desc" else "ASC"
    if order_col not in cols:
        order_col = "id" if "id" in cols else cols[0]

    where_clauses: list = []
    params: list = []

    if q:
        where_clauses.append(
            "(" + " OR ".join(f'"{_safe_ident(c)}" LIKE ?' for c in cols) + ")"
        )
        params.extend([f"%{q}%"] * len(cols))

    # Filter Target — matches target_name / target_dn when present on the table
    # (aces, dangerous_ace, extended_rights all carry these columns).
    target_cols = [c for c in ("target_name", "target_dn") if c in cols]
    if target_q and target_cols:
        where_clauses.append(
            "(" + " OR ".join(f'"{_safe_ident(c)}" LIKE ?' for c in target_cols) + ")"
        )
        params.extend([f"%{target_q}%"] * len(target_cols))

    # Filter Principal — matches principal / principal_sid when present.
    principal_cols = [c for c in ("principal", "principal_sid") if c in cols]
    if principal_q and principal_cols:
        where_clauses.append(
            "(" + " OR ".join(f'"{_safe_ident(c)}" LIKE ?' for c in principal_cols) + ")"
        )
        params.extend([f"%{principal_q}%"] * len(principal_cols))

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    total = conn.execute(
        f'SELECT COUNT(*) AS c FROM "{_safe_ident(table)}" {where_sql}', params
    ).fetchone()["c"]

    rows = conn.execute(
        f'SELECT *, rowid FROM "{_safe_ident(table)}" {where_sql} '
        f'ORDER BY "{_safe_ident(order_col)}" {direction} LIMIT ? OFFSET ?',
        (*params, limit, offset),
    ).fetchall()

    records = [row_to_dict(r) for r in rows]
    # Enrich each row with its child-table data (e.g. users -> admin_rules,
    # member_of) so paginated list views show the same data as /api/users.
    _attach_child_data(conn, table, records)

    return jsonify({
        "table": table,
        "columns": cols,
        "total": total,
        "offset": offset,
        "limit": limit,
        "rows": records,
    })


@app.route("/api/object/<table>/<int:obj_id>")
def api_object(table: str, obj_id: int):
    conn = get_db()
    if table not in PARENT_TABLES:
        return jsonify({"error": f"Unknown parent table: {table}"}), 404
    obj = fetch_parent_object(conn, table, obj_id)
    if obj is None:
        return jsonify({"error": "Not found"}), 404
    obj["label"] = PARENT_TABLES[table]["label"]
    return jsonify(obj)


def _export_parent_records(conn: sqlite3.Connection, table: str) -> list[dict]:
    cols = table_columns(conn, table)
    if "id" not in cols:
        raise ValueError(f"Table '{table}' has no id column")

    parent_rows = conn.execute(
        f'SELECT * FROM "{_safe_ident(table)}" ORDER BY id'
    ).fetchall()
    records = [row_to_dict(r) for r in parent_rows]
    by_id = {rec["id"]: rec for rec in records if "id" in rec}

    for child_table, fk_col, _label in CHILD_TABLES.get(table, []):
        prefix = fk_col[:-len("_rowid")] if fk_col.endswith("_rowid") else fk_col
        field_name = (
            child_table[len(prefix) + 1:]
            if child_table.startswith(prefix + "_")
            else child_table
        )

        try:
            child_cols = table_columns(conn, child_table)
            child_rows = conn.execute(
                f'SELECT * FROM "{_safe_ident(child_table)}"'
            ).fetchall()
        except sqlite3.OperationalError:
            continue

        value_cols = [c for c in child_cols if c not in ("id", fk_col)]
        grouped: dict = {}
        for r in child_rows:
            d = row_to_dict(r)
            fk_val = d.get(fk_col)
            if len(value_cols) == 1:
                item = d.get(value_cols[0])
            else:
                item = {c: d.get(c) for c in value_cols}
            grouped.setdefault(fk_val, []).append(item)

        for parent_id, rec in by_id.items():
            rec[field_name] = grouped.get(parent_id, [])

    return records


@app.route("/api/export/<table>")
def api_export(table: str):
    conn = get_db()
    if table not in PARENT_TABLES:
        return jsonify({"error": f"Unknown parent table: {table}"}), 404
    try:
        records = _export_parent_records(conn, table)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({
        "success": True,
        "table": table,
        "count": len(records),
        "rows": records,
    })


def _render_parent_table(table: str, data_key: str):
    conn = get_db()
    if table not in PARENT_TABLES:
        return jsonify({"success": False, "error": f"Unknown parent table: {table}"}), 404
    try:
        records = _export_parent_records(conn, table)
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 500

    return jsonify({
        "success": True,
        "count": len(records),
        data_key: records,
        "meta": {
            "source": "sqlite",
            "table": table,
            "db_path": str(DB_PATH),
        },
    })


@app.route("/api/users")
def api_users():
    return _render_parent_table("users", "users")

@app.route("/api/computers")
def api_computers():
    return _render_parent_table("computers", "computers")

@app.route("/api/groups")
def api_groups():
    return _render_parent_table("groups", "groups")

@app.route("/api/ous")
def api_ous():
    return _render_parent_table("ous", "ous")

@app.route("/api/gpos")
def api_gpos():
    return _render_parent_table("gpos", "gpos")

@app.route("/api/trust")
def api_trust():
    return _render_parent_table("trusts", "trusts")


@app.route("/api/query", methods=["POST"])
def api_query():
    body = request.get_json(silent=True) or {}
    sql = (body.get("sql") or "").strip()
    if not sql:
        return jsonify({"error": "Empty query"}), 400

    lowered = sql.lower()
    if not lowered.startswith("select"):
        return jsonify({"error": "Only SELECT statements are allowed"}), 400
    forbidden = ["insert", "update", "delete", "drop", "attach", "pragma",
                 "alter", "create", "replace", "vacuum", ";"]
    if any(tok in lowered for tok in forbidden):
        return jsonify({"error": "Query contains a forbidden keyword (only a single SELECT is allowed)"}), 400

    conn = get_db()
    try:
        cur = conn.execute(sql)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description] if cur.description else []
        return jsonify({
            "columns": cols,
            "rows": [row_to_dict(r) for r in rows],
            "row_count": len(rows),
        })
    except sqlite3.Error as exc:
        return jsonify({"error": str(exc)}), 400


def _setup_logging() -> None:
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    handler = logging.StreamHandler(sys.stdout)
    handler.setStream(sys.stdout)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[handler],
        force=True,
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def _install_signal_handlers() -> None:
    def _shutdown(signum, _frame):
        logging.info("Signal %s received, shutting down.", signum)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sqlite_reader",
        description="Serves domain_data.db as a read-only REST API over HTTP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python sqlite_reader.py domain_data.db
  python sqlite_reader.py domain_data.db --port 9000

Endpoints:
  GET  /api/health
  GET  /api/tables
  GET  /api/list/<table>?q=&offset=0&limit=200&order=id&dir=asc
  GET  /api/object/<table>/<id>
  GET  /api/export/<table>
  POST /api/query   body: {"sql": "SELECT ..."}

  GET  /api/users | /api/computers | /api/groups | /api/ous | /api/gpos | /api/trust
        """,
    )
    parser.add_argument("db_path", help="Path to the .db file")
    parser.add_argument(
        "--port", type=int, default=8800,
        help="Bind port (default: 8800)",
    )

    args = parser.parse_args(argv)

    _setup_logging()

    db_path = Path(args.db_path).resolve()
    if not db_path.is_file():
        logging.info("DB file not found, creating an empty database: %s", db_path)
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            init_conn = sqlite3.connect(str(db_path))
            init_conn.execute("PRAGMA journal_mode=WAL")
            init_conn.commit()
            init_conn.close()
        except OSError as exc:
            print(f"ERROR: could not create '{db_path}' ({exc})", file=sys.stderr)
            return 1

    try:
        test_conn = sqlite3.connect(str(db_path))
        test_conn.execute("SELECT name FROM sqlite_master LIMIT 1")
        test_conn.close()
    except sqlite3.Error as exc:
        print(f"ERROR: '{db_path}' is not a valid SQLite file ({exc})", file=sys.stderr)
        return 1

    global DB_PATH
    DB_PATH = db_path

    _install_signal_handlers()

    host = "127.0.0.1"

    logging.info("SQLite API Server starting")
    logging.info("DB      : %s", DB_PATH)
    logging.info("Address : http://%s:%s", host, args.port)
    logging.info("Health  : http://%s:%s/api/health", host, args.port)

    app.run(
        host=host,
        port=args.port,
        debug=False,
        threaded=True,
        use_reloader=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())