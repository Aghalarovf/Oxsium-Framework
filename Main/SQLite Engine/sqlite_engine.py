from __future__ import annotations

import argparse
import json
import logging
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

logger = logging.getLogger("jsonl_to_sqlite")


# --------------------------------------------------------------------------- #
# Helper types
# --------------------------------------------------------------------------- #

@dataclass
class ChildTableSpec:
    """Definition for extracting a list field from a parent record into a separate table."""

    # Key in the parent object (e.g. "spn", "open_ports", "transitive_member_sids")
    source_key: str
    # Name of the child table to create (e.g. "computer_spns")
    table_name: str
    # FK column name pointing back to the parent (e.g. "computer_rowid")
    parent_fk: str
    # If list elements are dicts: {column_name: dict_key} mapping.
    # If list elements are plain scalars (str/int) use None — a "value" column is used.
    columns: dict[str, str] | None = None


@dataclass
class TableSpec:
    """Describes how a domain_*.jsonl file will be converted into tables."""

    table_name: str
    # Explicit column list for simple (scalar) fields. If None, determined
    # automatically from the first record (generic fallback).
    scalar_columns: list[str] | None = None
    # Fields to store as JSON TEXT (metadata lists/dicts)
    json_columns: list[str] = field(default_factory=list)
    # Fields to extract into a separate child table
    child_tables: list[ChildTableSpec] = field(default_factory=list)
    # Primary/unique search columns (for indexing, optional)
    index_columns: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Domain-specific schema definitions
# --------------------------------------------------------------------------- #

def _build_known_specs() -> dict[str, TableSpec]:
    """Returns a TableSpec dictionary for known domain_*.jsonl files."""

    specs: dict[str, TableSpec] = {}

    # ---------------- domain_info.jsonl (single record, domain-level) -------
    specs["domain_info"] = TableSpec(
        table_name="domain_info",
        scalar_columns=[
            "fqdn", "netbios_name", "domain_sid", "functional_level",
            "functional_level_name", "generated_at", "has_enterprise_ca",
            "laps_legacy", "laps_windows", "laps_enabled",
            "smb_signing_policy_present", "smb_signing_enabled",
            "smb_signing_required", "ntlm_supported", "smart_card_required",
            "machine_account_quota", "risk_score", "highest_severity",
            "success", "count", "error",
            # ── fsmo / password_policy / kerberos_policy dicts, flattened by
            #    _flatten_known_dicts() into "<dict>__<subkey>" columns.
            #    These MUST be listed here explicitly — since scalar_columns
            #    is not None for this spec, _write_record() only writes keys
            #    that appear in this list, so omitting them means they're
            #    silently dropped even though they're computed. ──
            "fsmo__schema_master", "fsmo__naming_master", "fsmo__rid_master",
            "fsmo__pdc_emulator", "fsmo__infrastructure",
            "password_policy__min_length", "password_policy__complexity_enabled",
            "password_policy__max_age_days", "password_policy__min_age_days",
            "password_policy__history_count", "password_policy__lockout_threshold",
            "password_policy__lockout_duration_mins",
            "password_policy__lockout_observation_mins",
            "password_policy__reversible_encryption",
            "password_policy__pwd_properties_raw",
            "kerberos_policy__max_ticket_age_hours",
            "kerberos_policy__max_renew_age_days",
            "kerberos_policy__max_service_age_mins",
            "kerberos_policy__max_clock_skew_mins",
        ],
        json_columns=["fine_grained_policies", "ca_list", "dns_zones", "meta"],
        child_tables=[
            ChildTableSpec(
                source_key="domain_controllers",
                table_name="domain_controllers",
                parent_fk="domain_info_rowid",
                columns={
                    "dn": "dn", "cn": "cn", "dns_name": "dns_name", "os": "os",
                    "os_version": "os_version", "sid": "sid",
                    "enc_types": "enc_types",
                    "is_schema_master": "is_schema_master",
                    "is_naming_master": "is_naming_master",
                    "is_rid_master": "is_rid_master",
                    "is_pdc_emulator": "is_pdc_emulator",
                    "is_infrastructure_master": "is_infrastructure_master",
                },
            ),
            ChildTableSpec(
                source_key="risk_findings",
                table_name="domain_info_risk_findings",
                parent_fk="domain_info_rowid",
                columns={
                    "severity": "severity", "code": "code",
                    "title": "title", "detail": "detail",
                },
            ),
        ],
    )
    # We add the fsmo / password_policy / kerberos_policy dicts as flat columns
    # (these are processed at runtime via "_FLATTEN_DICTS", see below)

    # ---------------- domain_users.jsonl -------------------------------------
    specs["domain_users"] = TableSpec(
        table_name="users",
        scalar_columns=[
            "username", "dn", "display_name", "sid", "upn", "description",
            "mail", "phone", "department", "title", "disabled", "locked_out",
            "must_change_pwd", "smartcard_required", "normal_account",
            "pwd_never_expires", "pwd_not_required", "pwd_cant_change",
            "preauth_required", "is_admin", "potential_admin",
            "is_direct_admin", "is_nested_admin", "dcsync", "asrep",
            "kerberoastable", "trusted_for_delegation",
            "unconstrained_delegation", "constrained_delegation",
            "delegation_effective", "delegation_blocked",
            "trusted_to_auth_for_delegation", "protocol_transition_delegation",
            "not_delegated", "msds_supportedencryptiontypes",
            "enc_risk_score", "enc_implicit_rc4", "when_created",
            "when_changed", "last_logon", "pwd_last_set", "logon_count",
            "domain_sid", "primary_group_id", "primary_group_sid",
            "bad_pwd_count", "bad_pwd_time", "account_expires",
            "account_never_expires", "msds_resultant_pso", "pwd_expiry_time",
            "has_key_credential_link", "script_path", "home_directory",
            "home_drive",
            # ── AD Recycle Bin / tombstone (users_dump.py tərəfindən yazılır) ──
            "deleted", "deleted_dn", "last_known_parent", "when_deleted",
        ],
        json_columns=[
            "spn", "msds_allowedtodelegateto",
            "msds_allowedtodelegateto_structurized",
            "msds_supportedencryptiontypesname",
            "msds_supportedencryptiontypes_name", "key_credential_link",
        ],
        child_tables=[
            ChildTableSpec(
                source_key="member_of",
                table_name="user_member_of",
                parent_fk="user_rowid",
                columns=None,  # simple string list -> "value" column
            ),
            ChildTableSpec(
                source_key="admin_rules",
                table_name="user_admin_rules",
                parent_fk="user_rowid",
                columns={
                    "level": "level", "severity": "severity",
                    "label": "label", "detail": "detail_json",
                },
            ),
        ],
        index_columns=["sid", "username", "dn", "deleted"],
    )

    # ---------------- domain_computers.jsonl ----------------------------------
    specs["domain_computers"] = TableSpec(
        table_name="computers",
        scalar_columns=[
            "computer_name", "dns_name", "dn", "display_name", "sid",
            "domainsid", "description", "location", "disabled", "os",
            "os_version", "os_service_pack", "os_bucket", "is_workstation",
            "is_server", "is_domain_controller", "potential_privileged",
            "is_stale", "stale_by_pwd", "stale_by_logon", "has_spn",
            "trusted_for_delegation", "trusted_to_auth_for_delegation",
            "unconstrained_delegation", "constrained_delegation",
            "protocol_transition_delegation", "delegation_effective",
            "rbcd_enabled", "rbcd_sddl", "has_laps", "haslaps",
            "laps_expiration", "isaclprotected", "primary_group_id",
            "primary_group_sid", "kerberoastable", "asrep",
            "has_shadow_credential", "risk_score", "smb_port_open",
            "smb_signing_required", "smb_version", "is_ip_only",
            "when_created", "when_changed", "last_logon", "pwd_last_set",
            "domain_name",
        ],
        json_columns=[
            "spn", "allowed_to_delegate_to", "allowed_to_delegate_to_structured",
            "rbcd_principals", "rbcd_principal_names", "laps_attributes",
            "sid_history", "token_group_sids", "risk_factors", "risk_controls",
            "ipv4_addresses", "ipv6_addresses",
        ],
        index_columns=["sid", "computer_name", "dn"],
    )

    # ---------------- domain_groups.jsonl --------------------------------------
    # Real JSONL strukturu (get_all_group_members çıxışı):
    #   Scalar: group_name, group_dn, group_sid, member_count,
    #           member_users_count, is_empty
    #   Child dict lists: members, member_users
    #     hər element: {name, sid, dn, is_user, is_group, isaclprotected, domainsid}
    specs["domain_groups"] = TableSpec(
        table_name="groups",
        scalar_columns=[
            "group_name", "group_dn", "group_sid",
            "member_count", "member_users_count", "is_empty",
            "primary_group_token", "isaclprotected", "domainsid",
            "is_privileged", "is_protected", "is_nested",
            "managed_by", "description", "when_created", "when_changed",
        ],
        json_columns=[],
        child_tables=[
            ChildTableSpec(
                source_key="members",
                table_name="group_direct_members",
                parent_fk="group_rowid",
                # {name, sid, dn, is_user, is_group, isaclprotected, domainsid}
                columns={
                    "name":          "member_name",
                    "sid":           "member_sid",
                    "dn":            "member_dn",
                    "is_user":       "is_user",
                    "is_group":      "is_group",
                    "isaclprotected": "isaclprotected",
                    "domainsid":     "domainsid",
                },
            ),
            ChildTableSpec(
                source_key="member_users",
                table_name="group_member_users",
                parent_fk="group_rowid",
                # {name, sid, dn, is_user, is_group, isaclprotected, domainsid}
                columns={
                    "name":          "member_name",
                    "sid":           "member_sid",
                    "dn":            "member_dn",
                    "is_user":       "is_user",
                    "is_group":      "is_group",
                    "isaclprotected": "isaclprotected",
                    "domainsid":     "domainsid",
                },
            ),
        ],
        index_columns=["group_sid", "group_dn", "group_name"],
    )

    # ---------------- domain_gpos.jsonl -----------------------------------------
    # NOTE: column names below match the actual fields produced by the
    # collector for domain_gpos.jsonl (verified against real sample data):
    #   name, guid, display_name, description, dn, path, domain, domainsid,
    #   created, modified, version, user_version, computer_version, flags,
    #   user_settings_disabled, computer_settings_disabled, linked_count,
    #   enforced, link_disabled, isaclprotected, owner_sid, owner_name,
    #   highvalue. "managed_by", "risk_score", "high_risk", "orphaned",
    #   "domain_name" are NOT present in the real data.
    # list/dict fields not previously captured: all_cpasswords (cleartext
    # GPP credentials — important!), ldap_dacl_aces, ou_inheritance, sysvol.
    specs["domain_gpos"] = TableSpec(
        table_name="gpos",
        scalar_columns=[
            "name", "guid", "display_name", "description", "dn", "path",
            "domain", "domainsid", "created", "modified",
            "version", "user_version", "computer_version", "flags",
            "user_settings_disabled", "computer_settings_disabled",
            "linked_count", "enforced", "link_disabled", "isaclprotected",
            "owner_sid", "owner_name", "highvalue", "inheritance_blocked",
        ],
        json_columns=[
            "linked_containers", "user_extensions", "machine_extensions",
            "risk_controls", "all_cpasswords", "ldap_dacl_aces",
            "ou_inheritance", "sysvol",
        ],
        index_columns=["guid", "dn"],
    )

    # ---------------- domain_ous.jsonl ------------------------------------------
    # NOTE: column names below match the actual fields produced by the
    # collector for domain_ous.jsonl (verified against real sample data):
    #   objectguid/objectid (not object_guid/object_id), childous (not
    #   child_ous, and it's a scalar JSON list, not a child table),
    #   is_protected, type. "managed_by_name", "gp_options", "gpo_count",
    #   "inherited_gpo_count", "high_risk", "risk_score", "domain_name" are
    #   NOT present in the real data.
    # Child list shapes also differ from the old spec:
    #   linked_gpos / inherited_gpos -> {gpo_dn, gpo_guid, order, enforced}
    #   privileged_users -> {sam_name, dn, sid} (no "cn")
    #   privileged_computers -> {cn, dn, sid} (no "dns_name")
    specs["domain_ous"] = TableSpec(
        table_name="ous",
        scalar_columns=[
            "name", "dn", "path", "description", "managed_by", "type",
            "objectguid", "objectid", "parent_dn", "depth", "gpo_links_raw",
            "has_gpo_links", "inheritance_blocked", "blocksinheritance",
            "object_count", "is_protected",
            "privileged_users_count", "privileged_computers_count",
            "delegated_permissions", "highvalue",
            "isaclprotected", "domainsid",
            "created", "modified",
        ],
        json_columns=["childous", "risk_controls"],
        child_tables=[
            ChildTableSpec(
                source_key="linked_gpos",
                table_name="ou_linked_gpos",
                parent_fk="ou_rowid",
                columns={
                    "gpo_dn": "gpo_dn", "gpo_guid": "gpo_guid",
                    "order": "link_order", "enforced": "enforced",
                },
            ),
            ChildTableSpec(
                source_key="gpo_precedence",
                table_name="ou_gpo_precedence",
                parent_fk="ou_rowid",
                columns={
                    "gpo_guid": "gpo_guid", "order": "link_order",
                    "enforced": "enforced",
                },
            ),
            ChildTableSpec(
                source_key="inherited_gpos",
                table_name="ou_inherited_gpos",
                parent_fk="ou_rowid",
                columns={
                    "gpo_dn": "gpo_dn", "gpo_guid": "gpo_guid",
                    "order": "link_order", "enforced": "enforced",
                },
            ),
            ChildTableSpec(
                source_key="privileged_users",
                table_name="ou_privileged_users",
                parent_fk="ou_rowid",
                columns={
                    "sam_name": "sam_name", "dn": "dn", "sid": "sid",
                },
            ),
            ChildTableSpec(
                source_key="privileged_computers",
                table_name="ou_privileged_computers",
                parent_fk="ou_rowid",
                columns={
                    "cn": "cn", "dn": "dn", "sid": "sid",
                },
            ),
        ],
        index_columns=["objectguid", "dn"],
    )

    # ---------------- domain_trusts.jsonl ---------------------------------------
    # NOTE: column names below match the actual fields produced by the
    # collector for domain_trusts.jsonl (verified against real sample data):
    #   partner (not trust_partner), flat_name, sid (not partner_sid),
    #   trust_type/trust_type_raw, direction/direction_raw, inbound/outbound
    #   (booleans, not is_inbound/is_outbound), attributes_raw, transitive,
    #   forest, treat_as_external, sid_filtering_enabled, selective_auth,
    #   forest_wide_auth, dangerous, when_created, when_changed. There is no
    #   risk_score/highest_severity/risk_findings in the real data — instead
    #   there's a "security_posture" list of {level, text} dicts.
    specs["domain_trusts"] = TableSpec(
        table_name="trusts",
        scalar_columns=[
            "name", "partner", "flat_name", "sid", "dn", "object_guid",
            "description", "trust_type", "trust_type_raw",
            "direction", "direction_raw", "inbound", "outbound",
            "attributes_raw", "transitive", "forest", "treat_as_external",
            "sid_filtering_enabled", "selective_auth", "forest_wide_auth",
            "dangerous", "usn_created", "usn_changed",
            "when_created", "when_changed",
        ],
        json_columns=[
            "attributes_decoded", "forest_trust_info",
            "supported_encryption_types", "risk_controls",
        ],
        child_tables=[
            ChildTableSpec(
                source_key="security_posture",
                table_name="trust_security_posture",
                parent_fk="trust_rowid",
                columns={
                    "level": "level", "text": "text",
                },
            ),
        ],
        index_columns=["partner", "sid", "flat_name"],
    )

    # ---------------- domain_network.jsonl --------------------------------------
    specs["domain_network"] = TableSpec(
        table_name="network_hosts",
        scalar_columns=[
            "ipv4", "mac", "mac_vendor", "hostname", "ping_ok", "arp_ok",
            "open_port_count", "os_guess", "os_detail", "os_confidence",
            "ttl", "ad_matched", "ad_computer_name", "ad_dn", "ad_sid",
            "ad_os", "has_smb", "has_rdp", "has_ssh", "has_winrm", "has_ldap",
            "has_http", "has_ftp", "has_telnet", "has_snmp", "has_mssql",
            "has_mysql", "risk_score", "high_risk", "is_gateway",
            "gateway_confidence", "gateway_reason", "oui_vendor",
            "oui_device_type", "generated_at",
        ],
        json_columns=["risk_factors", "gateway_signals"],
        child_tables=[
            ChildTableSpec(
                source_key="open_ports",
                table_name="network_open_ports",
                parent_fk="network_host_rowid",
                columns={
                    "port": "port", "protocol": "protocol", "state": "state",
                    "service_name": "service_name", "banner": "banner",
                    "version": "version", "extra_info": "extra_info",
                },
            ),
        ],
        index_columns=["ipv4", "hostname", "ad_sid"],
    )

    # Shared scalar/json columns for all ACE-type files.
    # domain_aces / domain_dangerous_ace / domain_extended_rights all use
    # the same schema as of the current data format.
    _ace_scalars = [
        "target_name", "target_dn", "target_sid", "target_type",
        "principal", "principal_sid", "principal_scope", "principal_is_disabled",
        "object_acetype", "object_ace_type", "ace_qualifier", "ace_type_raw",
        "rights_display", "is_edge", "edge_kind", "is_inherited",
        "ace_flags", "modified",
    ]
    _ace_json = ["rights", "edge_rights"]
    _ace_index = ["target_sid", "principal_sid", "is_edge"]

    # ---------------- domain_aces.jsonl -----------------------------------------
    specs["domain_aces"] = TableSpec(
        table_name="aces",
        scalar_columns=_ace_scalars,
        json_columns=_ace_json,
        index_columns=_ace_index,
    )

    # ---------------- domain_dangerous_ace.jsonl --------------------------------
    specs["domain_dangerous_ace"] = TableSpec(
        table_name="dangerous_ace",
        scalar_columns=_ace_scalars,
        json_columns=_ace_json,
        index_columns=_ace_index,
    )

    # ---------------- domain_extended_rights.jsonl ------------------------------
    specs["domain_extended_rights"] = TableSpec(
        table_name="extended_rights",
        scalar_columns=_ace_scalars,
        json_columns=_ace_json,
        index_columns=_ace_index,
    )

    return specs


KNOWN_SPECS = _build_known_specs()

# --------------------------------------------------------------------------- #
# Whitelisted files – ONLY these are ever written to the database.
# Any other domain_*.jsonl files present in the directory are silently ignored.
# --------------------------------------------------------------------------- #

WHITELISTED_FILES: tuple[str, ...] = (
    "domain_info.jsonl",
    "domain_users.jsonl",
    "domain_computers.jsonl",
    "domain_groups.jsonl",
    "domain_gpos.jsonl",
    "domain_ous.jsonl",
    "domain_trusts.jsonl",
    "domain_aces.jsonl",
    "domain_dangerous_ace.jsonl",
    "domain_extended_rights.jsonl",
)

# Dict (struct) fields in domain_info.jsonl - expanded into flat columns
_DOMAIN_INFO_FLATTEN_DICTS = {
    "fsmo": ["schema_master", "naming_master", "rid_master", "pdc_emulator",
             "infrastructure"],
    "password_policy": ["min_length", "complexity_enabled", "max_age_days",
                         "min_age_days", "history_count", "lockout_threshold",
                         "lockout_duration_mins", "lockout_observation_mins",
                         "reversible_encryption", "pwd_properties_raw"],
    "kerberos_policy": ["max_ticket_age_hours", "max_renew_age_days",
                         "max_service_age_mins", "max_clock_skew_mins"],
}



# Fields that identify an envelope/metadata record (first line of each file).
# These records contain run-time stats, not domain objects, and must be skipped.
_ENVELOPE_KEYS = frozenset({"generated_at", "source", "success", "count", "error", "meta"})


def _is_envelope(obj: dict, file_stem: str | None = None) -> bool:
    """Returns True if the record looks like a file-level metadata envelope.

    An envelope has at least 2 of the known envelope keys and none of the
    typical domain-object keys (like 'dn', 'sid', 'username', etc.).

    NOTE: domain_info.jsonl's real (non-envelope) record legitimately
    carries success/count/error/meta/generated_at alongside the actual
    domain payload (fqdn, netbios_name, domain_controllers, ...), so the
    generic domain-field check above would misclassify it as an envelope
    and drop it. For this file we additionally recognize domain_info-only
    markers as proof of a real record.
    """
    envelope_hits = sum(1 for k in obj if k in _ENVELOPE_KEYS)
    has_domain_fields = any(k in obj for k in ("dn", "sid", "username", "sam_account_name",
                                                "computer_name", "object_sid", "trust_partner",
                                                "trustee_sid", "name", "guid"))
    if file_stem == "domain_info":
        has_domain_fields = has_domain_fields or any(
            k in obj for k in ("fqdn", "netbios_name", "domain_controllers", "fsmo")
        )
    return envelope_hits >= 2 and not has_domain_fields


def iter_jsonl(path: Path, file_stem: str | None = None) -> Iterator[dict[str, Any]]:
    """Reads a .jsonl file line by line and returns it as a dict generator.

    Skips:
    - Empty lines
    - Unparseable lines (with a warning)
    - Envelope/metadata records (the first-line summary that each file starts with)

    file_stem (e.g. "domain_info") is passed to _is_envelope() so it can
    apply file-specific rules for telling a real record apart from a pure
    metadata envelope. Defaults to path.stem when not given.
    """
    stem = file_stem if file_stem is not None else path.stem
    with path.open("r", encoding="utf-8") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("Parse error %s:%d - line skipped (%s)",
                                path.name, line_no, exc)
                continue
            if not isinstance(obj, dict):
                logger.warning("%s:%d - not an object (type=%s), skipping",
                                path.name, line_no, type(obj).__name__)
                continue
            if _is_envelope(obj, stem):
                logger.debug("%s:%d - envelope/metadata record skipped", path.name, line_no)
                continue
            yield obj


# --------------------------------------------------------------------------- #
# Value normalization (converting to a SQLite-writable form)
# --------------------------------------------------------------------------- #

def _to_sqlite_value(value: Any) -> Any:
    """Converts a Python value into a type supported by SQLite.

    bool  -> 0/1 (int)
    list/dict -> JSON string
    str/int/float/None -> unchanged
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return value


def _sqlite_column_type(value: Any) -> str:
    """Infers the appropriate SQLite column type from a Python value, for automatic schema."""
    if isinstance(value, bool):
        return "INTEGER"
    if isinstance(value, int):
        return "INTEGER"
    if isinstance(value, float):
        return "REAL"
    return "TEXT"


def _quote_ident(name: str) -> str:
    """Safely quotes a SQLite identifier (table/column name)."""
    return '"' + name.replace('"', '""') + '"'


# --------------------------------------------------------------------------- #
# DB schema creation and writing
# --------------------------------------------------------------------------- #

class SqliteWriter:
    """Manages table creation/insert operations over a SQLite connection."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self._created_tables: set[str] = set()
        # Tracks known columns per table in memory (set for O(1) lookup).
        # After the first CREATE/PRAGMA, only ALTER TABLE is issued for truly
        # new columns — no repeated PRAGMA calls on every row.
        self._table_columns: dict[str, set[str]] = {}

    def ensure_table(self, table_name: str, column_types: dict[str, str]) -> None:
        """Creates the table if it doesn't exist; adds any missing columns.

        On the first call for a given table the full schema is resolved (either
        CREATE TABLE or a PRAGMA introspection for pre-existing tables).
        On every subsequent call only columns absent from the in-memory set are
        added via ALTER TABLE — this handles generic/unknown files where
        different rows may introduce new fields.
        """
        cur = self.conn.cursor()
        if table_name not in self._created_tables:
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                        (table_name,))
            exists = cur.fetchone() is not None
            if not exists:
                cols_sql = ",\n    ".join(
                    f"{_quote_ident(c)} {t}" for c, t in column_types.items()
                )
                cur.execute(
                    f'CREATE TABLE {_quote_ident(table_name)} (\n'
                    f'    id INTEGER PRIMARY KEY AUTOINCREMENT,\n'
                    f'    {cols_sql}\n'
                    f')'
                )
                self._table_columns[table_name] = set(column_types.keys())
            else:
                cur.execute(f"PRAGMA table_info({_quote_ident(table_name)})")
                existing_cols: set[str] = {row[1] for row in cur.fetchall()}
                for col, ctype in column_types.items():
                    if col not in existing_cols:
                        cur.execute(
                            f'ALTER TABLE {_quote_ident(table_name)} '
                            f'ADD COLUMN {_quote_ident(col)} {ctype}'
                        )
                self._table_columns[table_name] = existing_cols | set(column_types.keys())
            self._created_tables.add(table_name)
        else:
            # Fast path: compare against in-memory column set, ALTER only if needed.
            known = self._table_columns[table_name]
            for col, ctype in column_types.items():
                if col not in known:
                    cur.execute(
                        f'ALTER TABLE {_quote_ident(table_name)} '
                        f'ADD COLUMN {_quote_ident(col)} {ctype}'
                    )
                    known.add(col)

    def insert(self, table_name: str, row: dict[str, Any]) -> int:
        """Inserts a row into a table, returns the new rowid (id)."""
        cols = list(row.keys())
        placeholders = ", ".join("?" for _ in cols)
        col_sql = ", ".join(_quote_ident(c) for c in cols)
        cur = self.conn.execute(
            f'INSERT INTO {_quote_ident(table_name)} ({col_sql}) VALUES ({placeholders})',
            [row[c] for c in cols],
        )
        return cur.lastrowid

    def create_index(self, table_name: str, column: str) -> None:
        idx_name = f"idx_{table_name}_{column}"
        try:
            self.conn.execute(
                f'CREATE INDEX IF NOT EXISTS {_quote_ident(idx_name)} '
                f'ON {_quote_ident(table_name)} ({_quote_ident(column)})'
            )
        except sqlite3.OperationalError as exc:
            logger.warning("Could not create index (%s.%s): %s", table_name, column, exc)


# --------------------------------------------------------------------------- #
# Core logic for writing a record (parent + child tables)
# --------------------------------------------------------------------------- #

def _flatten_known_dicts(record: dict[str, Any], file_stem: str) -> dict[str, Any]:
    """Converts nested dicts (fsmo, password_policy, kerberos_policy) in files
    like domain_info into prefixed flat columns. For other files the record
    is returned unchanged."""
    if file_stem != "domain_info":
        return record
    flat = dict(record)
    for dict_key, subkeys in _DOMAIN_INFO_FLATTEN_DICTS.items():
        sub = flat.pop(dict_key, None) or {}
        for sk in subkeys:
            flat[f"{dict_key}__{sk}"] = sub.get(sk)
    return flat


def _write_child_rows(
    writer: SqliteWriter,
    spec: ChildTableSpec,
    items: list[Any],
    parent_rowid: int,
) -> None:
    if not items:
        return
    for item in items:
        if spec.columns is None:
            # simple scalar list -> a single "value" column
            row = {"value": _to_sqlite_value(item), spec.parent_fk: parent_rowid}
            col_types = {"value": _sqlite_column_type(item), spec.parent_fk: "INTEGER"}
        else:
            if not isinstance(item, dict):
                # unexpected shape - store as a JSON string
                row = {"raw": _to_sqlite_value(item), spec.parent_fk: parent_rowid}
                col_types = {"raw": "TEXT", spec.parent_fk: "INTEGER"}
            else:
                row = {spec.parent_fk: parent_rowid}
                col_types = {spec.parent_fk: "INTEGER"}
                for src_key, dest_col in spec.columns.items():
                    val = item.get(src_key)
                    row[dest_col] = _to_sqlite_value(val)
                    col_types[dest_col] = _sqlite_column_type(val) if val is not None else "TEXT"
        writer.ensure_table(spec.table_name, col_types)
        writer.insert(spec.table_name, row)


def _write_record(
    writer: SqliteWriter,
    spec: TableSpec,
    record: dict[str, Any],
    file_stem: str,
) -> None:
    record = _flatten_known_dicts(record, file_stem)

    child_keys = {ct.source_key for ct in spec.child_tables}
    json_keys = set(spec.json_columns)

    # Column list: use the explicit one if given, otherwise use all scalar fields
    if spec.scalar_columns is not None:
        scalar_keys = spec.scalar_columns
    else:
        scalar_keys = [
            k for k in record.keys()
            if k not in child_keys and k not in json_keys
            and not isinstance(record.get(k), (list, dict))
        ]

    row: dict[str, Any] = {}
    col_types: dict[str, str] = {}

    for key in scalar_keys:
        val = record.get(key)
        row[key] = _to_sqlite_value(val)
        col_types[key] = _sqlite_column_type(val) if val is not None else "TEXT"

    for key in spec.json_columns:
        val = record.get(key)
        row[key] = _to_sqlite_value(val) if val is not None else None
        col_types[key] = "TEXT"

    # In the generic fallback case, when there are no scalar_columns, also add
    # the prefixed columns produced by the domain_info flattening
    if spec.scalar_columns is None:
        for key, val in record.items():
            if key in row or key in child_keys or key in json_keys:
                continue
            row[key] = _to_sqlite_value(val)
            col_types[key] = _sqlite_column_type(val) if val is not None else "TEXT"

    writer.ensure_table(spec.table_name, col_types)
    parent_rowid = writer.insert(spec.table_name, row)

    for ct in spec.child_tables:
        items = record.get(ct.source_key) or []
        if isinstance(items, list):
            _write_child_rows(writer, ct, items, parent_rowid)


def _read_domain_fqdn(input_dir: Path, pattern: str) -> str:
    """Reads the domain FQDN from domain_info.jsonl in input_dir.

    Raises FileNotFoundError if domain_info.jsonl is missing, and ValueError
    if it exists but contains no usable 'fqdn' field. The `pattern` is used
    only to decide whether a domain_info file is expected to participate in
    this run at all (kept for symmetry with the rest of the pipeline).
    """
    info_path = input_dir / "domain_info.jsonl"
    if not info_path.exists():
        raise FileNotFoundError(
            f"Cannot determine domain name: '{info_path}' not found. "
            "Pass --output explicitly to bypass automatic naming."
        )

    fqdn: str | None = None
    for record in iter_jsonl(info_path, file_stem="domain_info"):
        candidate = record.get("fqdn")
        if candidate:
            fqdn = str(candidate).strip()
            break

    if not fqdn:
        raise ValueError(
            f"Cannot determine domain name: '{info_path}' has no usable "
            "'fqdn' field. Pass --output explicitly to bypass automatic naming."
        )

    return fqdn


def _sanitize_fqdn_for_filename(fqdn: str) -> str:
    """Turns 'warzone.oxsium.local' into 'warzone_oxsium_local'.

    Any character that isn't alphanumeric, '_' or '-' is replaced with '_'
    so the result is always a safe filename component.
    """
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", fqdn.strip().lower())
    safe = re.sub(r"_+", "_", safe).strip("_")
    return safe or "unknown_domain"


def _generic_spec_for_unknown_file(file_stem: str) -> TableSpec:
    """Creates a generic TableSpec (everything as either scalar or JSON TEXT
    columns) for a domain_*.jsonl file with an unknown schema."""
    table_name = file_stem.replace("domain_", "", 1) or file_stem
    return TableSpec(table_name=table_name, scalar_columns=None, json_columns=[])


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def convert_file(
    jsonl_path: str | Path,
    conn: sqlite3.Connection,
    spec: TableSpec | None = None,
    progress_cb: Callable[[int], None] | None = None,
) -> int:
    """Writes a single domain_*.jsonl file to the given open SQLite connection.

    Parameters
    ----------
    jsonl_path : path to the .jsonl file
    conn       : open sqlite3.Connection (caller is responsible for commit)
    spec       : TableSpec to use. If None, looked up by file name in
                 KNOWN_SPECS; if not found, a generic spec is built.
    progress_cb: optional callback invoked every N lines, receiving the
                 number of lines read so far (for CLI progress display)

    Returns: number of rows written
    """
    jsonl_path = Path(jsonl_path)
    file_stem = jsonl_path.stem  # "domain_users", etc.

    if spec is None:
        spec = KNOWN_SPECS.get(file_stem) or _generic_spec_for_unknown_file(file_stem)

    writer = SqliteWriter(conn)
    count = 0
    for record in iter_jsonl(jsonl_path, file_stem=file_stem):
        _write_record(writer, spec, record, file_stem)
        count += 1
        if progress_cb and count % 500 == 0:
            progress_cb(count)

    for col in spec.index_columns:
        writer.create_index(spec.table_name, col)

    if progress_cb:
        progress_cb(count)

    logger.info("%-22s -> table '%s' (%d rows)", jsonl_path.name, spec.table_name, count)
    return count




def _inject_primary_group_members_sqlite(conn: sqlite3.Connection) -> int:
    """
    users.primary_group_sid əsasında group_direct_members və
    group_member_users cədvəllərinə primary group üzvlərini əlavə edir.

    LDAP 'member' atributu primary group üzvlərini qaytarmır —
    buna görə JSONL-da bu üzvlər olmur. Bu funksiya SQLite-da
    users → groups cross-reference edərək çatışan üzvləri doldurur.

    Yalnız artıq mövcud olmayan (member_sid-ə görə) üzvlər əlavə edilir.
    """
    try:
        # users və groups cədvəlləri mövcuddurmu?
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        if not ('users' in tables and 'groups' in tables and
                'group_direct_members' in tables):
            return 0

        # users cədvəlinin sütunlarını yoxla
        user_cols = {r[1] for r in conn.execute('PRAGMA table_info(users)').fetchall()}
        if 'primary_group_sid' not in user_cols:
            return 0

        # qrupların rowid → group_sid xəritəsi
        group_map = {
            row[1]: row[0]  # group_sid → rowid
            for row in conn.execute('SELECT rowid, group_sid FROM groups WHERE group_sid IS NOT NULL').fetchall()
        }

        # mövcud group_direct_members-dəki (group_rowid, member_sid) cütlüklər
        existing = set(conn.execute(
            'SELECT group_rowid, member_sid FROM group_direct_members WHERE member_sid IS NOT NULL'
        ).fetchall())

        # users-dən primary group üzvlərini çək
        user_rows = conn.execute(
            'SELECT username, sid, dn, primary_group_sid FROM users '
            'WHERE primary_group_sid IS NOT NULL AND primary_group_sid != ""'
        ).fetchall()

        dm_rows = []
        mu_rows = []

        for username, sid, dn, pg_sid in user_rows:
            group_rowid = group_map.get(pg_sid)
            if group_rowid is None:
                continue  # bu SID-ə uyğun qrup yoxdur
            if (group_rowid, sid) in existing:
                continue  # artıq var

            dm_rows.append((group_rowid, username, sid, dn, 1, 0, 0, ''))
            mu_rows.append((group_rowid, username, sid, dn, 1, 0, 0, ''))
            existing.add((group_rowid, sid))

        if not dm_rows:
            return 0

        conn.executemany(
            'INSERT INTO group_direct_members '
            '(group_rowid, member_name, member_sid, member_dn, is_user, is_group, isaclprotected, domainsid) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            dm_rows,
        )
        conn.executemany(
            'INSERT INTO group_member_users '
            '(group_rowid, member_name, member_sid, member_dn, is_user, is_group, isaclprotected, domainsid) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            mu_rows,
        )

        # member_count-u yenilə
        conn.execute("""
            UPDATE groups SET member_count = (
                SELECT COUNT(*) FROM group_direct_members
                WHERE group_direct_members.group_rowid = groups.rowid
            )
        """)
        conn.execute("""
            UPDATE groups SET member_users_count = (
                SELECT COUNT(*) FROM group_member_users
                WHERE group_member_users.group_rowid = groups.rowid
            )
        """)
        conn.execute("""
            UPDATE groups SET is_empty = CASE
                WHEN member_count = 0 THEN 1 ELSE 0
            END
        """)

        return len(dm_rows)

    except Exception as exc:
        logger.warning("primary group injection failed: %s", exc)
        return 0

def convert_directory(
    input_dir: str | Path,
    output_db: str | Path,
    pattern: str = "domain_*.jsonl",
    overwrite: bool = False,
    progress: bool = True,
    delete_source: bool = False,
) -> dict[str, int]:
    """Converts all domain_*.jsonl files in a directory into a single SQLite
    .db file.

    Parameters
    ----------
    input_dir  : directory containing the domain_*.jsonl files
    output_db  : path to the .db file to be created/written. If this file
                 already exists, it is always deleted and recreated from
                 scratch (this matters most when output_db was derived from
                 the domain name: writing a second time for the same domain
                 replaces the old .db rather than appending to it).
    pattern    : glob pattern (default "domain_*.jsonl")
    overwrite  : kept for backwards compatibility; no longer required for
                 deletion to happen (output_db is now always replaced if it
                 exists), but still accepted as a no-op flag.
    progress   : if True, writes brief progress output to stderr for each file
    delete_source : if True, every source .jsonl file that was written to
                 the database successfully is deleted once its own commit
                 has gone through. Each file is processed and committed in
                 isolation: if one file fails, files already committed
                 before it are still deleted, and the failing file (along
                 with any files after it, since they are processed in
                 order) is left in place. A summary of failures is logged
                 either way and does not stop the rest of the files from
                 being processed.

    Returns: a dict of {table_name_or_filename: rows_written}
    """
    input_dir = Path(input_dir)
    output_db = Path(output_db)

    if not input_dir.is_dir():
        raise FileNotFoundError(f"Directory not found: {input_dir}")

    # Only process the explicitly whitelisted files; all other domain_*.jsonl
    # files in the directory are intentionally ignored.
    files = [input_dir / name for name in WHITELISTED_FILES
             if (input_dir / name).exists()]
    if not files:
        raise FileNotFoundError(
            f"None of the whitelisted JSONL files were found in: {input_dir}\n"
            f"Expected one or more of: {', '.join(WHITELISTED_FILES)}"
        )

    if output_db.exists():
        output_db.unlink()

    output_db.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(output_db))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    results: dict[str, int] = {}
    succeeded_files: list[Path] = []
    failed: list[tuple[Path, Exception]] = []
    try:
        for f in files:
            spec = KNOWN_SPECS.get(f.stem) or _generic_spec_for_unknown_file(f.stem)

            def _cb(n: int, _name=f.name) -> None:
                if progress:
                    print(f"\r  {_name}: {n} lines read...", end="", file=sys.stderr, flush=True)

            try:
                count = convert_file(f, conn, spec=spec, progress_cb=_cb if progress else None)
                if progress:
                    print(file=sys.stderr)  # close the line
                conn.commit()  # isolate this file's writes from the next file's
                results[spec.table_name] = count
                succeeded_files.append(f)
            except Exception as exc:  # noqa: BLE001 - we want to isolate any failure
                conn.rollback()
                if progress:
                    print(file=sys.stderr)  # close the partial progress line
                logger.error("Failed to process %s: %s", f.name, exc)
                failed.append((f, exc))
    finally:
        conn.close()

    if delete_source:
        for f in succeeded_files:
            try:
                f.unlink()
            except OSError as exc:
                logger.error("Could not delete source file %s: %s", f, exc)

    if failed:
        logger.warning(
            "%d file(s) failed and were left in place: %s",
            len(failed),
            ", ".join(f.name for f, _ in failed),
        )

    # MƏRHƏLƏ 1: primary group üzvlərini users.primary_group_sid-dən inject et
    # (domain_users.jsonl-dan oxunur, ayrıca LDAP sorğusu yoxdur)
    try:
        conn2 = sqlite3.connect(str(output_db))
        added = _inject_primary_group_members_sqlite(conn2)
        conn2.commit()
        conn2.close()
        if added:
            logger.info("Primary group injection: %d members added", added)
    except Exception as _pg_exc:
        logger.warning("Primary group injection skipped: %s", _pg_exc)

    return results


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jsonl_to_sqlite",
        description=(
            "Reads domain_*.jsonl files under a Domain Object directory and "
            "converts them into a single SQLite (.db) file."
        ),
    )
    parser.add_argument(
        "input_dir",
        help="Directory containing the domain_*.jsonl files",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help=(
            "Path to the .db file to create. If omitted, the name is "
            "derived automatically from the domain's fqdn (read from "
            "domain_info.jsonl), e.g. 'domain_warzone_oxsium_local.db'."
        ),
    )
    parser.add_argument(
        "--pattern",
        default="domain_*.jsonl",
        help=(
            "[IGNORED] File discovery now uses a fixed whitelist (WHITELISTED_FILES). "
            "This argument is accepted for backwards compatibility but has no effect."
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="If an existing .db file exists, delete it and recreate",
    )
    parser.add_argument(
        "--delete-source",
        action="store_true",
        help=(
            "After the .db file has been written, delete every source "
            ".jsonl file that was successfully processed. Files are "
            "committed to the database one at a time, so if one file "
            "fails, files processed before it are still deleted while "
            "the failing file is left in place."
        ),
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Disable progress output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Debug-level log output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.quiet:
        log_level = logging.CRITICAL + 1  # effectively disables all logging
    elif args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
    )

    try:
        if args.output is None:
            try:
                fqdn = _read_domain_fqdn(Path(args.input_dir), args.pattern)
            except (FileNotFoundError, ValueError) as exc:
                if not args.quiet:
                    logger.error(str(exc))
                return 1
            output_path = f"domain_{_sanitize_fqdn_for_filename(fqdn)}.db"
        else:
            output_path = args.output

        results = convert_directory(
            args.input_dir,
            output_path,
            pattern=args.pattern,
            overwrite=args.overwrite,
            progress=not args.quiet,
            delete_source=args.delete_source,
        )
    except FileNotFoundError as exc:
        if not args.quiet:
            logger.error(str(exc))
        return 1

    if not args.quiet:
        total = sum(results.values())
        print(f"\nDone. Output: {output_path}")
        print(f"{'Table':<30} {'Row count':>12}")
        print("-" * 43)
        for table, count in sorted(results.items()):
            print(f"{table:<30} {count:>12}")
        print("-" * 43)
        print(f"{'TOTAL':<30} {total:>12}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())