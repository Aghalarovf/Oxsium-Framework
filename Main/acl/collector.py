import os
import threading
import traceback
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from .backends import normalize_value
from .constants import (
    TARGET_FILTER,
    _AD_SENSITIVE_TEMPLATES,
    _DEEP_SCAN_BASES,
    _DEEP_SCAN_BASES_MINIMAL,
    _DEEP_SCAN_CRITICAL_SUBTREES,
    WELL_KNOWN_SIDS,
    _SD_FLAGS,
)
from .models import AclFilterConfig, LdapBackend, ObjectScope, SecurityDescriptorParser
from .parsers import (
    _apply_filters,
    _entry_to_sd_payload,
    _fetch_object_sd,
    _normalize_controls,
    _paged_search_iter,
    _parse_dacl_payloads_batch,
    _parse_dacl_to_records,
    _resolve_self_dn,
)


_PARSE_BATCH_SIZE = 200
_DEFAULT_IO_WORKERS = 2


@dataclass(slots=True)
class _CollectionStats:
    objects_with_sd: int = 0
    entries_seen: int = 0
    entries_without_sd: int = 0


class ScopeResolver:
    _SCOPE_FILTERS: dict[ObjectScope, str] = {
        ObjectScope.SECURITY_PRINCIPALS: "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
        ObjectScope.NAMED_CONTAINERS: "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain)(objectClass=domainDNS))",
        ObjectScope.GPO: "(objectClass=groupPolicyContainer)",
        ObjectScope.ALL_WITH_ACL: "(objectClass=*)",
    }

    def resolve(
        self,
        scope: ObjectScope,
        base_dn: str,
        custom_filter: str = "",
        extra_bases: list[str] | None = None,
        deep_scan_minimal: bool = False,
    ) -> tuple[str, list[str]]:
        if scope == ObjectScope.SENSITIVE_TEMPLATES:
            bases = [template.format(base_dn=base_dn) for template, _ in _AD_SENSITIVE_TEMPLATES.values()]
            return "(objectClass=*)", self._merge_bases(bases, extra_bases)

        if scope == ObjectScope.DEEP_SCAN:
            source = _DEEP_SCAN_BASES_MINIMAL if deep_scan_minimal else _DEEP_SCAN_BASES
            bases = [template.format(base_dn=base_dn) for template in source]
            return "(objectClass=*)", self._merge_bases(bases, extra_bases)

        if scope == ObjectScope.CUSTOM_FILTER:
            if not custom_filter:
                raise ValueError("custom_filter is required for ObjectScope.CUSTOM_FILTER")
            return custom_filter, self._merge_bases([base_dn], extra_bases)

        ldap_filter = self._SCOPE_FILTERS.get(scope, TARGET_FILTER)
        return ldap_filter, self._merge_bases([base_dn], extra_bases)

    @staticmethod
    def _merge_bases(primary: list[str], extra: list[str] | None) -> list[str]:
        values = [*primary, *(extra or [])]
        return list(dict.fromkeys(value for value in values if value))


class AclCollector:
    def __init__(
        self,
        conn: LdapBackend,
        base_dn: str,
        parser: SecurityDescriptorParser,
        page_size: int = 200,
        guid_map: dict[str, str] | None = None,
        conn_factory: Callable[[], LdapBackend] | None = None,
        initial_errors: list[dict] | None = None,
        io_workers: int = _DEFAULT_IO_WORKERS,
        deep_scan_minimal: bool = False,
    ) -> None:
        self._conn = conn
        self._base_dn = base_dn
        self._parser = parser
        self._page_size = page_size
        self._guid_map = guid_map
        self._resolver = ScopeResolver()
        self._conn_factory = conn_factory
        self._io_workers = max(1, io_workers)
        self._deep_scan_minimal = deep_scan_minimal

        self._errors: list[dict] = list(initial_errors) if initial_errors else []
        self._errors_lock = threading.Lock()

        self._sid_map: dict[str, str] = dict(WELL_KNOWN_SIDS)
        self._disabled_sids: set[str] = set()
        self._sid_lock = threading.Lock()

    def collect(
        self,
        flt: AclFilterConfig,
        scope: ObjectScope = ObjectScope.SECURITY_PRINCIPALS,
        custom_filter: str = "",
        on_records: Callable[[list[dict]], None] | None = None,
    ) -> dict:
        try:
            if flt.self_acl_only:
                return self._collect_self(flt)
            return self._collect_by_scope(flt, scope, custom_filter, on_records=on_records)
        except Exception as exc:
            return self._failure("collect", f"scope={scope}", exc)

    def _collect_self(self, flt: AclFilterConfig) -> dict:
        try:
            self_dn = _resolve_self_dn(self._conn, self._base_dn, flt.principal_filter or "")
            if not self_dn:
                return self._failure(
                    "resolve_self_dn",
                    self._base_dn,
                    RuntimeError("Bind user DN was not found"),
                    404,
                )

            raw_sd, entry = _fetch_object_sd(self._conn, self_dn, sdflags=_SD_FLAGS)
            if not raw_sd or entry is None:
                return self._failure(
                    "fetch_self_sd",
                    self_dn,
                    RuntimeError("Security descriptor was not returned"),
                    403,
                )

            records = _parse_dacl_to_records(
                raw_sd,
                self_dn,
                entry,
                self._sid_map,
                self._parser,
                disabled_sids=self._disabled_sids,
                guid_map=self._guid_map,
            )
            return self._build_result(records, flt, objects_with_sd=1, self_dn=self_dn)
        except Exception as exc:
            return self._failure("collect_self", self._base_dn, exc)

    def _collect_by_scope(
        self,
        flt: AclFilterConfig,
        scope: ObjectScope,
        custom_filter: str,
        on_records: Callable[[list[dict]], None] | None = None,
    ) -> dict:
        from ldap3.protocol.microsoft import security_descriptor_control

        try:
            ldap_filter, base_dns = self._resolver.resolve(
                scope, self._base_dn, custom_filter,
                deep_scan_minimal=self._deep_scan_minimal,
            )
        except ValueError as exc:
            return self._failure("resolve_scope", str(scope), exc, 400)

        sd_ctrl = security_descriptor_control(sdflags=_SD_FLAGS, criticality=False)[0]
        sd_ctrl_norm = _normalize_controls([sd_ctrl])

        if scope == ObjectScope.SENSITIVE_TEMPLATES:
            records, objects_with_sd = self._collect_sensitive_templates(base_dns, sd_ctrl_norm, on_records)
        else:
            bases = self._expand_bases(scope, base_dns)
            records, objects_with_sd = self._collect_bases_parallel(
                bases,
                ldap_filter,
                sd_ctrl,
                on_records=on_records,
            )

        return self._build_result(
            records,
            flt,
            objects_with_sd=objects_with_sd,
            skip_inherit_only=False,
        )

    def _collect_sensitive_templates(
        self,
        dns: list[str],
        controls,
        on_records: Callable[[list[dict]], None] | None = None,
    ) -> tuple[list[dict], int]:
        records: list[dict] = []
        objects_with_sd = 0

        for dn in dns:
            try:
                self._conn.search(
                    dn,
                    "(objectClass=*)",
                    search_scope="BASE",
                    attributes=[
                        "name",
                        "distinguishedName",
                        "objectClass",
                        "whenChanged",
                        "objectSid",
                        "nTSecurityDescriptor",
                    ],
                    controls=controls,
                )
                if not self._conn.entries:
                    continue

                entry = self._conn.entries[0]
                raw_values = getattr(getattr(entry, "nTSecurityDescriptor", None), "raw_values", None) or []
                if not raw_values:
                    continue

                entry_dn = str(normalize_value(getattr(entry, "distinguishedName", None)) or dn)
                parsed = _parse_dacl_to_records(
                    raw_values[0],
                    entry_dn,
                    entry,
                    self._sid_map,
                    self._parser,
                    disabled_sids=self._disabled_sids,
                    guid_map=self._guid_map,
                    skip_inherit_only=False,
                )
                if parsed:
                    records.extend(parsed)
                    self._emit_records(parsed, on_records, "stream_records", entry_dn)
                objects_with_sd += 1
            except Exception as exc:
                self._record_error("sensitive_template_search", dn, exc)

        return records, objects_with_sd

    def _collect_bases_parallel(
        self,
        bases: list[str],
        ldap_filter: str,
        sd_ctrl,
        on_records: Callable[[list[dict]], None] | None = None,
        max_workers: int | None = None,
    ) -> tuple[list[dict], int]:
        max_workers = self._io_workers if max_workers is None else max_workers
        all_records: list[dict] = []
        stats = _CollectionStats()
        seen_dns: set[str] = set()

        dn_lock = threading.Lock()
        stats_lock = threading.Lock()
        result_lock = threading.Lock()

        attributes = [
            "distinguishedName",
            "objectClass",
            "name",
            "whenChanged",
            "objectSid",
            "nTSecurityDescriptor",
            "sAMAccountName",
            "userAccountControl",
        ]

        cpu_workers = max(1, min(os.cpu_count() or 4, 8))

        def process_batch(proc_pool: ProcessPoolExecutor, batch: list[dict], base_context: str) -> None:
            if not batch:
                return

            with self._sid_lock:
                sid_snapshot = dict(self._sid_map)
                disabled_snapshot = set(self._disabled_sids)

            try:
                future = proc_pool.submit(
                    _parse_dacl_payloads_batch,
                    batch,
                    sid_snapshot,
                    disabled_snapshot,
                    self._guid_map,
                    False,
                )
                batch_records = future.result()
            except Exception as exc:
                self._record_error("process_batch", f"base={base_context} batch_size={len(batch)}", exc)
                return

            with result_lock:
                stats.objects_with_sd += len(batch)
                all_records.extend(batch_records)

            self._emit_records(batch_records, on_records, "stream_records", base_context)

        def scan_base(proc_pool: ProcessPoolExecutor, base: str, conn: LdapBackend) -> None:
            batch: list[dict] = []
            try:
                for entry in _paged_search_iter(
                    conn,
                    base,
                    ldap_filter,
                    attributes=attributes,
                    page_size=self._page_size,
                    search_scope="SUBTREE",
                    extra_controls=[sd_ctrl],
                ):
                    dn = str(normalize_value(getattr(entry, "distinguishedName", None)) or "")
                    if not dn:
                        continue

                    with dn_lock:
                        if dn in seen_dns:
                            continue
                        seen_dns.add(dn)

                    payload = _entry_to_sd_payload(entry, dn)

                    with stats_lock:
                        stats.entries_seen += 1

                    sam_name = payload.get("sam")
                    target_sid = payload.get("target_sid", "")
                    if sam_name and target_sid:
                        with self._sid_lock:
                            self._sid_map[target_sid] = sam_name
                            if payload.get("uac", 0) & 0x2:
                                self._disabled_sids.add(target_sid)

                    if not payload.get("raw_sd"):
                        with stats_lock:
                            stats.entries_without_sd += 1
                        continue

                    batch.append(payload)
                    if len(batch) >= _PARSE_BATCH_SIZE:
                        process_batch(proc_pool, batch, base)
                        batch = []

                process_batch(proc_pool, batch, base)
            except Exception as exc:
                self._record_error("scan_base", base, exc)
                if batch:
                    process_batch(proc_pool, batch, base)

        with ProcessPoolExecutor(max_workers=cpu_workers) as proc_pool:
            if self._conn_factory:
                base_conn_pairs: list[tuple[str, LdapBackend]] = []
                for base in bases:
                    try:
                        base_conn_pairs.append((base, self._conn_factory()))
                    except Exception as exc:
                        self._record_error("conn_factory", base, exc)

                try:
                    if base_conn_pairs:
                        worker_count = max(1, min(max_workers, len(base_conn_pairs)))
                        with ThreadPoolExecutor(max_workers=worker_count) as io_pool:
                            future_to_base = {
                                io_pool.submit(scan_base, proc_pool, base, conn): base
                                for base, conn in base_conn_pairs
                            }
                            for future in as_completed(future_to_base):
                                base_context = future_to_base[future]
                                try:
                                    future.result()
                                except Exception as exc:
                                    self._record_error("scan_base_thread", base_context, exc)
                finally:
                    for _, conn in base_conn_pairs:
                        try:
                            conn.unbind()
                        except Exception:
                            pass
            else:
                for base in bases:
                    scan_base(proc_pool, base, self._conn)

        if stats.entries_seen > 0 and stats.entries_without_sd == stats.entries_seen:
            self._record_error(
                "scan_no_sd_returned",
                f"bases={bases}",
                RuntimeError(f"{stats.entries_seen} objects were found, but none returned nTSecurityDescriptor"),
            )

        return all_records, stats.objects_with_sd

    def _expand_bases(self, scope: ObjectScope, base_dns: list[str]) -> list[str]:
        bases = list(base_dns)

        if scope == ObjectScope.ALL_WITH_ACL:
            bases.extend(
                [
                    f"CN=Configuration,{self._base_dn}",
                    f"CN=Schema,CN=Configuration,{self._base_dn}",
                    f"DC=DomainDnsZones,{self._base_dn}",
                    f"DC=ForestDnsZones,{self._base_dn}",
                ]
            )

        if scope == ObjectScope.DEEP_SCAN and not self._deep_scan_minimal:
            bases.extend(template.format(base_dn=self._base_dn) for template, _ in _DEEP_SCAN_CRITICAL_SUBTREES)

        return list(dict.fromkeys(bases))

    def _emit_records(
        self,
        records: list[dict],
        on_records: Callable[[list[dict]], None] | None,
        stage: str,
        context: str,
    ) -> None:
        if not records or on_records is None:
            return

        try:
            on_records(records)
        except Exception as exc:
            self._record_error(stage, context, exc)

    def _build_result(
        self,
        records: list[dict],
        flt: AclFilterConfig,
        objects_with_sd: int = 0,
        self_dn: str | None = None,
        skip_inherit_only: bool = True,
    ) -> dict:
        acl_entries: list[dict] = []
        aces_filtered = 0

        for record in records:
            if not _apply_filters(record, record["ace_flags"], flt, skip_inherit_only=skip_inherit_only):
                aces_filtered += 1
                continue
            acl_entries.append(record)

        return {
            "success": True,
            "count": len(acl_entries),
            "acls": acl_entries,
            "self_dn": self_dn,
            "meta": self._meta(
                objects_with_sd=objects_with_sd,
                aces_seen=len(records),
                aces_exported=len(acl_entries),
                aces_filtered=aces_filtered,
                errors=self._errors,
            ),
        }

    def _meta(
        self,
        *,
        objects_with_sd: int = 0,
        aces_seen: int = 0,
        aces_exported: int = 0,
        aces_filtered: int = 0,
        errors: list[dict] | None = None,
    ) -> dict:
        error_list = list(errors or [])
        return {
            "objects_with_sd": objects_with_sd,
            "aces_seen": aces_seen,
            "aces_exported": aces_exported,
            "aces_filtered": aces_filtered,
            "error_count": len(error_list),
            "errors": error_list,
        }

    def _failure(
        self,
        stage: str,
        context: str,
        error: BaseException,
        code: int = 500,
    ) -> dict:
        self._record_error(stage, context, error)
        return {
            "success": False,
            "error": str(error),
            "code": code,
            "count": 0,
            "acls": [],
            "meta": self._meta(errors=self._errors),
        }

    def _record_error(self, stage: str, context: str, exc: BaseException) -> None:
        entry = {
            "stage": stage,
            "context": context,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "traceback": traceback.format_exc(limit=20),
        }
        with self._errors_lock:
            self._errors.append(entry)