import os
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from collections.abc import Callable

from .constants import (
    TARGET_FILTER,
    _SD_FLAGS,
    _SD_FLAGS_FULL,
    _AD_SENSITIVE_TEMPLATES,
    _DEEP_SCAN_BASES,
    _DEEP_SCAN_CRITICAL_SUBTREES,
    WELL_KNOWN_SIDS,
)
from .models import LdapBackend, SecurityDescriptorParser, AclFilterConfig, ObjectScope
from .parsers import (
    _resolve_self_dn,
    _fetch_object_sd,
    _paged_search,
    _paged_search_iter,
    _parse_dacl_to_records,
    _parse_dacl_payloads_batch,
    _entry_to_sd_payload,
    _apply_filters,
)
from .backends import normalize_value
from .parsers import _normalize_controls


# ══════════════════════════════════════════════════════════════════════════════
# Yeni: ScopeResolver — scope → (ldap_filter, base_dns) çevirməsi
# ══════════════════════════════════════════════════════════════════════════════

class ScopeResolver:
    """
    Verilmiş ObjectScope-u LDAP filtr sətrinə və axtarış bazaların siyahısına çevirir.
    Collector-dan scope məntiqini ayıraraq SRP tələbini yerinə yetirir.
    """

    _SCOPE_FILTERS: dict[ObjectScope, str] = {
        ObjectScope.SECURITY_PRINCIPALS: (
            "(|(objectClass=user)(objectClass=group)(objectClass=computer))"
        ),
        ObjectScope.NAMED_CONTAINERS: (
            "(|(objectClass=organizationalUnit)(objectClass=container)"
            "(objectClass=builtinDomain)(objectClass=domainDNS))"
        ),
        ObjectScope.GPO: (
            "(objectClass=groupPolicyContainer)"
        ),
        ObjectScope.ALL_WITH_ACL: (
            "(objectClass=*)"
        ),
    }

    def resolve(
        self,
        scope: ObjectScope,
        base_dn: str,
        custom_filter: str = "",
        extra_bases: list[str] | None = None,
    ) -> tuple[str, list[str]]:

        if scope == ObjectScope.SENSITIVE_TEMPLATES:
            dns = [
                tmpl.format(base_dn=base_dn)
                for tmpl, _ in _AD_SENSITIVE_TEMPLATES.values()
            ]
            if extra_bases:
                dns = list(dict.fromkeys(dns + extra_bases))
            return "(objectClass=*)", dns

        if scope == ObjectScope.DEEP_SCAN:
            # Domain NC + Configuration NC + DNS application partitions.
            # Schema NC, Configuration NC-nin SUBTREE-sinə daxildir — ayrıca verilmir.
            bases = [b.format(base_dn=base_dn) for b in _DEEP_SCAN_BASES]
            if extra_bases:
                bases = list(dict.fromkeys(bases + extra_bases))
            return "(objectClass=*)", bases

        if scope == ObjectScope.CUSTOM_FILTER:
            if not custom_filter:
                raise ValueError(
                    "ObjectScope.CUSTOM_FILTER üçün custom_filter parametri boş ola bilməz."
                )
            bases = [base_dn] + (extra_bases or [])
            return custom_filter, bases

        ldap_filter = self._SCOPE_FILTERS.get(scope, TARGET_FILTER)
        bases = [base_dn] + (extra_bases or [])
        return ldap_filter, bases


# Bir process-pool submit-ində neçə obyektin SD-si toplu göndəriləcək.
# Çox kiçik olsa IPC overhead-i artır, çox böyük olsa bir "batch"in bitməsini
# gözləmək streaming-i gecikdirir — 200 orta ölçülü domenlər üçün məqbul balansdır.
_PARSE_BATCH_SIZE = 200

# 4 NC (Domain / Configuration / DomainDnsZones / ForestDnsZones) üçün nəzərdə
# tutulan default thread sayı.
_DEFAULT_IO_WORKERS = 4


class AclCollector:

    def __init__(
        self,
        conn: LdapBackend,
        base_dn: str,
        parser: SecurityDescriptorParser,
        page_size: int = 1000,
        guid_map: dict[str, str] | None = None,
        conn_factory: Callable[[], LdapBackend] | None = None,
    ) -> None:
        self._conn         = conn
        self._base_dn      = base_dn
        self._parser       = parser
        self._page_size    = page_size
        self._resolver     = ScopeResolver()
        self._guid_map     = guid_map

        # DƏYİŞİKLİK: əvvəllər burada _build_sid_map(conn, base_dn) çağırılıb
        # bütün user/group/computer obyektləri üçün ayrıca tam-domen keçidi
        # aparılırdı (ACE skanı başlamazdan əvvəl). Bu keçid ləğv edilib —
        # sid_map artıq DEEP_SCAN/ALL_WITH_ACL taramaları öz gedişində
        # (sAMAccountName/userAccountControl atributlarını əlavə edərək)
        # canlı doldurur. Nəticə: eyni domen üçün bir keçid azdır.
        #
        # Trade-off: bir ACE-nin principal SID-i sid_map-ə hələ yazılmayıbsa
        # (yəni həmin principal obyekti hələ scan olunmayıb), o ACE üçün
        # "principal" sahəsi ada deyil, raw SID-ə düşəcək (əvvəlki davranışla
        # eyni fallback — sadəcə tamlıq faizi bir az aşağı ola bilər).
        self._sid_map:      dict[str, str] = dict(WELL_KNOWN_SIDS)
        self._disabled_sids: set[str]      = set()
        self._sid_lock = threading.Lock()

        # Paralel NC skanı üçün: hər thread öz LDAP bağlantısını açsın deyə
        # (ldap3 Connection thread-safe deyil). Factory verilməyibsə, bazalar
        # sequential gəzilir (I/O paralelləşmir, amma CPU-parsing yenə paralel
        # olur).
        self._conn_factory = conn_factory

    def collect(
        self,
        flt: AclFilterConfig,
        scope: ObjectScope = ObjectScope.SECURITY_PRINCIPALS,
        custom_filter: str = "",
        on_records: Callable[[list[dict]], None] | None = None,
    ) -> dict:

        if flt.self_acl_only:
            return self._collect_self(flt)
        return self._collect_by_scope(flt, scope, custom_filter, on_records=on_records)

    def _collect_self(self, flt: AclFilterConfig) -> dict:
        """SRP: yalnız bind istifadəçisinin ACL-larını toplayır."""
        self_dn = _resolve_self_dn(
            self._conn, self._base_dn, flt.principal_filter or ""
        )
        if not self_dn:
            return {"success": False,
                    "error":   "Bind user DN tapılmadı", "code": 404}

        raw_sd, self_entry = _fetch_object_sd(self._conn, self_dn, sdflags=_SD_FLAGS_FULL)
        if not raw_sd:
            return {"success": False,
                    "error":   ".",
                    "code":    403}

        records = _parse_dacl_to_records(
            raw_sd, self_dn, self_entry, self._sid_map, self._parser,
            disabled_sids=self._disabled_sids,
            guid_map=self._guid_map,
        )
        return self._build_result(records, flt, objects_with_sd=1, self_dn=self_dn)

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
                scope, self._base_dn, custom_filter
            )
        except ValueError as e:
            return {"success": False, "error": str(e), "code": 400}

        sd_ctrl      = security_descriptor_control(sdflags=0x07)
        sd_ctrl_norm = _normalize_controls([sd_ctrl])

        all_records:     list[dict] = []
        objects_with_sd: int        = 0

        if scope == ObjectScope.SENSITIVE_TEMPLATES:
            # DN-lər artıq məlumdur — birbaşa BASE sorğusu. Kiçik/sabit sayda
            # obyekt olduğu üçün paralelləşdirmə/streaming lazım deyil.
            for dn in base_dns:
                self._conn.search(
                    dn, "(objectClass=*)",
                    search_scope="BASE",
                    attributes=["name", "distinguishedName", "objectClass",
                                "whenChanged", "objectSid", "nTSecurityDescriptor"],
                    controls=sd_ctrl_norm,
                )
                if not self._conn.entries:
                    continue
                entry      = self._conn.entries[0]
                raw_values = getattr(
                    getattr(entry, "nTSecurityDescriptor", None), "raw_values", None
                ) or []
                if not raw_values:
                    continue
                objects_with_sd += 1
                entry_dn = str(normalize_value(
                    getattr(entry, "distinguishedName", None)) or dn)
                records = _parse_dacl_to_records(
                    raw_values[0], entry_dn, entry,
                    self._sid_map, self._parser,
                    disabled_sids=self._disabled_sids,
                    guid_map=self._guid_map,
                    skip_inherit_only=False,
                )
                all_records.extend(records)
                if on_records and records:
                    on_records(records)
        else:
            effective_bases = list(base_dns)
            if scope == ObjectScope.ALL_WITH_ACL:
                config_dn = f"CN=Configuration,{self._base_dn}"
                schema_dn = f"CN=Schema,CN=Configuration,{self._base_dn}"
                dns_domain = f"DC=DomainDnsZones,{self._base_dn}"
                dns_forest = f"DC=ForestDnsZones,{self._base_dn}"
                for extra in (config_dn, schema_dn, dns_domain, dns_forest):
                    if extra not in effective_bases:
                        effective_bases.append(extra)

            if scope == ObjectScope.DEEP_SCAN:
                for tmpl, _ in _DEEP_SCAN_CRITICAL_SUBTREES:
                    critical_dn = tmpl.format(base_dn=self._base_dn)
                    if critical_dn not in effective_bases:
                        effective_bases.append(critical_dn)

            # DƏYİŞİKLİK: əvvəllər bu bazalar `for base in effective_bases`
            # ilə ardıcıl (bir-birinin ardınca) gəzilirdi. İndi hər biri öz
            # thread-ində, paralel gəzilir — 4 NC = 4 thread. Hər thread-in
            # SD-parsing işi (CPU-bağlı) ayrıca ProcessPoolExecutor-a
            # ötürülür ki, Python GIL-i bu işi tək nüvəyə həbs etməsin.
            all_records, objects_with_sd = self._collect_bases_parallel(
                effective_bases, ldap_filter, sd_ctrl, on_records=on_records,
            )

        return self._build_result(all_records, flt,
                                   objects_with_sd=objects_with_sd,
                                   skip_inherit_only=False)

    def _collect_bases_parallel(
        self,
        bases: list[str],
        ldap_filter: str,
        sd_ctrl,
        on_records: Callable[[list[dict]], None] | None = None,
        max_workers: int = _DEFAULT_IO_WORKERS,
    ) -> tuple[list[dict], int]:
        """`bases` siyahısındakı NC-ləri paralel skan edir.

        - I/O paralelliyi: hər baza öz thread-ində, öz LDAP bağlantısında
          (conn_factory varsa) SUBTREE + paged axtarış aparır.
        - CPU paralelliyi: hər batch (≤ _PARSE_BATCH_SIZE obyekt) DACL
          parsing üçün paylaşılan ProcessPoolExecutor-a göndərilir.
        - sid_map/disabled_sids canlı doldurulur (əvvəlki ayrıca ön-tur
          ləğv olunduğu üçün) — lock ilə qorunur, hər batch üçün an-lıq
          "snapshot" kopyası process-ə göndərilir (dict özü picklable-dır,
          amma paralel mutasiya zamanı ssafe olsun deyə kopya götürülür).
        - Streaming: `on_records` verilibsə, hər batch bitər-bitməz
          çağırılır — nəticə əvvəlcə yaddaşda tam toplanıb sonda bir dəfəyə
          yazılmır, səhifə-səhifə/batch-batch ötürülür.

        conn_factory verilməyibsə (geriyə uyğunluq üçün), bazalar TƏHLÜKƏSİZLİK
        naminə sequential gəzilir — çünki tək ldap3 Connection paralel
        thread-lərdən eyni anda istifadə oluna bilməz (thread-safe deyil).
        Bu halda da CPU-parsing yenə paralel olur.
        """

        all_records:     list[dict] = []
        objects_with_sd: int        = 0
        seen_dns:  set[str]      = set()
        dn_lock     = threading.Lock()
        result_lock = threading.Lock()

        attributes = [
            "distinguishedName", "objectClass", "name", "whenChanged",
            "objectSid", "nTSecurityDescriptor",
            "sAMAccountName", "userAccountControl",
        ]

        cpu_workers = max(1, min(os.cpu_count() or 4, 8))

        def _process_batch(proc_pool: ProcessPoolExecutor, batch: list[dict]) -> None:
            nonlocal objects_with_sd
            if not batch:
                return
            with self._sid_lock:
                sid_snapshot      = dict(self._sid_map)
                disabled_snapshot = set(self._disabled_sids)

            future = proc_pool.submit(
                _parse_dacl_payloads_batch,
                batch, sid_snapshot, disabled_snapshot,
                self._guid_map, False,
            )
            batch_records = future.result()

            with result_lock:
                objects_with_sd += len(batch)
                all_records.extend(batch_records)

            if on_records and batch_records:
                on_records(batch_records)

        def _scan_base(proc_pool: ProcessPoolExecutor, base: str, conn: LdapBackend) -> None:
            batch: list[dict] = []
            for entry in _paged_search_iter(
                conn, base, ldap_filter,
                attributes=attributes,
                page_size=self._page_size,
                search_scope="SUBTREE",
                extra_controls=[sd_ctrl],
            ):
                dn = str(normalize_value(
                    getattr(entry, "distinguishedName", None)) or "")
                if not dn:
                    continue
                with dn_lock:
                    if dn in seen_dns:
                        continue
                    seen_dns.add(dn)

                payload = _entry_to_sd_payload(entry, dn)

                # Canlı sid_map yeniləməsi — sid_map pre-tur ləğv edildiyi
                # üçün burada doldurulur (user/group/computer obyektləri).
                sam_name = payload.get("sam")
                target_sid = payload.get("target_sid", "")
                if sam_name and target_sid:
                    with self._sid_lock:
                        self._sid_map[target_sid] = sam_name
                        if payload.get("uac", 0) & 0x2:
                            self._disabled_sids.add(target_sid)

                if not payload.get("raw_sd"):
                    continue

                batch.append(payload)
                if len(batch) >= _PARSE_BATCH_SIZE:
                    _process_batch(proc_pool, batch)
                    batch = []

            _process_batch(proc_pool, batch)

        with ProcessPoolExecutor(max_workers=cpu_workers) as proc_pool:
            if self._conn_factory:
                connections = [self._conn_factory() for _ in bases]
                try:
                    with ThreadPoolExecutor(max_workers=max_workers) as io_pool:
                        futures = [
                            io_pool.submit(_scan_base, proc_pool, base, conn)
                            for base, conn in zip(bases, connections)
                        ]
                        for f in as_completed(futures):
                            f.result()  # exception varsa yuxarı ötür
                finally:
                    for conn in connections:
                        try:
                            conn.unbind()
                        except Exception:
                            pass
            else:
                # conn_factory yoxdur — sequential fallback (I/O paralel
                # deyil, CPU-parsing yenə paraleldir).
                for base in bases:
                    _scan_base(proc_pool, base, self._conn)

        return all_records, objects_with_sd

    @staticmethod
    def _build_result(
        records: list[dict],
        flt: AclFilterConfig,
        objects_with_sd: int = 0,
        self_dn: str | None = None,
        skip_inherit_only: bool = True,
    ) -> dict:
        """SRP: filter tətbiq edir və cavab strukturunu qurur."""
        acl_entries:   list[dict] = []
        aces_filtered: int        = 0

        for record in records:
            if not _apply_filters(record, record["ace_flags"], flt,
                                  skip_inherit_only=skip_inherit_only):
                aces_filtered += 1
                continue
            acl_entries.append(record)

        return {
            "success":  True,
            "count":    len(acl_entries),
            "acls":     acl_entries,
            "self_dn":  self_dn,
            "meta": {
                "objects_with_sd": objects_with_sd,
                "aces_seen":       len(records),
                "aces_exported":   len(acl_entries),
                "aces_filtered":   aces_filtered,
            },
        }