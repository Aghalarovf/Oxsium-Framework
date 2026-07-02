import os
import threading
import traceback
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
        initial_errors: list[dict] | None = None,
    ) -> None:
        self._conn         = conn
        self._base_dn      = base_dn
        self._parser       = parser
        self._page_size    = page_size
        self._resolver     = ScopeResolver()
        self._guid_map     = guid_map

        # ══════════════════════════════════════════════════════════════════
        # Xəta jurnalı: kolleksiya boyunca baş verən HƏR bir xəta (ldap3
        # istisnaları, impacket parse xətaları, process-pool worker
        # istisnaları, gözlənilməz bug-lar və s.) burada toplanır və
        # `meta.errors` vasitəsilə son nəticəyə (deməli, domain_aces.jsonl-in
        # metadata sətrinə) ötürülür. Məqsəd: heç bir xəta səssizcə udulmasın
        # və ya bütün kolleksiyanı yarımçıq kəsməsin — bir baza/batch-dakı
        # problem digərlərinin toplanmasına mane olmamalıdır.
        # `initial_errors` — collector yaradılmazdan ƏVVƏL (məs. guid_map
        # qurularkən) baş vermiş xətaları da eyni jurnala daxil etmək üçün.
        # ══════════════════════════════════════════════════════════════════
        self._errors: list[dict] = list(initial_errors) if initial_errors else []
        self._errors_lock = threading.Lock()

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

    def _record_error(self, stage: str, context: str, exc: BaseException) -> None:
        """SRP: istənilən mərhələdə (LDAP axtarışı, DACL parse, process-pool
        worker və s.) baş verən xətanı thread-safe şəkildə jurnala yazır.
        `stage` — xətanın hansı addımda baş verdiyini (məs. 'scan_base'),
        `context` — hansı obyekt/baza üzərində baş verdiyini (məs. bir DN)
        bildirir. Tam traceback də saxlanılır ki, domain_aces.jsonl-in
        metadata sətrində problem tam diaqnoz edilə bilsin."""
        entry = {
            "stage":         stage,
            "context":       context,
            "error_type":    type(exc).__name__,
            "error_message": str(exc),
            "traceback":     traceback.format_exc(limit=20),
        }
        with self._errors_lock:
            self._errors.append(entry)

    def collect(
        self,
        flt: AclFilterConfig,
        scope: ObjectScope = ObjectScope.SECURITY_PRINCIPALS,
        custom_filter: str = "",
        on_records: Callable[[list[dict]], None] | None = None,
    ) -> dict:

        # SRP + son mühafizə xətti: `collect()` heç vaxt exception atmamalıdır.
        # Bütün alt-metodlar öz daxilində xətaları tuturlar, amma gözlənilməz
        # (proqramlaşdırma xətası kimi) bir istisna yenə də bura sızarsa,
        # burada tutulur ki, çağıran (api.py) "boş" bir crash yerinə HƏMİŞƏ
        # `meta.errors` daxilində tam diaqnoz məlumatı olan struktur nəticə alsın.
        try:
            if flt.self_acl_only:
                return self._collect_self(flt)
            return self._collect_by_scope(flt, scope, custom_filter, on_records=on_records)
        except Exception as e:
            self._record_error("collect", f"scope={scope}", e)
            return {
                "success": False,
                "error":   str(e),
                "code":    500,
                "count":   0,
                "acls":    [],
                "meta": {
                    "objects_with_sd": 0,
                    "aces_seen":       0,
                    "aces_exported":   0,
                    "aces_filtered":   0,
                    "error_count":     len(self._errors),
                    "errors":          self._errors,
                },
            }

    def _collect_self(self, flt: AclFilterConfig) -> dict:
        """SRP: yalnız bind istifadəçisinin ACL-larını toplayır."""
        self_dn = ""
        try:
            self_dn = _resolve_self_dn(
                self._conn, self._base_dn, flt.principal_filter or ""
            )
            if not self_dn:
                return {"success": False,
                        "error":   "Bind user DN tapılmadı", "code": 404,
                        "meta": {"error_count": len(self._errors), "errors": self._errors}}

            raw_sd, self_entry = _fetch_object_sd(self._conn, self_dn, sdflags=_SD_FLAGS_FULL)
            if not raw_sd:
                return {"success": False,
                        "error":   ".",
                        "code":    403,
                        "meta": {"error_count": len(self._errors), "errors": self._errors}}

            records = _parse_dacl_to_records(
                raw_sd, self_dn, self_entry, self._sid_map, self._parser,
                disabled_sids=self._disabled_sids,
                guid_map=self._guid_map,
            )
            return self._build_result(records, flt, objects_with_sd=1, self_dn=self_dn,
                                       errors=self._errors)
        except Exception as e:
            self._record_error("collect_self", self_dn or "bind_user", e)
            return {"success": False, "error": str(e), "code": 500,
                    "meta": {"error_count": len(self._errors), "errors": self._errors}}

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
                # Hər DN öz try/except-i ilə əhatə olunub: bir template-in
                # (məs. mövcud olmayan bir konteynerin) axtarışı xəta versə
                # belə, digər sensitive template-lərin toplanması davam edir —
                # xəta sadəcə jurnala yazılır və `continue` ilə keçilir.
                try:
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
                except Exception as e:
                    self._record_error("sensitive_template_search", dn, e)
                    continue
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
                                   skip_inherit_only=False,
                                   errors=self._errors)

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

        def _process_batch(proc_pool: ProcessPoolExecutor, batch: list[dict],
                            base_context: str) -> None:
            nonlocal objects_with_sd
            if not batch:
                return
            with self._sid_lock:
                sid_snapshot      = dict(self._sid_map)
                disabled_snapshot = set(self._disabled_sids)

            # DÜZƏLİŞ: `future.result()` process-pool worker-indən gələn
            # istənilən istisnanı (məs. impacket parse xətası, picklama
            # problemi, yaddaş xətası) burada tuturuq. Əvvəllər bu, birbaşa
            # `_scan_base`-i və ordan `as_completed(...).result()` vasitəsilə
            # BÜTÜN kolleksiyanı dayandırırdı — bir pozulmuş SD bütün domenin
            # taranmasını uğursuz edə bilərdi. İndi yalnız bu batch itir,
            # xəta tam jurnal olunur, qalan bazalar/batch-lar davam edir.
            try:
                future = proc_pool.submit(
                    _parse_dacl_payloads_batch,
                    batch, sid_snapshot, disabled_snapshot,
                    self._guid_map, False,
                )
                batch_records = future.result()
            except Exception as e:
                self._record_error(
                    "process_batch",
                    f"base={base_context} batch_size={len(batch)}",
                    e,
                )
                return

            with result_lock:
                objects_with_sd += len(batch)
                all_records.extend(batch_records)

            if on_records and batch_records:
                on_records(batch_records)

        def _scan_base(proc_pool: ProcessPoolExecutor, base: str, conn: LdapBackend) -> None:
            batch: list[dict] = []
            # DÜZƏLİŞ: bütün metod gövdəsi try/except ilə əhatə olunub.
            # Əvvəllər bir NC-də (məs. `adminLimitExceeded`, referral xətası,
            # socket kəsilməsi) baş verən İSTƏNİLƏN LDAP/parse xətası bu
            # thread-i çökdürür və `as_completed(...).result()` vasitəsilə
            # bütün kolleksiyanı dayandırırdı. İndi xəta tam kontekstlə
            # (hansı baza, hansı mərhələ) jurnala yazılır, digər NC-lərin
            # taranması davam edir — nə qədər toplana bilirsə, o qədər
            # domain_aces.jsonl-ə düşür, itki yalnız bu baza ilə məhdudlaşır.
            try:
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
                        _process_batch(proc_pool, batch, base)
                        batch = []

                _process_batch(proc_pool, batch, base)
            except Exception as e:
                self._record_error("scan_base", base, e)
                # Bu ana qədər toplanmış (amma hələ göndərilməmiş) qismi
                # batch-i də itirməmək üçün ayrıca yazmağa çalışırıq.
                if batch:
                    try:
                        _process_batch(proc_pool, batch, base)
                    except Exception as e2:
                        self._record_error("scan_base_partial_batch", base, e2)

        with ProcessPoolExecutor(max_workers=cpu_workers) as proc_pool:
            if self._conn_factory:
                # DÜZƏLİŞ: hər baza üçün bağlantı ayrıca try/except ilə
                # qurulur. Əvvəllər `[self._conn_factory() for _ in bases]`
                # tək bir bazanın bağlantı xətası (məs. bind uğursuzluğu)
                # bütün siyahının qurulmasını çökdürürdü — nəticədə heç bir
                # NC taranmırdı. İndi uğursuz bağlantı jurnala yazılır və
                # yalnız həmin baza atlanılır, qalanları taranır.
                base_conn_pairs: list[tuple[str, LdapBackend]] = []
                for base in bases:
                    try:
                        base_conn_pairs.append((base, self._conn_factory()))
                    except Exception as e:
                        self._record_error("conn_factory", base, e)

                try:
                    if base_conn_pairs:
                        with ThreadPoolExecutor(max_workers=max_workers) as io_pool:
                            future_to_base = {
                                io_pool.submit(_scan_base, proc_pool, base, conn): base
                                for base, conn in base_conn_pairs
                            }
                            for f in as_completed(future_to_base):
                                # DÜZƏLİŞ: `_scan_base` artıq öz daxilində
                                # xətaları tutur, amma burada da əlavə
                                # mühafizə saxlanılır — thread-in özündə
                                # (məs. yaddaş, gözlənilməz bug) baş verə
                                # biləcək istənilən xəta bu kolleksiyanı
                                # dayandırmasın deyə.
                                base_ctx = future_to_base[f]
                                try:
                                    f.result()
                                except Exception as e:
                                    self._record_error("scan_base_thread", base_ctx, e)
                finally:
                    for _, conn in base_conn_pairs:
                        try:
                            conn.unbind()
                        except Exception:
                            pass
            else:
                # conn_factory yoxdur — sequential fallback (I/O paralel
                # deyil, CPU-parsing yenə paraleldir). `_scan_base` öz
                # daxilində xətaları tutduğu üçün burada əlavə try/except
                # lazım deyil — bir bazanın xətası növbətini dayandırmır.
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
        errors: list[dict] | None = None,
    ) -> dict:
        """SRP: filter tətbiq edir və cavab strukturunu qurur.
        `errors` — kolleksiya boyunca `_record_error` vasitəsilə toplanmış
        bütün xətalar; bunlar `meta.errors` daxilində HƏMİŞƏ görünür (uğurlu
        nəticə olsa belə — qismən xəta ilə qismən uğur eyni anda ola bilər,
        məs. 4 NC-dən biri xəta versə, digər 3-ü uğurla toplanır)."""
        acl_entries:   list[dict] = []
        aces_filtered: int        = 0
        errors = errors if errors is not None else []

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
                "error_count":     len(errors),
                "errors":          errors,
            },
        }