from .constants import (
    TARGET_FILTER,
    _SD_FLAGS,
    _SD_FLAGS_FULL,
    _AD_SENSITIVE_TEMPLATES,
    _DEEP_SCAN_BASES,
    _DEEP_SCAN_CRITICAL_SUBTREES,
)
from .models import LdapBackend, SecurityDescriptorParser, AclFilterConfig, ObjectScope
from .parsers import (
    _build_sid_map,
    _resolve_self_dn,
    _fetch_object_sd,
    _paged_search,
    _parse_dacl_to_records,
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

class AclCollector:


    def __init__(
        self,
        conn: LdapBackend,
        base_dn: str,
        parser: SecurityDescriptorParser,
        page_size: int = 200,
        guid_map: dict[str, str] | None = None,
    ) -> None:
        self._conn         = conn
        self._base_dn      = base_dn
        self._parser       = parser
        self._page_size    = page_size
        self._resolver     = ScopeResolver()
        self._sid_map, self._disabled_sids = _build_sid_map(
            conn, base_dn, page_size=page_size
        )
        self._guid_map = guid_map

    def collect(
        self,
        flt: AclFilterConfig,
        scope: ObjectScope = ObjectScope.SECURITY_PRINCIPALS,
        custom_filter: str = "",
    ) -> dict:
        
        if flt.self_acl_only:
            return self._collect_self(flt)
        return self._collect_by_scope(flt, scope, custom_filter)

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
            # DN-lər artıq məlumdur — birbaşa BASE sorğusu
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
                all_records.extend(
                    _parse_dacl_to_records(
                        raw_values[0], entry_dn, entry,
                        self._sid_map, self._parser,
                            disabled_sids=self._disabled_sids,
                            guid_map=self._guid_map,
                        skip_inherit_only=False,
                    )
                )
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

            seen_dns: set[str] = set()

            for base in effective_bases:

                dn_entries = _paged_search(
                    self._conn, base, ldap_filter,
                    attributes=["distinguishedName", "objectClass",
                                "name", "whenChanged"],
                    page_size=self._page_size,
                    search_scope="SUBTREE",
                )
                # Mərhələ 2: Hər DN üçün ayrıca BASE sorğusu ilə SD oxu.
                # Yalnız nTSecurityDescriptor raw_values mövcud olan obyektlər
                # işlənir — atributu olmayan (məs. silinmiş, irsiyyət olmayan)
                # obyektlər avtomatik keçilir.
                for meta_entry in dn_entries:
                    dn = str(normalize_value(
                        getattr(meta_entry, "distinguishedName", None)) or "")
                    if not dn:
                        continue
                    # DN deduplication — eyni obyekti bir neçə search bazasından gələndə
                    # təkrar işləməmək üçün.
                    if dn in seen_dns:
                        continue
                    seen_dns.add(dn)

                    self._conn.search(
                        dn, "(objectClass=*)",
                        search_scope="BASE",
                        attributes=["name", "distinguishedName", "objectClass",
                                    "whenChanged", "objectSid", "nTSecurityDescriptor"],
                        controls=sd_ctrl_norm,
                    )
                    if not self._conn.entries:
                        continue
                    sd_entry   = self._conn.entries[0]
                    raw_values = getattr(
                        getattr(sd_entry, "nTSecurityDescriptor", None),
                        "raw_values", None
                    ) or []
                    # nTSecurityDescriptor mövcud deyilsə obyekti keç —
                    # istifadəçinin "yalnız SD olan obyektlər" tələbini yerinə yetirir.
                    if not raw_values:
                        continue
                    objects_with_sd += 1
                    all_records.extend(
                        _parse_dacl_to_records(
                            raw_values[0], dn, sd_entry,
                            self._sid_map, self._parser,
                            disabled_sids=self._disabled_sids,
                            guid_map=self._guid_map,
                            skip_inherit_only=False,
                        )
                    )

        return self._build_result(all_records, flt,
                                   objects_with_sd=objects_with_sd,
                                   skip_inherit_only=False)

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