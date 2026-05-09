import json
import re
from pathlib import Path

from ldap3 import Server, Connection, ALL, BASE, SUBTREE
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError
from ldap3.utils.conv import escape_filter_chars


def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    netbios = domain.split(".")[0].upper()
    return f"{netbios}\\{username}"


def _parse_isaclprotected(sd_raw) -> bool:
    if isinstance(sd_raw, (bytearray, memoryview)):
        sd_raw = bytes(sd_raw)
    if not isinstance(sd_raw, bytes) or len(sd_raw) < 4:
        return False
    try:
        control = int.from_bytes(sd_raw[2:4], byteorder="little")
        return bool(control & 0x1000)
    except Exception:
        return False


def _extract_domainsid_from_sid(sid_str: str) -> str:
    if not sid_str:
        return ""
    parts = sid_str.split("-")
    if len(parts) >= 8 and parts[2] == "5" and parts[3] == "21":
        return "-".join(parts[:-1])
    return ""


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _group_snapshot_candidates(config) -> list[Path]:
    candidates: list[Path] = []
    output_dir = getattr(config, "OUTPUT_DIR", "")
    if output_dir:
        candidates.append(Path(output_dir) / "domain_groups.json")
    root = _project_root()
    candidates.append(root / "Domain Object" / "domain_groups.json")
    candidates.append(root / "domain_groups.json")
    return candidates


def _load_group_rows(config) -> list[dict]:
    seen: set[str] = set()
    for path in _group_snapshot_candidates(config):
        path_key = str(path).lower()
        if path_key in seen:
            continue
        seen.add(path_key)
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            continue

        rows = payload.get("groups") if isinstance(payload, dict) else payload
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _resolve_group_dns_from_snapshot(config) -> list[dict]:
    groups = _load_group_rows(config)
    resolved: list[dict] = []
    for group in groups:
        group_name = str(group.get("name") or group.get("group_name") or group.get("sam_name") or group.get("samaccountname") or "").strip()
        group_dn = str(group.get("dn") or group.get("distinguishedName") or "").strip()
        if not group_name and not group_dn:
            continue
        resolved.append({
            "group_name": group_name,
            "group_dn": group_dn,
            "group_sid": str(group.get("sid") or group.get("group_sid") or "").strip(),
        })
    return resolved


# ─────────────────────────────────────────────────────────────────────────────
# İKİ MƏRHƏLƏLİ ÜZVLÜK İNJECTION
#
# MƏRHƏLƏ 1 — LDAP memberOf əsasında üzvlük (domain_users.json-dan)
#   domain_users.json-dakı hər userin "member_of" siyahısına baxılır.
#   Qrupun adı o siyahıda varsa user həmin qrupa əlavə edilir.
#   Bu üzvlər LDAP-ın explicit memberOf atributunu əks etdirir.
#
# MƏRHƏLƏ 2 — primaryGroupID əsasında üzvlük
#   LDAP "member" atributu primary group üzvlərini göstərmir.
#   (Domain Users qrupunda olan istifadəçilər buna misaldır.)
#   Yalnız MƏRHƏLƏ 1-də həmin qrupa əlavə edilməmiş userlər
#   primary_group_sid uyğunlaşdırması ilə yoxlanılır və əlavə edilir.
#   Beləliklə MƏRHƏLƏ 1-dən gələn üzvlərə heç bir müdaxilə olmur.
# ─────────────────────────────────────────────────────────────────────────────

def _user_snapshot_candidates(config) -> list[Path]:
    """domain_users.json faylı üçün axtarış sırası."""
    candidates: list[Path] = []
    output_dir = getattr(config, "OUTPUT_DIR", "")
    if output_dir:
        candidates.append(Path(output_dir) / "domain_users.json")
    root = _project_root()
    candidates.append(root / "Domain Object" / "domain_users.json")
    candidates.append(root / "domain_users.json")
    return candidates


def _load_user_rows(config) -> list[dict]:
    """domain_users.json-u oxuyub user siyahısını qaytarır."""
    seen: set[str] = set()
    for path in _user_snapshot_candidates(config):
        path_key = str(path).lower()
        if path_key in seen:
            continue
        seen.add(path_key)
        if not path.exists():
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            continue

        rows = payload.get("users") if isinstance(payload, dict) else payload
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _build_member_entry(user: dict) -> dict:
    """
    domain_users.json-dakı bir user sətirindən members/member_users
    strukturuna uyğun üzv obyekti qurur.
    """
    sid = str(user.get("sid") or "")
    return {
        "name": str(user.get("username") or user.get("sam_name") or user.get("sAMAccountName") or ""),
        "sid": sid,
        "dn": str(user.get("dn") or ""),
        "is_user": True,
        "is_group": False,
        "isaclprotected": bool(user.get("isaclprotected", False)),
        "domainsid": str(
            user.get("domain_sid")
            or _extract_domainsid_from_sid(sid)
        ),
    }


def _inject_memberof_members(
    merged_groups: list[dict],
    users: list[dict],
) -> None:
    """
    MƏRHƏLƏ 1 — domain_users.json-dakı "member_of" atributuna əsasən üzvlük.

    Hər userin "member_of" siyahısındakı qrup adları (case-insensitive)
    merged_groups-dakı qrupların adları ilə uyğunlaşdırılır.
    Uyğunluq tapılarsa user həmin qrupun members / member_users siyahısına
    əlavə edilir.

    VACIB: Bu mərhələdə əlavə edilən hər üzv "ldap_memberof_member: True"
    işarəsi alır ki, MƏRHƏLƏ 2 onu asanlıqla tanıya bilsin və
    primary group yoxlamasından keçirməsin.

    LDAP-dan gələn (batch sorğudan) mövcud members-lərə toxunulmur —
    onlar öz SID-ləri ilə existing_sids-ə daxil edilir ki,
    duplikat əlavə olunmasın.
    """
    # qrupları ad (kiçik hərf) → group dict xəritəsinə köçür
    groups_by_name: dict[str, dict] = {}
    for group in merged_groups:
        gname = str(group.get("group_name") or "").strip().lower()
        if gname:
            groups_by_name[gname] = group

    for user in users:
        member_of_raw = user.get("member_of") or []
        if not member_of_raw:
            continue

        member_entry = _build_member_entry(user)
        user_sid = member_entry["sid"]

        for mo_item in member_of_raw:
            mo_name = str(mo_item).strip().lower()
            if not mo_name:
                continue

            group = groups_by_name.get(mo_name)
            if group is None:
                continue  # bu adda qrup tapılmadı

            # LDAP sorğusundan gələn mövcud members-lərdəki SID-ləri yığ
            # (bu set hər qrup üçün bir dəfə qurulur — lazy init ilə)
            if "_phase1_sids" not in group:
                group["_phase1_sids"] = {
                    str(m.get("sid") or "")
                    for m in group.get("members", [])
                    if m.get("sid")
                }

            existing: set[str] = group["_phase1_sids"]
            if user_sid and user_sid in existing:
                continue  # artıq var (LDAP sorğusundan gəlib)

            # Mərhələ 1 işarəsi əlavə et — MƏRHƏLƏ 2 bunu görəcək
            tagged_entry = dict(member_entry)
            tagged_entry["ldap_memberof_member"] = True

            group.setdefault("members", []).append(tagged_entry)
            group.setdefault("member_users", []).append(tagged_entry)
            group["member_count"] = (group.get("member_count") or 0) + 1
            group["member_users_count"] = (group.get("member_users_count") or 0) + 1

            if user_sid:
                existing.add(user_sid)


def _build_primary_group_map(
    users: list[dict],
) -> dict[str, list[dict]]:
    """
    MƏRHƏLƏ 2 üçün primary_group_sid → [member_entry, ...] xəritəsi.

    primary_group_sid birbaşa mövcuddursa istifadə olunur; yoxdursa
    domain_sid + primary_group_id birləşməsindən özümüz qururuq.
    """
    pg_map: dict[str, list[dict]] = {}

    for user in users:
        pg_sid = str(user.get("primary_group_sid") or "").strip()

        if not pg_sid:
            domain_sid = str(user.get("domain_sid") or "").strip()
            pg_id = user.get("primary_group_id")
            if domain_sid and pg_id is not None:
                try:
                    pg_sid = f"{domain_sid}-{int(pg_id)}"
                except (TypeError, ValueError):
                    pass

        if not pg_sid:
            continue

        member_entry = _build_member_entry(user)
        # primary group üzvü olduğunu işarələ
        member_entry["primary_group_member"] = True
        pg_map.setdefault(pg_sid, []).append(member_entry)

    return pg_map


def _inject_primary_group_members(
    merged_groups: list[dict],
    pg_map: dict[str, list[dict]],
) -> None:
    """
    MƏRHƏLƏ 2 — primaryGroupID əsasında üzvlük.

    Hər qrup üçün primary_group_map yoxlanılır.
    Yalnız MƏRHƏLƏ 1-dən keçməmiş (ldap_memberof_member işarəsi olmayan)
    və LDAP batch sorğusundan gəlməmiş (SID-ə görə yoxlanır) userlər
    əlavə edilir.

    MƏRHƏLƏ 1-dən gələn üzvlərə (ldap_memberof_member=True) qətiyyən
    toxunulmur — onlar həmişə qalır.
    """
    for group in merged_groups:
        group_sid = str(group.get("group_sid") or group.get("sid") or "").strip()
        if not group_sid or group_sid not in pg_map:
            # lazım olduqda temp set-i təmizlə
            group.pop("_phase1_sids", None)
            continue

        pg_users = pg_map[group_sid]

        # bütün mövcud SID-ləri topla (LDAP + MƏRHƏLƏ 1)
        existing_sids: set[str] = group.pop("_phase1_sids", None) or {
            str(m.get("sid") or "")
            for m in group.get("members", [])
            if m.get("sid")
        }

        added_members: list[dict] = []
        added_users: list[dict] = []

        for pg_user in pg_users:
            user_sid = str(pg_user.get("sid") or "")
            if user_sid and user_sid in existing_sids:
                continue  # LDAP-dan və ya MƏRHƏLƏ 1-dən artıq var
            added_members.append(pg_user)
            added_users.append(pg_user)
            if user_sid:
                existing_sids.add(user_sid)

        if not added_members:
            continue

        group.setdefault("members", []).extend(added_members)
        group.setdefault("member_users", []).extend(added_users)
        group["member_count"] = (group.get("member_count") or 0) + len(added_members)
        group["member_users_count"] = (group.get("member_users_count") or 0) + len(added_users)

    # Qalan temp set-ləri təmizlə (primary_group_map-də olmayan qruplar üçün)
    for group in merged_groups:
        group.pop("_phase1_sids", None)


# ─────────────────────────────────────────────────────────────────────────────


def _resolve_group_members_from_connection(conn, group_name: str = "", group_dn: str = "") -> dict:
    group_name = str(group_name or "").strip()
    group_dn = str(group_dn or "").strip()
    if not group_name and not group_dn:
        return {"success": False, "error": "Missing group_name", "code": 400}

    if group_dn:
        conn.search(
            search_base=group_dn,
            search_filter="(objectClass=group)",
            search_scope=BASE,
            attributes=["member"],
        )
    else:
        escaped = escape_filter_chars(group_name)
        conn.search(
            search_base="",
            search_filter=f"(&(objectClass=group)(|(cn={escaped})(sAMAccountName={escaped})(name={escaped})))",
            search_scope=BASE,
            attributes=["member", "distinguishedName", "cn", "sAMAccountName", "objectSid"],
        )

    if not conn.entries:
        return {"success": False, "error": "Group not found", "code": 404}

    group_entry = conn.entries[0]
    members_attr = getattr(group_entry, "member", None)
    member_dns = [str(v) for v in (getattr(members_attr, "values", []) or [])]

    # Nested qrupların üzvlərini də əldə etmək üçün
    # LDAP_MATCHING_RULE_IN_CHAIN ilə ayrıca sorğu at
    nested_dn_set: set[str] = set(dn.lower() for dn in member_dns)
    try:
        chain_filter = f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn or group_entry.entry_dn)})"
        conn.search(
            search_base=group_entry.entry_dn,
            search_filter=chain_filter,
            search_scope=SUBTREE,
            attributes=["distinguishedName"],
        )
        for e in conn.entries:
            dn_val = str(getattr(e, "distinguishedName", None) or e.entry_dn or "")
            if dn_val and dn_val.lower() not in nested_dn_set:
                member_dns.append(dn_val)
                nested_dn_set.add(dn_val.lower())
    except Exception:
        pass  # fallback: yalnız birbaşa üzvlər istifadə olunur

    resolved = []
    for member_dn in member_dns:
        try:
            conn.search(
                search_base=member_dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["sAMAccountName", "cn", "objectSid", "objectClass", "nTSecurityDescriptor"],
            )
            if not conn.entries:
                resolved.append({
                    "name": member_dn,
                    "sid": "",
                    "dn": member_dn,
                    "is_user": False,
                    "is_group": False,
                    "isaclprotected": False,
                    "domainsid": "",
                })
                continue

            ment = conn.entries[0]
            sam = getattr(ment, "sAMAccountName", None)
            cn = getattr(ment, "cn", None)
            sid = getattr(ment, "objectSid", None)
            cls = getattr(ment, "objectClass", None)
            classes = [str(v).lower() for v in (getattr(cls, "values", []) or [])]

            sid_str = str(getattr(sid, "value", "") or "")

            ntsd_attr = getattr(ment, "nTSecurityDescriptor", None)
            ntsd_raw = getattr(ntsd_attr, "value", None)
            if isinstance(ntsd_raw, (bytearray, memoryview)):
                ntsd_raw = bytes(ntsd_raw)
            elif not isinstance(ntsd_raw, bytes):
                ntsd_raw = b""

            resolved.append({
                "name": str(getattr(sam, "value", None) or getattr(cn, "value", None) or member_dn),
                "sid": sid_str,
                "dn": member_dn,
                "is_user": "user" in classes and "computer" not in classes,
                "is_group": "group" in classes,
                "isaclprotected": _parse_isaclprotected(ntsd_raw),
                "domainsid": _extract_domainsid_from_sid(sid_str),
            })
        except Exception:
            resolved.append({
                "name": member_dn,
                "sid": "",
                "dn": member_dn,
                "is_user": False,
                "is_group": False,
                "isaclprotected": False,
                "domainsid": "",
            })

    users_only = [m for m in resolved if m.get("is_user")]
    return {
        "success": True,
        "group_name": group_name or str(getattr(group_entry, "cn", None) or getattr(group_entry, "sAMAccountName", None) or group_dn),
        "group_dn": group_dn,
        "members": resolved,
        "member_users": users_only,
        "member_count": len(member_dns),
        "member_users_count": len(users_only),
    }


def _merge_batch_results(results: list[dict]) -> dict:
    member_count = 0
    member_users_count = 0
    for item in results:
        member_count += int(item.get("member_count") or 0)
        member_users_count += int(item.get("member_users_count") or 0)
    return {
        "success": True,
        "mode": "batch",
        "group_count": len(results),
        "member_count": member_count,
        "member_users_count": member_users_count,
        "groups": results,
    }


def _resolve_group_members_batch(conn, group_rows: list[dict]) -> list[dict]:
    """
    Resolve members for multiple groups in a single LDAP query.

    Steps:
    - Ensure each group has a DN. If some groups only have names, resolve their DN/SID
      with a single search across the directory.
    - Query for all objects that have memberOf equal to any of the groups' DNs
      using a single OR filter.
    - Build per-group member lists from the results.
    """
    # prepare groups map by DN (lowercase) and fallback map for groups lacking DN
    groups_by_dn: dict[str, dict] = {}
    name_only = []
    for g in group_rows:
        dn = str(g.get("group_dn") or "").strip()
        name = str(g.get("group_name") or "").strip()
        if dn:
            groups_by_dn[dn.lower()] = {
                "group_name": name,
                "group_dn": dn,
                "group_sid": str(g.get("group_sid") or "").strip(),
                "members": [],
                "member_users": [],
                "member_count": 0,
                "member_users_count": 0,
            }
        elif name:
            name_only.append(name)
        else:
            # group without name or dn — include empty placeholder
            groups_by_dn[f"__unknown_{len(groups_by_dn)}"] = {
                "group_name": name,
                "group_dn": dn,
                "group_sid": str(g.get("group_sid") or "").strip(),
                "members": [],
                "member_users": [],
                "member_count": 0,
                "member_users_count": 0,
            }

    # If we have groups identified only by name, resolve their DN/SID in one query
    if name_only:
        or_parts = []
        for nm in name_only:
            esc = escape_filter_chars(nm)
            or_parts.append(f"(cn={esc})")
            or_parts.append(f"(sAMAccountName={esc})")
            or_parts.append(f"(name={esc})")
        name_filter = "(|" + "".join(or_parts) + ")"
        try:
            conn.search(
                search_base="",
                search_filter=f"(&(objectClass=group){name_filter})",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "cn", "sAMAccountName", "objectSid"],
            )
            for entry in conn.entries:
                dn_val = str(getattr(entry, "distinguishedName", None) or getattr(entry, "dn", None) or entry.entry_dn)
                cn = getattr(entry, "cn", None)
                sam = getattr(entry, "sAMAccountName", None)
                sid = getattr(entry, "objectSid", None)
                name_val = str(getattr(cn, "value", None) or getattr(sam, "value", None) or "").strip()
                dn_key = dn_val.strip().lower()
                groups_by_dn.setdefault(dn_key, {
                    "group_name": name_val,
                    "group_dn": dn_val,
                    "group_sid": str(getattr(sid, "value", "") or "").strip(),
                    "members": [],
                    "member_users": [],
                    "member_count": 0,
                    "member_users_count": 0,
                })
        except Exception:
            # if resolution fails, proceed with whatever DNs we have
            pass

    # Collect list of DNs to query memberOf for
    dn_list = [v.get("group_dn") for v in groups_by_dn.values() if v.get("group_dn")]
    dn_list = [d for d in dn_list if d]

    if dn_list:
        # LDAP_MATCHING_RULE_IN_CHAIN ilə HƏR QRUP ÜÇÜN AYRICA sorğu atılır.
        #
        # NIYƏ böyük OR filter işləmirdi?
        # OR filter nəticəsindəki entry.memberOf yalnız birbaşa qrupu göstərir.
        # Nested user-in memberOf-unda GroupA yox, yalnız GroupB var.
        # Ona görə groups_by_dn-də tapılmır və skip olunurdu.
        # Ayrıca sorğuda nəticələr artıq birbaşa hədəf qrupa aid olur.

        base_dn = ""
        try:
            base_dn = str(conn.server.info.other.get("defaultNamingContext", [""])[0])
        except Exception:
            pass

        for grp in groups_by_dn.values():
            group_dn_real = grp.get("group_dn", "")
            if not group_dn_real:
                continue

            chain_filter = (
                f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn_real)})"
            )
            seen_sids: set[str] = set()

            try:
                conn.search(
                    search_base=base_dn or group_dn_real,
                    search_filter=chain_filter,
                    search_scope=SUBTREE,
                    attributes=[
                        "sAMAccountName", "cn", "objectSid",
                        "objectClass", "nTSecurityDescriptor",
                    ],
                )
                for entry in conn.entries:
                    member_dn = str(
                        getattr(entry, "distinguishedName", None) or entry.entry_dn or ""
                    )
                    sam = getattr(entry, "sAMAccountName", None)
                    cn  = getattr(entry, "cn", None)
                    sid = getattr(entry, "objectSid", None)
                    cls = getattr(entry, "objectClass", None)
                    classes = [str(v).lower() for v in (getattr(cls, "values", []) or [])]

                    sid_str = str(getattr(sid, "value", "") or "")
                    dedup_key = sid_str or member_dn.lower()
                    if dedup_key in seen_sids:
                        continue
                    seen_sids.add(dedup_key)

                    ntsd_attr = getattr(entry, "nTSecurityDescriptor", None)
                    ntsd_raw  = getattr(ntsd_attr, "value", None)
                    if isinstance(ntsd_raw, (bytearray, memoryview)):
                        ntsd_raw = bytes(ntsd_raw)
                    elif not isinstance(ntsd_raw, bytes):
                        ntsd_raw = b""

                    member_obj = {
                        "name": str(
                            getattr(sam, "value", None)
                            or getattr(cn, "value", None)
                            or member_dn
                        ),
                        "sid": sid_str,
                        "dn": member_dn,
                        "is_user": "user" in classes and "computer" not in classes,
                        "is_group": "group" in classes,
                        "isaclprotected": _parse_isaclprotected(ntsd_raw),
                        "domainsid": _extract_domainsid_from_sid(sid_str),
                    }
                    grp.setdefault("members", []).append(member_obj)
                    if member_obj.get("is_user"):
                        grp.setdefault("member_users", []).append(member_obj)

            except Exception:
                pass

    # finalize counts
    results = []
    for grp in groups_by_dn.values():
        grp["member_count"] = len(grp.get("members", []))
        grp["member_users_count"] = len(grp.get("member_users", []))
        results.append(grp)

    return results


def _snapshot_output_path(config) -> Path:
    output_dir = getattr(config, "OUTPUT_DIR", "")
    if output_dir:
        return Path(output_dir) / "domain_groups.json"
    return _project_root() / "Domain Object" / "domain_groups.json"


def _write_group_snapshot(config, groups: list[dict]) -> None:
    output_path = _snapshot_output_path(config)
    payload = {"success": True, "groups": groups, "count": len(groups)}
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, default=str)
    except Exception:
        pass


def get_all_group_members(ip, domain, username, password, config):
    auth_type = "SIMPLE"
    if is_ntlm_hash(password):
        password = f"00000000000000000000000000000000:{password}"
        auth_type = "NTLM"

    bind_user = get_bind_user(username, domain)
    group_rows = _resolve_group_dns_from_snapshot(config)
    if not group_rows:
        return {"success": False, "error": "No groups found in domain_groups.json", "code": 404}

    # Hər iki mərhələ üçün user siyahısını bir dəfə yüklə
    users = _load_user_rows(config)
    # MƏRHƏLƏ 2 üçün primary group xəritəsini əvvəlcədən qur
    pg_map = _build_primary_group_map(users)

    try:
        server = Server(ip, get_info=ALL, connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        conn = Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=config.LDAP_RECEIVE_TIMEOUT,
        )

        # Resolve members for all groups in a single batched LDAP query
        batch_results = _resolve_group_members_batch(conn, group_rows)

        # merge original metadata with resolved members
        merged_groups = []
        # index batch results by lowercase DN or name when DN missing
        batch_index: dict[str, dict] = {}
        for br in batch_results:
            key = (br.get("group_dn") or br.get("group_name") or "").strip().lower()
            batch_index[key] = br

        for group_row in group_rows:
            dn = str(group_row.get("group_dn") or "").strip()
            name = str(group_row.get("group_name") or "").strip()
            lookup_key = dn.lower() if dn else name.lower()
            br = batch_index.get(lookup_key, {})
            merged_group = dict(group_row)
            merged_group.update({
                "group_dn": dn,
                "group_name": name,
                "group_sid": group_row.get("group_sid", ""),
                "members": br.get("members", []),
                "member_users": br.get("member_users", []),
                "member_count": br.get("member_count", 0),
                "member_users_count": br.get("member_users_count", 0),
            })
            merged_groups.append(merged_group)

        # MƏRHƏLƏ 1: domain_users.json member_of-dan gələn explicit üzvlər
        # (LDAP batch sorğusunda tapılmayanlar üçün)
        _inject_memberof_members(merged_groups, users)

        # MƏRHƏLƏ 2: primaryGroupID üzrə üzvlər
        # (nə LDAP-dan, nə də MƏRHƏLƏ 1-dən gələnlər buraya düşmür)
        _inject_primary_group_members(merged_groups, pg_map)

        conn.unbind()
        _write_group_snapshot(config, merged_groups)
        return _merge_batch_results(merged_groups)

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}


def get_group_members(ip, domain, username, password, group_dn, config):
    auth_type = "SIMPLE"
    if is_ntlm_hash(password):
        password = f"00000000000000000000000000000000:{password}"
        auth_type = "NTLM"

    bind_user = get_bind_user(username, domain)

    if not str(group_dn or "").strip() or str(group_dn).strip().lower() in {"*", "all", "__all__"}:
        return get_all_group_members(ip, domain, username, password, config)

    try:
        server = Server(ip, get_info=ALL, connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        conn = Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=config.LDAP_RECEIVE_TIMEOUT,
        )
        result = _resolve_group_members_from_connection(conn, group_dn=group_dn)

        # Tək qrup sorğusunda da iki mərhələli injection tətbiq et
        if result.get("success"):
            users = _load_user_rows(config)
            pg_map = _build_primary_group_map(users)
            # result-i merged_groups formatına uyğunlaşdır
            single_group = {
                "group_name": result.get("group_name", ""),
                "group_sid": group_dn,   # SID yoxdursa DN ilə axtarış olunmaz, inject skip edilər
                "members": result.get("members", []),
                "member_users": result.get("member_users", []),
                "member_count": result.get("member_count", 0),
                "member_users_count": result.get("member_users_count", 0),
            }
            # MƏRHƏLƏ 1: member_of-dan gələn explicit üzvlər
            _inject_memberof_members([single_group], users)
            # MƏRHƏLƏ 2: primary group üzvləri (MƏRHƏLƏ 1-dən keçməyənlər)
            _inject_primary_group_members([single_group], pg_map)
            result["members"] = single_group["members"]
            result["member_users"] = single_group["member_users"]
            result["member_count"] = single_group["member_count"]
            result["member_users_count"] = single_group["member_users_count"]

        conn.unbind()
        return result

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}