import re
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ldap3 import Server, Connection, ALL, BASE, SUBTREE
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPSocketOpenError
from ldap3.utils.conv import escape_filter_chars


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def domain_to_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    netbios = domain.split(".")[0].upper()
    return f"{netbios}\\{username}"


def normalize_value(value):
    if hasattr(value, "value"):
        value = value.value
    if isinstance(value, list):
        return value[0] if value else None
    return value


def safe_int(value, default=0):
    value = normalize_value(value)
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return default


def ldap_timestamp_to_iso(value):
    normalized = normalize_value(value)
    if normalized is None:
        return None
    if isinstance(normalized, datetime):
        return normalized.replace(tzinfo=timezone.utc).isoformat()
    if isinstance(normalized, str) and not normalized.isdigit():
        return normalized
    try:
        ticks = int(str(normalized))
    except (ValueError, TypeError):
        return str(normalized)
    if ticks in (0, 9223372036854775807):
        return None
    unix_seconds = (ticks - 116444736000000000) / 10000000
    try:
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        return dt.isoformat()
    except (OSError, OverflowError, ValueError):
        return str(normalized)


def decode_group_type(value: int) -> str:
    group_type = safe_int(value, 0)
    scope = "Unknown"
    category = "Security"

    if group_type & 0x00000002:
        scope = "Global"
    elif group_type & 0x00000004:
        scope = "Domain Local"
    elif group_type & 0x00000008:
        scope = "Universal"

    if not (group_type & 0x80000000):
        category = "Distribution"

    return f"{category} / {scope}"


def _parse_isaclprotected(sd_raw) -> bool:
    """
    nTSecurityDescriptor Control word-ünün SE_DACL_PROTECTED (0x1000) bitini yoxlayır.
    Set-dirsə ACL inheritance bloklanıb — BloodHound 'isaclprotected' field-i.
    """
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
    """
    Qrupun öz SID-indən domain SID-ini çıxarır.
    S-1-5-21-X-X-X-RID  →  S-1-5-21-X-X-X
    """
    if not sid_str:
        return ""
    parts = sid_str.split("-")
    if len(parts) >= 8 and parts[2] == "5" and parts[3] == "21":
        return "-".join(parts[:-1])
    return ""


def _parse_sid_history(entry) -> list:
    """
    sIDHistory atributunu oxuyur — köhnə domainlərdən miras qalan SID-lər.
    Migration zamanı təhlükəli ola bilər (privilege escalation riski).
    """
    sid_history_attr = getattr(entry, "sIDHistory", None)
    if not sid_history_attr:
        return []
    values = getattr(sid_history_attr, "values", []) or []
    return [str(v) for v in values if v]


def _is_protected_users_group(sid: str) -> bool:
    """
    Protected Users Group-u yoxlayır.
    Well-known RID: 525  →  SID S-1-5-21-<domain>-525
    """
    return sid.endswith("-525")


def _extract_rid_from_sid(sid: str) -> int | None:
    sid_text = str(sid or "").strip()
    if not sid_text:
        return None
    parts = sid_text.split("-")
    if not parts:
        return None
    try:
        return int(parts[-1])
    except (TypeError, ValueError):
        return None


def _is_potential_privileged_by_rid(rid: int | None) -> bool:
    potential_privileged_rids = {548, 549, 551, 520, 550, 569, 578, 582, 526, 527, 553, 557}
    return rid in potential_privileged_rids


# ═══════════════════════════════════════════════════════════════════════════════
# groups.py — DOMAIN GROUPS
# ═══════════════════════════════════════════════════════════════════════════════

def get_domain_groups(ip, domain, username, password, config):
    auth_type = "SIMPLE"
    if is_ntlm_hash(password):
        password = f"00000000000000000000000000000000:{password}"
        auth_type = "NTLM"

    base_dn = domain_to_dn(domain)
    bind_user = get_bind_user(username, domain)

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

        attrs = [
            "cn", "sAMAccountName", "distinguishedName", "description",
            "objectSid", "groupType", "managedBy",
            "adminCount", "whenCreated", "whenChanged", "memberOf",
            "nTSecurityDescriptor",  # isaclprotected üçün
            "primaryGroupToken",     # PrimaryGroupToken — bu qrupu primary group kimi
                                     # istifadə edən userları tapmaq üçün əsas dəyər
            "sIDHistory",            # SID History — köhnə domainlərdən miras SID-lər
        ]

        conn.search(
            base_dn,
            "(objectClass=group)",
            search_scope=SUBTREE,
            attributes=attrs,
            paged_size=getattr(config, "LDAP_PAGE_SIZE", 500),
        )

        groups = []
        for entry in conn.entries:
            def get_attr(attr_name):
                attr = getattr(entry, attr_name, None)
                if not attr:
                    return None
                return attr.value

            member_of = getattr(entry, "memberOf", None)
            member_of_list = [str(v) for v in (getattr(member_of, "values", []) or [])]
            group_type = safe_int(get_attr("groupType"), 0)
            name = str(get_attr("cn") or "")
            sam_name = str(get_attr("sAMAccountName") or "")
            sid = str(get_attr("objectSid") or "")

            # ── isaclprotected ───────────────────────────────────────────────
            ntsd_raw = get_attr("nTSecurityDescriptor")
            if isinstance(ntsd_raw, (bytearray, memoryview)):
                ntsd_raw = bytes(ntsd_raw)
            elif not isinstance(ntsd_raw, bytes):
                ntsd_raw = b""
            isaclprotected = _parse_isaclprotected(ntsd_raw)

            # ── domainsid ────────────────────────────────────────────────────
            domainsid = _extract_domainsid_from_sid(sid)

            # ── primaryGroupToken ────────────────────────────────────────────
            # Bu token-i primaryGroupID-i eyni olan userlar bu qrupu
            # primary group kimi istifadə edir (default: 513 = Domain Users)
            primary_group_token = safe_int(get_attr("primaryGroupToken"), None)

            # ── SID History ──────────────────────────────────────────────────
            # Köhnə domain SID-lərini saxlayır; migration sonrası silinməyibsə
            # privilege escalation riski yarada bilər
            sid_history = _parse_sid_history(entry)

            # ── Protected Users Group ────────────────────────────────────────
            # RID-525 qrupu — NTLM, RC4, unconstrained delegation-u bloklayır
            is_protected_users = _is_protected_users_group(sid)

            privileged_names = {
                "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
                "ADMINISTRATORS", "ACCOUNT OPERATORS", "SERVER OPERATORS",
                "BACKUP OPERATORS", "PRINT OPERATORS",
            }
            privileged_rids = ("-512", "-518", "-519", "-520", "-544", "-548", "-549", "-550")
            required_privileged_rids = {512, 519, 518, 544, 516, 498, 521}
            sid_rid = _extract_rid_from_sid(sid)
            potential_privileged = _is_potential_privileged_by_rid(sid_rid)
            is_privileged = (
                name.upper() in privileged_names or
                sam_name.upper() in privileged_names or
                sid.endswith(privileged_rids) or
                (sid_rid in required_privileged_rids)
            )

            risk_controls = []
            if is_privileged:
                risk_controls.append("Privileged Group")
            if len(member_of_list) > 0:
                risk_controls.append("Nested Group")
            if sid_history:
                risk_controls.append("SID History Present")
            if is_protected_users:
                risk_controls.append("Protected Users Group")

            groups.append({
                "name": name,
                "group_name": name,
                "sam_name": sam_name,
                "group_sid": sid,
                "dn": str(get_attr("distinguishedName") or ""),
                "description": str(get_attr("description") or ""),
                "sid": sid,
                "group_type": decode_group_type(group_type),
                "group_type_raw": group_type,
                "groupType": group_type,
                "member_count": None,
                "members": [],
                "member_users": [],
                "member_users_count": None,
                "member_of": member_of_list,
                "member_of_count": len(member_of_list),
                "is_empty": False,
                "is_nested": len(member_of_list) > 0,
                "is_privileged": is_privileged,
                "potential_privileged": potential_privileged,
                "managed_by": str(get_attr("managedBy") or ""),
                "managedBy": str(get_attr("managedBy") or ""),
                "is_protected": safe_int(get_attr("adminCount"), 0) == 1,
                "when_created": ldap_timestamp_to_iso(get_attr("whenCreated")),
                "when_changed": ldap_timestamp_to_iso(get_attr("whenChanged")),
                "isaclprotected": isaclprotected,       # ACL inheritance bloklanıb/bloklanmayıb
                "domainsid": domainsid,                 # Domain SID (cross-domain path üçün)
                "primary_group_token": primary_group_token,  # primaryGroupToken dəyəri
                "primaryGroupToken": primary_group_token,
                "sid_history": sid_history,             # Köhnə domain SID-lərinin siyahısı
                "is_protected_users_group": is_protected_users,  # RID-525 Protected Users
                "risk_controls": risk_controls,
            })

        conn.unbind()

        result = {"success": True, "groups": groups, "count": len(groups)}

        # ── domain_groups.jsonl-a yaz ────────────────────────────────────────
        # _jsonl_output_path() eyni prioritet sırasını (DOMAIN_OBJECT_DIR →
        # OUTPUT_DIR → fallback) tətbiq edir; Mərhələ 2 də eyni funksiyanı
        # istifadə edir, buna görə hər iki mərhələ eyni fayla yazır/oxuyur.
        output_path = _jsonl_output_path(config)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as f:
                # 1-ci sətir: meta
                meta = {"success": result["success"], "count": result["count"]}
                f.write(json.dumps(meta, ensure_ascii=False, default=str) + "\n")
                # Hər qrup ayrı sətirdə; members bu mərhələdə boş ([]) qalır
                for group in result["groups"]:
                    f.write(json.dumps(group, ensure_ascii=False, default=str) + "\n")
        except Exception as write_exc:
            result["json_export_error"] = str(write_exc)

        return result

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}


# ═══════════════════════════════════════════════════════════════════════════════
# group_member.py — GROUP MEMBERS
# ═══════════════════════════════════════════════════════════════════════════════

def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _group_snapshot_candidates(config) -> list[Path]:
    candidates: list[Path] = []
    domain_object_dir = getattr(config, "DOMAIN_OBJECT_DIR", "")
    if domain_object_dir:
        candidates.append(Path(domain_object_dir) / "domain_groups.jsonl")
    output_dir = getattr(config, "OUTPUT_DIR", "")
    if output_dir:
        candidates.append(Path(output_dir) / "domain_groups.jsonl")
    root = _project_root()
    candidates.append(root / "Domain Object" / "domain_groups.jsonl")
    candidates.append(root / "domain_groups.jsonl")
    return candidates


def _load_group_rows(config) -> list[dict]:
    """
    domain_groups.jsonl oxuyur.
    Format:
      - 1-ci sətir: meta {"success": ..., "count": ...}  — skip edilir
      - sonrakı hər sətir: bir qrup obyekti
    """
    seen: set[str] = set()
    for path in _group_snapshot_candidates(config):
        path_key = str(path).lower()
        if path_key in seen:
            continue
        seen.add(path_key)
        if not path.exists():
            continue
        try:
            rows: list[dict] = []
            with path.open("r", encoding="utf-8") as handle:
                for i, line in enumerate(handle):
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    if i == 0:
                        # meta sətir — "success" / "count" saxlayır, qrup deyil
                        continue
                    if isinstance(obj, dict):
                        rows.append(obj)
            if rows:
                return rows
        except Exception:
            continue
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
# MƏRHƏLƏ 1 — primaryGroupID əsasında üzvlük
#   Hər user üçün ƏVVƏLCƏ primary_group_sid yoxlanılır.
#   LDAP "member" atributu primary group üzvlərini göstərmir
#   (Domain Users qrupunda olan istifadəçilər buna misaldır).
#   Bu mərhələ LDAP batch sorğusundan gəlməmiş userləri
#   primary_group_sid uyğunlaşdırması ilə qruplara əlavə edir.
#
# MƏRHƏLƏ 2 — LDAP memberOf əsasında üzvlük (domain_users.json-dan)
#   domain_users.json-dakı hər userin "member_of" siyahısına baxılır.
#   Qrupun adı o siyahıda varsa user həmin qrupa əlavə edilir.
#   Bu üzvlər LDAP-ın explicit memberOf atributunu əks etdirir.
#   Yalnız MƏRHƏLƏ 1-dən keçməmiş userlər buraya düşür —
#   MƏRHƏLƏ 1-dən gələn üzvlərə heç bir müdaxilə olmur.
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


def _computer_snapshot_candidates(config) -> list[Path]:
    """domain_computers.jsonl faylı üçün axtarış sırası (domain_groups.jsonl ilə eyni prinsip)."""
    candidates: list[Path] = []
    domain_object_dir = getattr(config, "DOMAIN_OBJECT_DIR", "")
    if domain_object_dir:
        candidates.append(Path(domain_object_dir) / "domain_computers.jsonl")
    output_dir = getattr(config, "OUTPUT_DIR", "")
    if output_dir:
        candidates.append(Path(output_dir) / "domain_computers.jsonl")
    root = _project_root()
    candidates.append(root / "Domain Object" / "domain_computers.jsonl")
    candidates.append(root / "domain_computers.jsonl")
    return candidates


def _load_computer_rows(config) -> list[dict]:
    """
    domain_computers.jsonl oxuyub computer siyahısını qaytarır.
    Format:
      - 1-ci sətir: meta {"generated_at": ..., "success": ..., "count": ...} — skip edilir
      - sonrakı hər sətir: bir computer obyekti
    """
    seen: set[str] = set()
    for path in _computer_snapshot_candidates(config):
        path_key = str(path).lower()
        if path_key in seen:
            continue
        seen.add(path_key)
        if not path.exists():
            continue
        try:
            rows: list[dict] = []
            with path.open("r", encoding="utf-8") as handle:
                for i, line in enumerate(handle):
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    if i == 0:
                        continue  # meta sətir — computer deyil
                    if isinstance(obj, dict):
                        rows.append(obj)
            if rows:
                return rows
        except Exception:
            continue
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
        "is_computer": False,
        "isaclprotected": bool(user.get("isaclprotected", False)),
        "domainsid": str(
            user.get("domain_sid")
            or _extract_domainsid_from_sid(sid)
        ),
    }


def _build_computer_member_entry(computer: dict) -> dict:
    """
    domain_computers.jsonl-dəki bir computer sətirindən members/member_computers
    strukturuna uyğun üzv obyekti qurur.
    """
    sid = str(computer.get("sid") or "")
    return {
        "name": str(computer.get("computer_name") or ""),
        "sid": sid,
        "dn": str(computer.get("dn") or ""),
        "is_user": False,
        "is_group": False,
        "is_computer": True,
        "isaclprotected": bool(computer.get("isaclprotected", False)),
        "domainsid": str(computer.get("domainsid") or _extract_domainsid_from_sid(sid)),
    }


def _build_primary_group_map(
    users: list[dict],
) -> dict[str, list[dict]]:
    """
    MƏRHƏLƏ 1 üçün primary_group_sid → [member_entry, ...] xəritəsi.

    domain_users.jsonl-dakı hər userin primary_group_sid sahəsi birbaşa
    istifadə olunur. Sahə boşdursa domain_sid + primary_group_id
    birləşməsindən SID qurulur.

    Ayrıca LDAP sorğusu atılmır — bütün məlumat domain_users.jsonl-dan oxunur.
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
        member_entry["primary_group_member"] = True
        pg_map.setdefault(pg_sid, []).append(member_entry)

    return pg_map


def _build_primary_group_map_for_computers(
    computers: list[dict],
) -> dict[str, list[dict]]:
    """
    MƏRHƏLƏ 1 (computer hesabları) üçün primary_group_sid → [member_entry, ...] xəritəsi.

    domain_computers.jsonl-dakı hər computer üçün "domainsid" + "primary_group_id"
    birləşməsindən SID qurulur (computers.py "primary_group_sid" sahəsini birbaşa
    hesablamır, ona görə burada birbaşa qurulur).

    Ayrıca LDAP sorğusu atılmır — bütün məlumat domain_computers.jsonl-dan oxunur.
    """
    pg_map: dict[str, list[dict]] = {}

    for computer in computers:
        domain_sid = str(computer.get("domainsid") or "").strip()
        pg_id = computer.get("primary_group_id")

        if not domain_sid or pg_id is None:
            continue

        try:
            pg_sid = f"{domain_sid}-{int(pg_id)}"
        except (TypeError, ValueError):
            continue

        member_entry = _build_computer_member_entry(computer)
        member_entry["primary_group_member"] = True
        pg_map.setdefault(pg_sid, []).append(member_entry)

    return pg_map


def _inject_primary_group_members(
    merged_groups: list[dict],
    pg_map: dict[str, list[dict]],
) -> None:
    """
    MƏRHƏLƏ 1 — primary_group_sid əsasında üzvlük (user və ya computer).

    Bu funksiya həm domain_users.jsonl, həm də domain_computers.jsonl üçün
    işləyir — hansı pg_map verilibsə (istifadəçi xəritəsi yoxsa computer
    xəritəsi) onu inject edir. Hər member_entry-dəki "is_computer" bayrağına
    görə "member_users" yoxsa "member_computers" siyahısına yazılır.

    Hər user/computer üçün ƏVVƏLCƏ primary group yoxlanılır.
    LDAP "member" atributu primary group üzvlərini qaytarmır —
    (məsələn Domain Users qrupunun bütün üzvləri).
    Bu məlumat artıq domain_users.jsonl / domain_computers.jsonl-da
    mövcuddur; ayrıca LDAP sorğusu lazım deyil.

    Hər qrupun mövcud LDAP üzvləri (batch sorğudan gələnlər) SID-ə görə
    yoxlanılır — duplikat əlavə edilmir.
    İşlənmiş SID-lər _existing_sids temp key-inə yazılır ki,
    sonrakı çağırışlar (digər pg_map və ya MƏRHƏLƏ 2) onları görüb keçsin.
    """
    for group in merged_groups:
        group_sid = str(group.get("group_sid") or group.get("sid") or "").strip()
        if not group_sid or group_sid not in pg_map:
            continue

        pg_members = pg_map[group_sid]

        # LDAP batch sorğusundan gələn mövcud üzvlərin SID-lərini yığ
        if "_existing_sids" not in group:
            group["_existing_sids"] = {
                str(m.get("sid") or "")
                for m in group.get("members", [])
                if m.get("sid")
            }

        existing_sids: set[str] = group["_existing_sids"]

        for pg_member in pg_members:
            member_sid = str(pg_member.get("sid") or "")
            if member_sid and member_sid in existing_sids:
                continue  # LDAP batch sorğusundan artıq var
            group.setdefault("members", []).append(pg_member)
            if pg_member.get("is_computer"):
                group.setdefault("member_computers", []).append(pg_member)
                group["member_computers_count"] = (group.get("member_computers_count") or 0) + 1
            else:
                group.setdefault("member_users", []).append(pg_member)
                group["member_users_count"] = (group.get("member_users_count") or 0) + 1
            group["member_count"] = (group.get("member_count") or 0) + 1
            if member_sid:
                existing_sids.add(member_sid)


def _inject_memberof_members(
    merged_groups: list[dict],
    users: list[dict],
) -> None:
    """
    MƏRHƏLƏ 2 — domain_users.jsonl-dakı "member_of" atributuna əsasən üzvlük.

    Hər userin "member_of" siyahısındakı qrup adları (case-insensitive)
    merged_groups-dakı qrupların adları ilə uyğunlaşdırılır.
    Uyğunluq tapılarsa user həmin qrupun members / member_users siyahısına
    əlavə edilir.

    MƏRHƏLƏ 1-dən (_inject_primary_group_members) artıq əlavə edilmiş
    üzvlər _existing_sids temp key-i vasitəsilə tanınır və keçilir.
    Bu mərhələdən əlavə edilən üzvlər də _existing_sids-ə yazılır ki,
    sonrakı duplikatlar bloklanılsın.
    Temp key hər qrup üçün burada da lazy init olunur (MƏRHƏLƏ 1-dən
    keçməmiş qruplar üçün).
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

            # MƏRHƏLƏ 1-dən qalan _existing_sids-i götür; yoxdursa lazy init et
            if "_existing_sids" not in group:
                group["_existing_sids"] = {
                    str(m.get("sid") or "")
                    for m in group.get("members", [])
                    if m.get("sid")
                }

            existing: set[str] = group["_existing_sids"]
            if user_sid and user_sid in existing:
                continue  # LDAP-dan və ya MƏRHƏLƏ 1-dən artıq var

            group.setdefault("members", []).append(member_entry)
            group.setdefault("member_users", []).append(member_entry)
            group["member_count"] = (group.get("member_count") or 0) + 1
            group["member_users_count"] = (group.get("member_users_count") or 0) + 1

            if user_sid:
                existing.add(user_sid)

    # Bütün temp set-ləri təmizlə
    for group in merged_groups:
        group.pop("_existing_sids", None)


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
                    "is_computer": False,
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
                "is_computer": "computer" in classes,
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
                "is_computer": False,
                "isaclprotected": False,
                "domainsid": "",
            })

    users_only = [m for m in resolved if m.get("is_user")]
    computers_only = [m for m in resolved if m.get("is_computer")]
    return {
        "success": True,
        "group_name": group_name or str(getattr(group_entry, "cn", None) or getattr(group_entry, "sAMAccountName", None) or group_dn),
        "group_dn": group_dn,
        "members": resolved,
        "member_users": users_only,
        "member_computers": computers_only,
        "member_count": len(member_dns),
        "member_users_count": len(users_only),
        "member_computers_count": len(computers_only),
    }


def _merge_batch_results(results: list[dict]) -> dict:
    member_count = 0
    member_users_count = 0
    member_computers_count = 0
    for item in results:
        member_count += int(item.get("member_count") or 0)
        member_users_count += int(item.get("member_users_count") or 0)
        member_computers_count += int(item.get("member_computers_count") or 0)
    return {
        "success": True,
        "mode": "batch",
        "group_count": len(results),
        "member_count": member_count,
        "member_users_count": member_users_count,
        "member_computers_count": member_computers_count,
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
                "member_computers": [],
                "member_count": 0,
                "member_users_count": 0,
                "member_computers_count": 0,
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
                "member_computers": [],
                "member_count": 0,
                "member_users_count": 0,
                "member_computers_count": 0,
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
                    "member_computers": [],
                    "member_count": 0,
                    "member_users_count": 0,
                    "member_computers_count": 0,
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
                        "is_computer": "computer" in classes,
                        "isaclprotected": _parse_isaclprotected(ntsd_raw),
                        "domainsid": _extract_domainsid_from_sid(sid_str),
                    }
                    grp.setdefault("members", []).append(member_obj)
                    if member_obj.get("is_user"):
                        grp.setdefault("member_users", []).append(member_obj)
                    if member_obj.get("is_computer"):
                        grp.setdefault("member_computers", []).append(member_obj)

            except Exception:
                pass

    # finalize counts
    results = []
    for grp in groups_by_dn.values():
        grp["member_count"] = len(grp.get("members", []))
        grp["member_users_count"] = len(grp.get("member_users", []))
        grp["member_computers_count"] = len(grp.get("member_computers", []))
        results.append(grp)

    return results



def _jsonl_output_path(config) -> Path:
    """domain_groups.jsonl üçün çıxış yolu.

    Prioritet:
      1) config.DOMAIN_OBJECT_DIR (connection.py-də istifadə olunan rəsmi yol)
      2) config.OUTPUT_DIR
      3) <project_root>/Domain Object/domain_groups.jsonl (fallback)
    """
    domain_object_dir = getattr(config, "DOMAIN_OBJECT_DIR", "")
    if domain_object_dir:
        return Path(domain_object_dir) / "domain_groups.jsonl"
    output_dir = getattr(config, "OUTPUT_DIR", "")
    if output_dir:
        return Path(output_dir) / "domain_groups.jsonl"
    return _project_root() / "Domain Object" / "domain_groups.jsonl"


def write_group_members_jsonl(config, groups: list[dict], success: bool = True,
                               error: str | None = None) -> dict:
    """
    group_member modulunun tapdığı BÜTÜN nəticələri (members/member_users
    daxil olmaqla, tam doldurulmuş qrup obyektləri) domain_groups.jsonl
    faylına yazır.

    Format groups.py-dəki domain_groups.jsonl yazılışı ilə eynidir:
      - 1-ci sətir: meta {"success": ..., "count": ...}
      - sonrakı hər sətir: bir qrup obyekti (members/member_users daxil)

    Beləliklə sqlite_engine.py (domain_groups spec-i) bu faylı birbaşa,
    heç bir əlavə çevrilmə olmadan oxuya bilir.

    Returns: {"success": bool, "path": str, "count": int} və ya
             yazma zamanı xəta olarsa {"success": False, "error": str}.
    """
    # ── temp key-ləri və sayları normalize et ───────────────────────────────
    _TEMP_KEYS = {"_existing_sids"}
    _INTERNAL_MEMBER_KEYS = {"primary_group_member"}

    def _clean_group(group: dict) -> dict:
        """
        Yazılmadan əvvəl:
          - temp set key-lərini sil (_existing_sids)
          - member_users / member_computers / members siyahısındakı daxili işarə key-lərini sil
          - member_count / member_users_count / member_computers_count-u real siyahı uzunluğuna uyğunlaşdır
          - is_empty flag-ini yenilə
        """
        cleaned = {k: v for k, v in group.items() if k not in _TEMP_KEYS}

        def _strip_internal(lst):
            return [
                {k: v for k, v in m.items() if k not in _INTERNAL_MEMBER_KEYS}
                for m in (lst or [])
            ]

        cleaned_members = _strip_internal(cleaned.get("members"))
        cleaned_member_users = _strip_internal(cleaned.get("member_users"))
        cleaned_member_computers = _strip_internal(cleaned.get("member_computers"))

        cleaned["members"] = cleaned_members
        cleaned["member_users"] = cleaned_member_users
        cleaned["member_computers"] = cleaned_member_computers
        cleaned["member_count"] = len(cleaned_members)
        cleaned["member_users_count"] = len(cleaned_member_users)
        cleaned["member_computers_count"] = len(cleaned_member_computers)
        cleaned["is_empty"] = len(cleaned_members) == 0
        return cleaned

    output_path = _jsonl_output_path(config)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            meta = {"success": success, "count": len(groups)}
            if error:
                meta["error"] = error
            f.write(json.dumps(meta, ensure_ascii=False, default=str) + "\n")
            for group in groups:
                f.write(json.dumps(_clean_group(group), ensure_ascii=False, default=str) + "\n")
        return {"success": True, "path": str(output_path), "count": len(groups)}
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def get_all_group_members(ip, domain, username, password, config):
    auth_type = "SIMPLE"
    if is_ntlm_hash(password):
        password = f"00000000000000000000000000000000:{password}"
        auth_type = "NTLM"

    bind_user = get_bind_user(username, domain)
    group_rows = _resolve_group_dns_from_snapshot(config)
    if not group_rows:
        return {"success": False, "error": "No groups found in domain_groups.jsonl", "code": 404}

    # Hər iki mərhələ üçün user və computer siyahısını bir dəfə yüklə
    users = _load_user_rows(config)
    computers = _load_computer_rows(config)
    # MƏRHƏLƏ 1 üçün primary group xəritələrini əvvəlcədən qur (user + computer)
    pg_map = _build_primary_group_map(users)
    pg_map_computers = _build_primary_group_map_for_computers(computers)

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
                "member_computers": br.get("member_computers", []),
                "member_count": br.get("member_count", 0),
                "member_users_count": br.get("member_users_count", 0),
                "member_computers_count": br.get("member_computers_count", 0),
            })
            merged_groups.append(merged_group)

        # MƏRHƏLƏ 1: primaryGroupID üzrə üzvlər (user + computer)
        # domain_users.jsonl / domain_computers.jsonl-dakı primary_group_id
        # əsasında — ayrıca LDAP sorğusu yoxdur.
        # Hər user/computer üçün əvvəlcə primary group yoxlanılır.
        _inject_primary_group_members(merged_groups, pg_map)
        _inject_primary_group_members(merged_groups, pg_map_computers)

        # MƏRHƏLƏ 2: domain_users.jsonl member_of-dan gələn explicit üzvlər
        # (nə LDAP-dan, nə də MƏRHƏLƏ 1-dən gələnlər buraya düşmür)
        _inject_memberof_members(merged_groups, users)

        conn.unbind()
        write_group_members_jsonl(config, merged_groups, success=True)
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
            computers = _load_computer_rows(config)
            pg_map = _build_primary_group_map(users)
            pg_map_computers = _build_primary_group_map_for_computers(computers)
            # result-i merged_groups formatına uyğunlaşdır
            single_group = {
                "group_name": result.get("group_name", ""),
                "group_sid": group_dn,   # SID yoxdursa DN ilə axtarış olunmaz, inject skip edilər
                "members": result.get("members", []),
                "member_users": result.get("member_users", []),
                "member_computers": result.get("member_computers", []),
                "member_count": result.get("member_count", 0),
                "member_users_count": result.get("member_users_count", 0),
                "member_computers_count": result.get("member_computers_count", 0),
            }
            # MƏRHƏLƏ 1: primary group üzvləri (user + computer)
            # domain_users.jsonl / domain_computers.jsonl-dakı primary_group_id
            # əsasında — ayrıca LDAP sorğusu yoxdur
            _inject_primary_group_members([single_group], pg_map)
            _inject_primary_group_members([single_group], pg_map_computers)
            # MƏRHƏLƏ 2: member_of-dan gələn explicit üzvlər (MƏRHƏLƏ 1-dən keçməyənlər)
            _inject_memberof_members([single_group], users)
            result["members"] = single_group["members"]
            result["member_users"] = single_group["member_users"]
            result["member_computers"] = single_group["member_computers"]
            result["member_count"] = single_group["member_count"]
            result["member_users_count"] = single_group["member_users_count"]
            result["member_computers_count"] = single_group["member_computers_count"]

        conn.unbind()
        return result

    except LDAPInvalidCredentialsResult:
        return {"success": False, "error": "Authentication failed", "code": 401}
    except LDAPSocketOpenError:
        return {"success": False, "error": "Could not connect to the server", "code": 503}
    except Exception as exc:
        return {"success": False, "error": f"Internal server error: {exc}", "code": 500}


# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE — GROUPS + MEMBERS (İKİ MƏRHƏLƏ)
# ═══════════════════════════════════════════════════════════════════════════════

def run_domain_groups_pipeline(ip, domain, username, password, config) -> dict:
    """
    İki mərhələli pipeline:

    MƏRHƏLƏ 1 — get_domain_groups()
        LDAP-dan bütün qrupları çəkir və domain_groups.jsonl faylını yaradır.
        Bu mərhələdə hər qrupun "members" massivi boş ([]) qalır.

    MƏRHƏLƏ 2 — get_all_group_members()
        domain_groups.jsonl-dən qrup adlarını/DN-lərini oxuyur,
        LDAP-dan hər qrupun üzvlərini çəkir (nested daxil).
        Əlavə olaraq domain_users.jsonl-dan:
          1) primary_group_sid əsasında primary group üzvlərini inject edir,
          2) member_of əsasında explicit üzvləri inject edir.
        Nəticəni eyni domain_groups.jsonl faylına "members" massivi
        içinə yazır (faylı tamamilə yenidən yazır).

    Qaytarılan dəyər:
        {
            "success": bool,
            "stage1": <get_domain_groups nəticəsi>,
            "stage2": <get_all_group_members nəticəsi>,   # yalnız uğurlu olarsa
            "jsonl_path": str,
            "group_count": int,
            "member_count": int,
            "member_users_count": int,
            "member_computers_count": int,
        }
    """
    # ── MƏRHƏLƏ 1: qrupları çək, JSONL yarat ────────────────────────────────
    stage1 = get_domain_groups(ip, domain, username, password, config)

    if not stage1.get("success"):
        return {
            "success": False,
            "stage": "groups",
            "stage1": stage1,
            "error": stage1.get("error", "get_domain_groups failed"),
            "code": stage1.get("code", 500),
        }

    jsonl_path = str(_jsonl_output_path(config))

    # ── MƏRHƏLƏ 2: JSONL-dən oxu, members doldur, geri yaz ──────────────────
    stage2 = get_all_group_members(ip, domain, username, password, config)

    if not stage2.get("success"):
        return {
            "success": False,
            "stage": "members",
            "stage1": stage1,
            "stage2": stage2,
            "jsonl_path": jsonl_path,
            "error": stage2.get("error", "get_all_group_members failed"),
            "code": stage2.get("code", 500),
        }

    return {
        "success": True,
        "stage1": stage1,
        "stage2": stage2,
        "jsonl_path": jsonl_path,
        "group_count": stage1.get("count", 0),
        "member_count": stage2.get("member_count", 0),
        "member_users_count": stage2.get("member_users_count", 0),
        "member_computers_count": stage2.get("member_computers_count", 0),
    }