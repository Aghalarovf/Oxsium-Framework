"""
Group Policy Objects (GPO) - Tam Enumeration Modulu
Əhatə edir: GPO Link, Scope, Inheritance, Enforcement, Block Inheritance,
GPP Passwords (cPassword), Scheduled Tasks, Immediate Tasks, Restricted Groups,
Files & Scripts, Registry Settings, All XML files, GPP-decrypt,
Software Installation, Drive Mappings, GPO Creator/Owner,
Description, gPCFileSysPath, SYSVOL ACL
"""

import re
import os
import base64
import struct
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import PureWindowsPath

from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException

try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb3structs import FILE_READ_DATA, FILE_LIST_DIRECTORY
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

# ─────────────────────────────────────────────
# AES-256-CBC key — Microsoft tərəfindən public
# MS-GPPREF spec-dən: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref
# ─────────────────────────────────────────────
GPP_AES_KEY = bytes([
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
])
GPP_AES_IV = b"\x00" * 16

# gPCUserExtensionNames / gPCMachineExtensionNames içindəki GUID-lərin
# insan oxuya biləcək adlara map-i (ən çox rast gəlinənlər)
EXTENSION_GUID_MAP = {
    "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": "Registry Settings",
    "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": "Security Settings",
    "{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}": "EFS Recovery Policy",
    "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}": "Scripts (Startup/Shutdown)",
    "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}": "Scripts (Logon/Logoff)",
    "{00000000-0000-0000-0000-000000000000}": "Core GPO",
    "{0F6B957E-509E-11D1-A7CC-0000F87571E3}": "Tool Extension Policy",
    "{0F6B957D-509E-11D1-A7CC-0000F87571E3}": "Tool Extension Policy",
    "{1612B55C-243C-48DD-A449-FFC097B19776}": "Deployed Printer Connections",
    "{1A6364EB-776B-4120-ADE1-B63A406A76B5}": "Offline Files",
    "{25537BA6-77A8-11D2-9B6C-0000F8080861}": "Folder Redirection",
    "{2BFCC077-22D2-48DE-BDE1-2F618D9B476D}": "AppV Policy",
    "{3060E8CE-7020-11D2-842D-00C04FA372D4}": "Remote Installation Services",
    "{3610EDA5-77EF-11D2-8DC5-00C04FA31A66}": "Microsoft Disk Quota",
    "{4CFB60C1-FAA6-47F1-89AA-0B18730C9FD3}": "Internet Explorer Zonemapping",
    "{4D2F9B6F-1E52-4711-A5BE-012D73A3A073}": "Drive Maps",
    "{516FC620-5D34-4B08-8165-6A06B623EDEB}": "Scheduled Tasks",
    "{53D6AB1B-2488-11D1-A28C-00C04FB94F17}": "EFS Recovery",
    "{5794DAFD-BE60-433F-88A2-1A31939AC01F}": "Drive Mappings",
    "{6232C319-91AC-4931-9385-E70C2B099F0E}": "Group Policy Folders",
    "{6A4C88C6-C502-4F74-8F60-2CB23EDC9E0A}": "Group Policy Network Options",
    "{728EE579-943C-4519-9EF7-AB56765798ED}": "Group Policy Data Sources",
    "{74EE6C03-5363-4554-B161-627540339CAB}": "Group Policy ini Files",
    "{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}": "Group Policy Files",
    "{7933F41E-56F8-41D6-A31C-4148A711EE93}": "Group Policy Internet Settings",
    "{A3F3E39B-5D83-4940-B954-28315B82F0A8}": "Group Policy Folder Options",
    "{AADCED64-746C-4633-A97C-D61349046527}": "Group Policy Scheduled Tasks",
    "{B087BE9D-ED37-454F-AF9C-04291E351182}": "Group Policy Registry",
    "{B9CCA4DE-E2B9-4CBD-BF7D-11B6EBFBDDF7}": "Group Policy Printers",
    "{BA649533-0AAC-4E04-B9B8-3D492B3CC60A}": "Group Policy Network Shares",
    "{C6DC5466-785A-11D2-84D0-00C04FB169F7}": "Software Installation",
    "{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}": "Scheduled Tasks (Immediate)",
    "{CF7639F3-ABA2-41DB-97F2-81E2C5DBFC5D}": "Internet Explorer",
    "{E437BC1C-AA7D-11D2-A382-00C04F991E27}": "IP Security",
    "{F9C77450-3A41-477E-9310-9ACD617BD9E3}": "Group Policy Applications",
    "{FB2CA36D-0B40-4307-821B-A13B252DE56C}": "Group Policy Environment",
    "{FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F}": "Group Policy Shortcuts",
    "{169EBF44-942F-4C43-87CE-13C93996EBBE}": "Group Policy Wireless (Vista+)",
    "{91FBB303-0CD5-4055-BF42-E512A681B325}": "Group Policy Wired Policy",
    "{40B6664F-4972-11D1-A7CA-0000F87571E3}": "Scripts",
    "{CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA}": "TCPIP",
    "{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}": "Group Policy Wireless",
    "{E5094040-C46C-4115-B030-04FB2E545B6F}": "Group Policy Regional Options",
    "{E62688F0-25FD-4C90-BFF5-F508B9D2E31F}": "Group Policy Power Options",
    "{EC4828A8-A768-4A2E-9edd-A73165B7D600}": "Group Policy Start Menu",
    "{F0DB2806-FD46-45B7-81BD-AA0B4B6E7AEB}": "Group Policy Task Bar",
    "{F581DAE7-8064-444A-AEB3-1875662A61CE}": "Group Policy Services",
    "{FD500BEF-9F03-4F58-97B8-2e51C2218566}": "Group Policy Local Users and Groups",
}

# nTSecurityDescriptor ACE Rights (en çox rast gəlinənlər)
ACE_RIGHTS_MAP = {
    0x00000001: "CC",   # CreateChild
    0x00000002: "DC",   # DeleteChild
    0x00000004: "LC",   # ListChildren
    0x00000008: "SW",   # Self
    0x00000010: "RP",   # ReadProperty
    0x00000020: "WP",   # WriteProperty
    0x00000040: "DT",   # DeleteTree
    0x00000080: "LO",   # ListObject
    0x00000100: "CR",   # ControlAccess
    0x00010000: "DE",   # Delete
    0x00020000: "RC",   # ReadControl
    0x00040000: "WD",   # WriteDACL
    0x00080000: "WO",   # WriteOwner
    0x00100000: "SY",   # Synchronize
    0x00F00000: "ST",   # StandardRightsRequired
    0x001F01FF: "FA",   # FullControl
    0x00120089: "FR",   # FileReadAccess (SYSVOL üçün)
    0x00120116: "FW",   # FileWriteAccess (SYSVOL üçün)
}


# ═══════════════════════════════════════════════════════
#  YARDIMÇI FUNKSIYALAR
# ═══════════════════════════════════════════════════════

def is_ntlm_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}", value or ""))


def get_bind_user(username: str, domain: str) -> str:
    if "@" in username or "\\" in username:
        return username
    netbios = domain.split(".")[0].upper()
    return f"{netbios}\\{username}"


def normalize_value(val):
    if val is None:
        return ""
    if hasattr(val, 'value'):
        return str(val.value) if val.value is not None else ""
    return str(val)


def normalize_values(val):
    if val is None:
        return []
    if hasattr(val, 'values'):
        return [str(v) for v in val.values if v is not None]
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    return [str(val)]


def safe_int(val, default=0):
    try:
        if val is None:
            return default
        if hasattr(val, 'value'):
            val = val.value
        if isinstance(val, bool):
            return default
        return int(val)
    except (ValueError, TypeError):
        try:
            return int(str(val))
        except (ValueError, TypeError):
            return default


def ldap_timestamp_to_iso(timestamp_value):
    try:
        if timestamp_value is None:
            return "Never"
        raw = timestamp_value.value if hasattr(timestamp_value, 'value') else timestamp_value
        if isinstance(raw, datetime):
            if raw.tzinfo is None:
                raw = raw.replace(tzinfo=timezone.utc)
            return raw.isoformat()
        if isinstance(raw, str):
            return raw
        ts = safe_int(raw, 0)
        if ts <= 0:
            return "Never"
        unix_seconds = (ts - 116444736000000000) / 10000000
        return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).isoformat()
    except Exception:
        return "Unknown"


# ═══════════════════════════════════════════════════════
#  GPP cPASSWORD DECRYPT
# ═══════════════════════════════════════════════════════

def _gpp_b64decode(cpassword: str) -> bytes:
    """
    Base64 padding-i düzəldib decode edir.
    GPP cPassword-lər bəzən trailing '=' olmadan gəlir.
    """
    pad = 4 - len(cpassword) % 4
    if pad != 4:
        cpassword += "=" * pad
    return base64.b64decode(cpassword)


def _gpp_strip_pkcs7(data: bytes) -> bytes:
    """PKCS7 padding-i silir; etibarsız padding halında orijinalı qaytarır."""
    if not data:
        return data
    pad_len = data[-1]
    if isinstance(pad_len, int) and 1 <= pad_len <= 16:
        return data[:-pad_len]
    return data


def _gpp_decrypt(cpassword: str) -> str:
    """
    GPP cPassword-i AES-256-CBC ilə decrypt edir.
    Microsoft-un public AES-256-CBC key-i istifadə olunur (MS-GPPREF).

    Fallback sırası:
      1. pycryptodome  (Crypto.Cipher.AES)
      2. cryptography  (cryptography.hazmat.primitives.ciphers)
      3. [DECRYPT_UNAVAILABLE] xəta mesajı

    Köhnə impacket AESDECRYPTBlock yanaşması silindi — o, xəta halında
    bloğu dəyişmədən qaytarır, XOR sonrası saçma mətn hasil olur.
    """
    if not cpassword:
        return ""
    try:
        ct = _gpp_b64decode(cpassword)
    except Exception:
        return f"[DECRYPT_ERROR: invalid base64 — {cpassword[:20]}...]"

    # ── Tier 1: pycryptodome ────────────────────────────────────────────
    try:
        from Crypto.Cipher import AES as _AES
        cipher = _AES.new(GPP_AES_KEY, _AES.MODE_CBC, GPP_AES_IV)
        raw = _gpp_strip_pkcs7(cipher.decrypt(ct))
        return raw.decode("utf-16-le", errors="replace").strip("\x00")
    except ImportError:
        pass
    except Exception as e:
        return f"[DECRYPT_ERROR: {e}]"

    # ── Tier 2: cryptography paketi ─────────────────────────────────────
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher as _Cipher, algorithms as _alg, modes as _mode
        )
        from cryptography.hazmat.backends import default_backend as _backend
        cipher = _Cipher(_alg.AES(GPP_AES_KEY), _mode.CBC(GPP_AES_IV),
                         backend=_backend())
        dec = cipher.decryptor()
        raw = _gpp_strip_pkcs7(dec.update(ct) + dec.finalize())
        return raw.decode("utf-16-le", errors="replace").strip("\x00")
    except ImportError:
        pass
    except Exception as e:
        return f"[DECRYPT_ERROR: {e}]"

    # ── Tier 3: heç bir paket yoxdur ────────────────────────────────────
    return "[DECRYPT_UNAVAILABLE: pip install pycryptodome  OR  pip install cryptography]"


# ═══════════════════════════════════════════════════════
#  LDAP SECURITY DESCRIPTOR PARSE
# ═══════════════════════════════════════════════════════

def _parse_isaclprotected(sd_raw) -> bool:
    """SE_DACL_PROTECTED (0x1000) bitini yoxlayır."""
    if isinstance(sd_raw, (bytearray, memoryview)):
        sd_raw = bytes(sd_raw)
    if not isinstance(sd_raw, bytes) or len(sd_raw) < 4:
        return False
    try:
        control = int.from_bytes(sd_raw[2:4], byteorder="little")
        return bool(control & 0x1000)
    except Exception:
        return False


def _parse_sd_owner(sd_raw: bytes) -> str:
    """
    nTSecurityDescriptor-dan Owner SID-ini çıxarır.
    Security Descriptor binary formatı:
      Offset 0: Revision (1 byte)
      Offset 1: Sbz1 (1 byte)
      Offset 2-3: Control (2 bytes, LE)
      Offset 4-7: OffsetOwner (4 bytes, LE)
      Offset 8-11: OffsetGroup (4 bytes, LE)
      Offset 12-15: OffsetSacl (4 bytes, LE)
      Offset 16-19: OffsetDacl (4 bytes, LE)
    """
    if not isinstance(sd_raw, bytes) or len(sd_raw) < 20:
        return ""
    try:
        offset_owner = struct.unpack_from("<I", sd_raw, 4)[0]
        if offset_owner == 0 or offset_owner >= len(sd_raw):
            return ""
        return _sid_bytes_to_str(sd_raw[offset_owner:])
    except Exception:
        return ""


def _sid_bytes_to_str(data: bytes) -> str:
    """
    Binary SID-i S-R-X-Y... formatına çevirir.
    SID struktur: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthorities(4 each)
    """
    if not data or len(data) < 8:
        return ""
    try:
        revision = data[0]
        sub_count = data[1]
        authority = int.from_bytes(data[2:8], byteorder="big")
        subs = []
        for i in range(sub_count):
            offset = 8 + i * 4
            if offset + 4 > len(data):
                break
            subs.append(struct.unpack_from("<I", data, offset)[0])
        return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)
    except Exception:
        return ""


def _parse_dacl_aces(sd_raw: bytes) -> list:
    """
    DACL-dən ACE siyahısını çıxarır.
    Hər ACE üçün: type, rights, trustee_sid, inherited.
    """
    aces = []
    if not isinstance(sd_raw, bytes) or len(sd_raw) < 20:
        return aces
    try:
        control = struct.unpack_from("<H", sd_raw, 2)[0]
        # SE_DACL_PRESENT (0x0004) yoxla
        if not (control & 0x0004):
            return aces
        offset_dacl = struct.unpack_from("<I", sd_raw, 16)[0]
        if offset_dacl == 0 or offset_dacl + 8 > len(sd_raw):
            return aces

        # ACL header: AclRevision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)
        ace_count = struct.unpack_from("<H", sd_raw, offset_dacl + 4)[0]
        pos = offset_dacl + 8

        # FIX #6: ACCESS_ALLOWED_OBJECT (type=5) və ACCESS_DENIED_OBJECT (type=6)
        # ACE-lərinin strukturu fərqlidir:
        #   Offset 0:  AceType  (1 byte)
        #   Offset 1:  AceFlags (1 byte)
        #   Offset 2:  AceSize  (2 bytes)
        #   Offset 4:  Mask     (4 bytes)
        #   Offset 8:  Flags    (4 bytes) ← OBJECT ACE-yə məxsus
        #   Offset 12: ObjectType GUID    (16 bytes, əgər Flags & 1)
        #   Offset 12 or 28: InheritedObjectType GUID (16 bytes, əgər Flags & 2)
        # Sonra SID gəlir — sabit 8 deyil, dinamik offset lazımdır.
        OBJECT_ACE_TYPES = {5, 6, 11, 12}  # *_OBJECT variantları
        ace_type_names = {
            0: "ACCESS_ALLOWED", 1: "ACCESS_DENIED",
            5: "ACCESS_ALLOWED_OBJECT", 6: "ACCESS_DENIED_OBJECT",
        }

        for _ in range(ace_count):
            if pos + 4 > len(sd_raw):
                break
            ace_type  = sd_raw[pos]
            ace_flags = sd_raw[pos + 1]
            ace_size  = struct.unpack_from("<H", sd_raw, pos + 2)[0]
            if ace_size < 8 or pos + ace_size > len(sd_raw):
                break

            access_mask = struct.unpack_from("<I", sd_raw, pos + 4)[0]

            # SID offset-i ACE tipinə görə hesabla
            if ace_type in OBJECT_ACE_TYPES and ace_size >= 12:
                # Flags field (4 bytes) @ pos+8
                obj_flags = struct.unpack_from("<I", sd_raw, pos + 8)[0]
                sid_offset = pos + 12
                if obj_flags & 0x1:   # ACE_OBJECT_TYPE_PRESENT
                    sid_offset += 16
                if obj_flags & 0x2:   # ACE_INHERITED_OBJECT_TYPE_PRESENT
                    sid_offset += 16
            else:
                sid_offset = pos + 8

            sid_data = sd_raw[sid_offset: pos + ace_size]
            trustee  = _sid_bytes_to_str(sid_data)

            inherited = bool(ace_flags & 0x10)  # INHERITED_ACE

            rights = []
            for bit, name in ACE_RIGHTS_MAP.items():
                if access_mask & bit == bit:
                    rights.append(name)

            aces.append({
                "type": ace_type_names.get(ace_type, f"TYPE_{ace_type}"),
                "access_mask": hex(access_mask),
                "rights": rights,
                "trustee_sid": trustee,
                "inherited": inherited,
            })
            pos += ace_size
    except Exception:
        pass
    return aces


# ═══════════════════════════════════════════════════════
#  SYSVOL SMB FUNKSIYALARI
# ═══════════════════════════════════════════════════════

def _smb_connect(ip: str, domain: str, username: str, password: str):
    """
    SMB connection qurur. impacket tələb olunur.
    NTLM hash destəyi: password 'LM:NT' formatinda olmalidir.

    FIX #1/#2: Əvvəl xeta yutulurdu ve None qayidirdi — indi
    (smb, error) tuple qaytarilir ki, çağiran kod neyin baş verdiyini bilsin.
    Returns: (SMBConnection | None, error_str | None)
    """
    if not HAS_IMPACKET:
        return None, "impacket not installed"
    try:
        lm_hash = ""
        nt_hash = ""
        plain_pass = password

        if is_ntlm_hash(password):
            lm_hash = "aad3b435b51404eeaad3b435b51404ee"
            nt_hash = password
            plain_pass = ""

        smb = SMBConnection(ip, ip, timeout=10)
        netbios = domain.split(".")[0].upper()

        if nt_hash:
            smb.login(username, "", domain=netbios, lmhash=lm_hash, nthash=nt_hash)
        else:
            smb.login(username, plain_pass, domain=netbios)
        return smb, None
    except Exception as e:
        return None, str(e)


def _probe_sysvol_access(smb, domain: str) -> bool:
    """Check whether the SYSVOL share is actually readable."""
    if not smb:
        return False
    try:
        smb.connectTree("SYSVOL")
        base = f"\\{domain}"
        entries = smb.listPath("SYSVOL", base + "\\*")
        return any(e.get_longname() not in (".", "..") for e in entries)
    except Exception:
        return False


def _smb_list_files(smb, share: str, path: str) -> list:
    """SMB share-dəki faylları siyahıya alır. Xəta halında boş list qaytarır."""
    try:
        entries = smb.listPath(share, path + "\\*")
        return [
            {
                "name": e.get_longname(),
                "is_dir": e.is_directory(),
                "size": e.get_filesize(),
            }
            for e in entries
            if e.get_longname() not in (".", "..")
        ]
    except Exception:
        return []


def _smb_read_file(smb, share: str, path: str, max_bytes: int = 512 * 1024) -> bytes:
    """SMB share-dən fayl məzmununu oxuyur. max_bytes limitini keçməz."""
    content = []
    total = 0

    def callback(data):
        nonlocal total
        if total < max_bytes:
            chunk = data[:max_bytes - total]
            content.append(chunk)
            total += len(chunk)

    try:
        smb.getFile(share, path, callback)
        return b"".join(content)
    except Exception:
        return b""


def _smb_get_acl(smb, share: str, path: str) -> list:
    """
    SYSVOL path-ının ACL-ini oxuyur (Security Descriptor).
    impacket SMBConnection.queryPathInfo + SEC_INFO_ALL istifadə edir.
    """
    acl_entries = []
    try:
        tid = smb.connectTree(share)
        fid = smb.openFile(
            tid, path,
            desiredAccess=0x00020000,  # READ_CONTROL
            shareMode=0x00000003,
        )
        # QuerySecurityInfo
        sd_data = smb.querySecurityInfo(tid, fid, 0x04)  # DACL_SECURITY_INFORMATION
        smb.closeFile(tid, fid)
        smb.disconnectTree(tid)
        if sd_data:
            aces = _parse_dacl_aces(sd_data)
            for ace in aces:
                acl_entries.append(ace)
    except Exception:
        pass
    return acl_entries


def _walk_sysvol(smb, share: str, base_path: str, max_depth: int = 6) -> list:
    """
    SYSVOL-u rekursiv gəzir, bütün fayl path-larını qaytarır.
    max_depth ilə sonsuz rekursiyanın qarşısı alınır.
    """
    results = []

    def _walk(path, depth):
        if depth > max_depth:
            return
        entries = _smb_list_files(smb, share, path)
        for e in entries:
            full = f"{path}\\{e['name']}"
            if e["is_dir"]:
                _walk(full, depth + 1)
            else:
                results.append({"path": full, "size": e["size"]})

    _walk(base_path, 0)
    return results


# ═══════════════════════════════════════════════════════
#  XML PARSE FUNKSIYALARI
# ═══════════════════════════════════════════════════════

def _safe_xml_parse(content: bytes):
    """XML məzmununu parse edir. Xəta halında None qaytarır."""
    try:
        return ET.fromstring(content.decode("utf-8", errors="replace"))
    except ET.ParseError:
        try:
            return ET.fromstring(content.decode("utf-16", errors="replace"))
        except Exception:
            return None
    except Exception:
        return None


def _parse_groups_xml(content: bytes) -> dict:
    """
    Groups.xml — Local Groups ve Users (her ikisi eyni faylda ola biler).
    cPassword tapilirsa decrypt edilir.
    FIX #9: <User> elementleri de parse edilir — kod yalniz <Group> ariyirdi.
    cPassword hem <Properties>-de, hem de <Member>-de ola biler (FIX #8).
    """
    result = {
        "type": "Groups",
        "groups": [],
        "users": [],
        "cpasswords_found": [],
        "restricted_groups": [],
    }
    root = _safe_xml_parse(content)
    if root is None:
        return result

    def _extract_cpasswords_from_props(props, context, name):
        """Properties ve Member elementlerinden cPassword-leri topla."""
        # <Properties cPassword="...">
        cp = props.get("cpassword", "") or props.get("cPassword", "")
        uname = props.get("userName", "") or props.get("username", "") or name
        if cp:
            result["cpasswords_found"].append({
                "context": context,
                "name": name,
                "username": uname,
                "cpassword": cp,
                "plaintext": _gpp_decrypt(cp),
            })
        # <Member cPassword="..."> (Groups.xml-de member sifreleri)
        for member in props.findall(".//Member"):
            m_cp = member.get("cpassword", "") or member.get("cPassword", "")
            if m_cp:
                m_name = member.get("name", "")
                result["cpasswords_found"].append({
                    "context": "GroupMember",
                    "name": name,
                    "username": m_name,
                    "cpassword": m_cp,
                    "plaintext": _gpp_decrypt(m_cp),
                })

    # <Group> elementleri
    for group in root.iter("Group"):
        props = group.find("Properties")
        if props is None:
            continue
        group_name = props.get("groupName", "") or props.get("name", "") or group.get("name", "")
        action = props.get("action", "")
        members = []
        for member in props.findall(".//Member"):
            members.append({
                "name":   member.get("name", ""),
                "sid":    member.get("sid", ""),
                "action": member.get("action", ""),
            })
        _extract_cpasswords_from_props(props, "Group", group_name)
        group_info = {"name": group_name, "action": action, "members": members}
        result["groups"].append(group_info)
        if group_name.lower() in ("administrators", "remote desktop users",
                                   "backup operators", "power users"):
            result["restricted_groups"].append(group_info)

    # <User> elementleri — local user yaratmaq/sifreni deyismek ucun
    for user_el in root.iter("User"):
        props = user_el.find("Properties")
        if props is None:
            continue
        user_name = props.get("userName", "") or props.get("name", "") or user_el.get("name", "")
        action = props.get("action", "")
        _extract_cpasswords_from_props(props, "LocalUser", user_name)
        result["users"].append({
            "name":        user_name,
            "action":      action,
            "full_name":   props.get("fullName", ""),
            "description": props.get("description", ""),
        })

    return result


def _parse_scheduledtasks_xml(content: bytes) -> dict:
    """
    ScheduledTasks.xml — Task name, command, RunAs user, cPassword.
    Immediate Tasks da eyni fayldan çıxarılır (ImmediateTask elementi).
    """
    result = {
        "type": "ScheduledTasks",
        "tasks": [],
        "immediate_tasks": [],
        "cpasswords_found": [],
    }
    root = _safe_xml_parse(content)
    if root is None:
        return result

    for tag, target_list in [("Task", result["tasks"]),
                               ("ImmediateTask", result["immediate_tasks"]),
                               ("ImmediateTaskV2", result["immediate_tasks"])]:
        for task in root.iter(tag):
            props = task.find("Properties")
            if props is None:
                continue

            name = props.get("name", task.get("name", ""))
            run_as = props.get("runAs", "")
            cpassword = props.get("cpassword", "") or props.get("cPassword", "")
            app_name = props.get("appName", "")
            args = props.get("args", "")
            enabled = props.get("enabled", "1")

            task_info = {
                "name": name,
                "run_as": run_as,
                "app_name": app_name,
                "args": args,
                "enabled": enabled == "1",
                "is_immediate": tag.startswith("Immediate"),
            }

            if cpassword:
                decrypted = _gpp_decrypt(cpassword)
                result["cpasswords_found"].append({
                    "context": "ScheduledTask",
                    "task_name": name,
                    "run_as": run_as,
                    "cpassword": cpassword,
                    "plaintext": decrypted,
                })
                task_info["cpassword"] = cpassword
                task_info["plaintext_password"] = decrypted

            target_list.append(task_info)

    return result


def _parse_drives_xml(content: bytes) -> dict:
    """
    Drives.xml — Drive Mappings (letter, path, label, cPassword).
    """
    result = {
        "type": "DriveMappings",
        "drives": [],
        "cpasswords_found": [],
    }
    root = _safe_xml_parse(content)
    if root is None:
        return result

    for drive in root.iter("Drive"):
        props = drive.find("Properties")
        if props is None:
            continue

        letter = props.get("letter", "")
        path = props.get("path", "")
        label = props.get("label", "")
        cpassword = props.get("cpassword", "") or props.get("cPassword", "")
        username_d = props.get("username", "")

        drive_info = {
            "letter": letter,
            "path": path,
            "label": label,
            "username": username_d,
        }

        if cpassword:
            decrypted = _gpp_decrypt(cpassword)
            result["cpasswords_found"].append({
                "context": "DriveMappings",
                "letter": letter,
                "path": path,
                "username": username_d,
                "cpassword": cpassword,
                "plaintext": decrypted,
            })
            drive_info["cpassword"] = cpassword
            drive_info["plaintext_password"] = decrypted

        result["drives"].append(drive_info)

    return result


def _parse_datasources_xml(content: bytes) -> dict:
    """DataSources.xml — ODBC DSN cPassword."""
    result = {"type": "DataSources", "sources": [], "cpasswords_found": []}
    root = _safe_xml_parse(content)
    if root is None:
        return result

    for ds in root.iter("DataSource"):
        props = ds.find("Properties")
        if props is None:
            continue
        name = props.get("dsn", "")
        cpassword = props.get("cpassword", "") or props.get("cPassword", "")
        username_ds = props.get("username", "")

        if cpassword:
            decrypted = _gpp_decrypt(cpassword)
            result["cpasswords_found"].append({
                "context": "DataSource",
                "dsn": name,
                "username": username_ds,
                "cpassword": cpassword,
                "plaintext": decrypted,
            })
        result["sources"].append({"dsn": name, "username": username_ds})
    return result


def _parse_printers_xml(content: bytes) -> dict:
    """Printers.xml — cPassword."""
    result = {"type": "Printers", "printers": [], "cpasswords_found": []}
    root = _safe_xml_parse(content)
    if root is None:
        return result

    for p in root.iter("Printer"):
        props = p.find("Properties")
        if props is None:
            continue
        name = props.get("name", "")
        cpassword = props.get("cpassword", "") or props.get("cPassword", "")
        username_p = props.get("username", "")

        if cpassword:
            decrypted = _gpp_decrypt(cpassword)
            result["cpasswords_found"].append({
                "context": "Printer",
                "name": name,
                "username": username_p,
                "cpassword": cpassword,
                "plaintext": decrypted,
            })
        result["printers"].append({"name": name})
    return result


def _parse_services_xml(content: bytes) -> dict:
    """Services.xml — Service runAs cPassword."""
    result = {"type": "Services", "services": [], "cpasswords_found": []}
    root = _safe_xml_parse(content)
    if root is None:
        return result

    for svc in root.iter("NTService"):
        props = svc.find("Properties")
        if props is None:
            continue
        name = props.get("serviceName", "")
        cpassword = props.get("cpassword", "") or props.get("cPassword", "")
        account = props.get("accountName", "")

        if cpassword:
            decrypted = _gpp_decrypt(cpassword)
            result["cpasswords_found"].append({
                "context": "Service",
                "service": name,
                "account": account,
                "cpassword": cpassword,
                "plaintext": decrypted,
            })
        result["services"].append({"name": name, "account": account})
    return result


def _parse_registry_xml(content: bytes) -> dict:
    """Registry.xml — Registry key/value settings."""
    result = {"type": "RegistrySettings", "entries": []}
    root = _safe_xml_parse(content)
    if root is None:
        return result

    for reg in root.iter("Registry"):
        props = reg.find("Properties")
        if props is None:
            continue
        result["entries"].append({
            "hive": props.get("hive", ""),
            "key": props.get("key", ""),
            "name": props.get("name", ""),
            "value": props.get("value", ""),
            "type": props.get("type", ""),
            "action": props.get("action", ""),
        })
    return result


def _parse_files_xml(content: bytes) -> dict:
    """Files.xml — File copy/script policies."""
    result = {"type": "Files", "files": []}
    root = _safe_xml_parse(content)
    if root is None:
        return result

    for f in root.iter("File"):
        props = f.find("Properties")
        if props is None:
            continue
        result["files"].append({
            "action": props.get("action", ""),
            "from_path": props.get("fromPath", ""),
            "target_path": props.get("targetPath", ""),
            "read_only": props.get("readOnly", ""),
            "archive": props.get("archive", ""),
            "hidden": props.get("hidden", ""),
        })
    return result


def _parse_shortcuts_xml(content: bytes) -> dict:
    """Shortcuts.xml — Shortcut targets."""
    result = {"type": "Shortcuts", "shortcuts": []}
    root = _safe_xml_parse(content)
    if root is None:
        return result

    for sc in root.iter("Shortcut"):
        props = sc.find("Properties")
        if props is None:
            continue
        result["shortcuts"].append({
            "name": props.get("name", ""),
            "target": props.get("targetPath", ""),
            "working_dir": props.get("startIn", ""),
            "args": props.get("arguments", ""),
        })
    return result


def _parse_software_xml(content: bytes) -> dict:
    """
    Software Installation — .msi/.msp paketlərinin path-ları.
    GPT.INI-dən deyil, Packages qovluğundan oxunur (ayrıca parse).
    """
    result = {"type": "SoftwareInstallation", "packages": []}
    root = _safe_xml_parse(content)
    if root is None:
        return result
    for pkg in root.iter("Package"):
        result["packages"].append({
            "name": pkg.get("name", ""),
            "path": pkg.get("path", ""),
            "action": pkg.get("action", ""),
        })
    return result


def _parse_gpt_ini(content: bytes) -> dict:
    """
    GPT.INI — GPO version nömrəsi (UserVersion, MachineVersion).
    Format: [General]\nVersion=NNNN
    """
    result = {"version": 0, "display_name": ""}
    try:
        text = content.decode("utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("version="):
                result["version"] = safe_int(line.split("=", 1)[1])
            elif line.lower().startswith("displayname="):
                result["display_name"] = line.split("=", 1)[1].strip()
    except Exception:
        pass
    return result


def _parse_scripts_ini(content: bytes, script_type: str) -> dict:
    """
    scripts.ini — Startup/Shutdown/Logon/Logoff skriptlər.
    Format: [Startup]\n0CmdLine=script.bat\n0Parameters=args
    """
    result = {"type": f"Scripts_{script_type}", "scripts": []}
    try:
        text = content.decode("utf-8", errors="replace")
        current_section = ""
        scripts = {}
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1]
            elif "=" in line and current_section:
                key, val = line.split("=", 1)
                # 0CmdLine, 0Parameters, 1CmdLine, ...
                m = re.match(r"(\d+)(CmdLine|Parameters)", key, re.IGNORECASE)
                if m:
                    idx = int(m.group(1))
                    field = m.group(2).lower()
                    scripts.setdefault(idx, {"section": current_section})[field] = val
        for idx in sorted(scripts):
            s = scripts[idx]
            result["scripts"].append({
                "index": idx,
                "section": s.get("section", ""),
                "cmdline": s.get("cmdline", ""),
                "parameters": s.get("parameters", ""),
            })
    except Exception:
        pass
    return result


def _parse_gptmpl_inf(content: bytes) -> dict:
    """
    GptTmpl.inf — Security Settings: Restricted Groups, Password Policy,
    Audit Policy, User Rights Assignment.
    """
    result = {
        "type": "SecuritySettings",
        "restricted_groups": [],
        "password_policy": {},
        "audit_policy": {},
        "user_rights": [],
        "registry_values": [],
    }
    try:
        text = content.decode("utf-8", errors="replace")
        current_section = ""
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].lower()
                continue

            if current_section == "group membership":
                # Format: *SID__Memberof = *SID veya GroupName__Members = user1,user2
                if "=" in line:
                    left, right = line.split("=", 1)
                    result["restricted_groups"].append({
                        "group": left.strip(),
                        "members": [m.strip() for m in right.split(",") if m.strip()],
                    })

            elif current_section == "system access":
                if "=" in line:
                    k, v = line.split("=", 1)
                    result["password_policy"][k.strip()] = v.strip()

            elif current_section == "audit policy":
                if "=" in line:
                    k, v = line.split("=", 1)
                    result["audit_policy"][k.strip()] = v.strip()

            elif current_section == "privilege rights":
                if "=" in line:
                    privilege, accounts = line.split("=", 1)
                    result["user_rights"].append({
                        "privilege": privilege.strip(),
                        "accounts": [a.strip() for a in accounts.split(",") if a.strip()],
                    })

            elif current_section == "registry values":
                if "=" in line:
                    result["registry_values"].append(line)

    except Exception:
        pass
    return result


# ═══════════════════════════════════════════════════════
#  LDAP YARDIMÇI FUNKSIYALAR
# ═══════════════════════════════════════════════════════

def _extract_domainsid(domain_dn: str, conn) -> str:
    try:
        conn.search(domain_dn, "(objectClass=domain)", attributes=["objectSid"])
        if conn.entries:
            sid_val = getattr(conn.entries[0], "objectSid", None)
            return str(getattr(sid_val, "value", "") or "")
    except Exception:
        pass
    return ""


def _is_gpo_enforced(gp_link_text: str, gpo_guid: str) -> bool:
    if not gp_link_text or not gpo_guid:
        return False
    pattern = re.compile(
        r'\[LDAP://[^\]]*' + re.escape(gpo_guid) + r'[^\]]*;(\d+)\]',
        re.IGNORECASE
    )
    for match in pattern.finditer(gp_link_text):
        flags = int(match.group(1))
        if flags & 2:
            return True
    return False


def _is_gpo_link_disabled(gp_link_text: str, gpo_guid: str) -> bool:
    """gPLink-dən bu GPO-nun link-inin disabled olub-olmadığını yoxlayır (flag & 1)."""
    if not gp_link_text or not gpo_guid:
        return False
    pattern = re.compile(
        r'\[LDAP://[^\]]*' + re.escape(gpo_guid) + r'[^\]]*;(\d+)\]',
        re.IGNORECASE
    )
    for match in pattern.finditer(gp_link_text):
        flags = int(match.group(1))
        if flags & 1:
            return True
    return False


def _parse_extension_guids(ext_str: str) -> list:
    """gPCUserExtensionNames / gPCMachineExtensionNames içindəki GUID-ləri parse edir."""
    if not ext_str:
        return []
    guids = re.findall(r'\{[0-9A-Fa-f\-]{36}\}', ext_str)
    result = []
    seen = set()
    for g in guids:
        gu = g.upper()
        if gu not in seen:
            seen.add(gu)
            result.append({
                "guid": gu,
                "name": EXTENSION_GUID_MAP.get(gu, "Unknown Extension"),
            })
    return result


def _resolve_sid_to_name(sid: str, conn, domain_dn: str) -> str:
    """
    SID-i LDAP-da axtarıb display name-ə çevirir.
    Məlum well-known SID-lər üçün birbaşa qaytarır.
    """
    WELL_KNOWN = {
        "S-1-1-0": "Everyone",
        "S-1-5-7": "Anonymous Logon",
        "S-1-5-11": "Authenticated Users",
        "S-1-5-18": "SYSTEM",
        "S-1-5-19": "LOCAL SERVICE",
        "S-1-5-20": "NETWORK SERVICE",
        "S-1-5-32-544": "BUILTIN\\Administrators",
        "S-1-5-32-545": "BUILTIN\\Users",
        "S-1-5-32-546": "BUILTIN\\Guests",
        "S-1-5-32-548": "BUILTIN\\Account Operators",
        "S-1-5-32-549": "BUILTIN\\Server Operators",
        "S-1-5-32-550": "BUILTIN\\Print Operators",
        "S-1-5-32-551": "BUILTIN\\Backup Operators",
        "S-1-5-32-552": "BUILTIN\\Replicators",
    }
    if sid in WELL_KNOWN:
        return WELL_KNOWN[sid]
    try:
        conn.search(
            domain_dn,
            f"(objectSid={sid})",
            attributes=["sAMAccountName", "name"],
            search_scope=SUBTREE
        )
        if conn.entries:
            e = conn.entries[0]
            sam = normalize_value(getattr(e, "sAMAccountName", None))
            name = normalize_value(getattr(e, "name", None))
            return sam or name or sid
    except Exception:
        pass
    return sid


# ═══════════════════════════════════════════════════════
#  SYSVOL GPO QOVLUĞUNU TAM TARA
# ═══════════════════════════════════════════════════════

def _enumerate_sysvol_gpo(smb, share: str, gpo_guid: str, domain: str,
                          gpc_fs_path: str = "") -> dict:
    """
    Bir GPO-nun SYSVOL qovluğunu tam tara:
    - GPT.INI
    - User\\  və Machine\\ altındakı bütün XML faylları
    - scripts.ini
    - GptTmpl.inf
    - Packages qovluğu (.msi/.msp)
    - SYSVOL ACL
    """
    # FIX #7: base path-i gPCFileSysPath-dan cixar
    # \\server\SysVol\domain\Policies\{guid} -> \domain\Policies\{guid}
    if gpc_fs_path:
        norm = gpc_fs_path.replace("/", "\\")
        parts = [p for p in norm.split("\\") if p]
        try:
            share_idx = next(i for i, p in enumerate(parts) if p.lower() == share.lower())
            base = "\\" + "\\".join(parts[share_idx + 1:])
        except StopIteration:
            base = f"\\{domain}\\Policies\\{{{gpo_guid}}}"
    else:
        base = f"\\{domain}\\Policies\\{{{gpo_guid}}}"
    sysvol_data = {
        "gpt_ini": {},
        "xml_files": [],
        "scripts": [],
        "security_settings": {},
        "software_packages": [],
        "all_files": [],
        "cpasswords_found": [],
        "sysvol_acl": [],
        "parse_errors": [],
    }

    # GPT.INI
    gpt_content = _smb_read_file(smb, share, base + "\\GPT.INI")
    if gpt_content:
        sysvol_data["gpt_ini"] = _parse_gpt_ini(gpt_content)

    # SYSVOL ACL
    sysvol_data["sysvol_acl"] = _smb_get_acl(smb, share, base)

    # Bütün faylları tap
    all_files = _walk_sysvol(smb, share, base)
    sysvol_data["all_files"] = [f["path"] for f in all_files]

    # XML fayl adlarına görə parse funksiyası seç
    XML_PARSERS = {
        "groups.xml": _parse_groups_xml,
        "scheduledtasks.xml": _parse_scheduledtasks_xml,
        "drives.xml": _parse_drives_xml,
        "datasources.xml": _parse_datasources_xml,
        "printers.xml": _parse_printers_xml,
        "services.xml": _parse_services_xml,
        "registry.xml": _parse_registry_xml,
        "files.xml": _parse_files_xml,
        "shortcuts.xml": _parse_shortcuts_xml,
        "software.xml": _parse_software_xml,
    }

    for file_info in all_files:
        fpath = file_info["path"]
        fname = fpath.split("\\")[-1].lower()

        # XML faylları
        if fname.endswith(".xml") and fname in XML_PARSERS:
            content = _smb_read_file(smb, share, fpath)
            if content:
                try:
                    parsed = XML_PARSERS[fname](content)
                    sysvol_data["xml_files"].append({
                        "path": fpath,
                        "data": parsed,
                    })
                    # cPassword topla
                    for cp in parsed.get("cpasswords_found", []):
                        sysvol_data["cpasswords_found"].append(cp)
                except Exception as ex:
                    sysvol_data["parse_errors"].append(
                        {"path": fpath, "error": str(ex)}
                    )
            continue

        # scripts.ini
        if fname == "scripts.ini":
            content = _smb_read_file(smb, share, fpath)
            if content:
                section = "Startup" if "machine" in fpath.lower() else "Logon"
                parsed = _parse_scripts_ini(content, section)
                sysvol_data["scripts"].append({
                    "path": fpath,
                    "data": parsed,
                })
            continue

        # GptTmpl.inf — Security Settings
        if fname == "gpttmpl.inf":
            content = _smb_read_file(smb, share, fpath)
            if content:
                sysvol_data["security_settings"] = _parse_gptmpl_inf(content)
            continue

        # .msi / .msp — Software Installation
        if fname.endswith((".msi", ".msp", ".mst")):
            sysvol_data["software_packages"].append({
                "path": fpath,
                "type": fname.split(".")[-1].upper(),
                "size": file_info.get("size", 0),
            })

    return sysvol_data


# ═══════════════════════════════════════════════════════
#  ANA FUNKSIYA: get_domain_gpos
# ═══════════════════════════════════════════════════════

def get_domain_gpos(ip, domain, username, password, config):
    """
    Active Directory-dən GPO-ları tam enumerate edir.

    Yoxlanan sahələr:
      1.  GPO Link (linked_containers, linked_count)
      2.  Scope of Management (user_version, computer_version, extensions)
      3.  Inheritance (inheritance_blocked OUs)
      4.  Enforcement (enforced flag, link_disabled)
      5.  Block Inheritance (gpOptions=1 olan container-lər)
      6.  GPP Passwords/cPassword (Groups, Tasks, Drives, Services...)
      7.  Scheduled Tasks – RunAs, cPassword
      8.  GPO Immediate Tasks
      9.  Restricted Groups (Groups.xml + GptTmpl.inf)
      10. Files & Scripts (Files.xml, scripts.ini)
      11. Registry Settings (Registry.xml)
      12. All .xml files (SYSVOL-da bütün XML-lər)
      13. GPP-decrypt (AES-256-CBC ilə avtomatik decrypt)
      14. Software Installation (Packages, .msi)
      16. Drive Mappings (Drives.xml)
      17. GPO Creator/Owner (nTSecurityDescriptor Owner SID)
      18. Description (description atributu)
      19. gPCFileSysPath
      20. SYSVOL ACL (DACL ACE-ləri)

    Args:
        ip: Domain Controller IP
        domain: Domain adı (məs. 'example.com')
        username: LDAP bind üçün istifadəçi adı
        password: Şifrə və ya NTLM hash (32 hex)
        config: LDAP_CONNECT_TIMEOUT və LDAP_RECEIVE_TIMEOUT olan konfiqurasiya

    Returns:
        dict: {
            'success': bool,
            'count': int,
            'sysvol_available': bool,
            'gpos': [ ... ],
            'all_cpasswords': [ ... ],   # Bütün GPO-lardakı cPassword-lər
            'inheritance_blocked': [ ... ], # gpOptions=1 olan container-lər
        }
    """
    if not all([ip, domain, username, password]):
        return {
            "success": False,
            "error": "Missing required parameters (ip, domain, username, password)",
            "count": 0,
            "gpos": [],
        }

    try:
        server = Server(ip, get_info=ALL, connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        bind_user = get_bind_user(username, domain)
        auth_type = "SIMPLE"
        smb_password = password

        if is_ntlm_hash(password):
            password = f"00000000000000000000000000000000:{password}"
            auth_type = "NTLM"

        domain_dn = "DC=" + ",DC=".join(domain.split("."))
        gpo_container = f"CN=Policies,CN=System,{domain_dn}"

        with Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=config.LDAP_RECEIVE_TIMEOUT,
        ) as conn:

            # ── 1. GPO-ları LDAP-dan çək ─────────────────────────────────
            conn.search(
                gpo_container,
                "(objectClass=groupPolicyContainer)",
                attributes=[
                    "name",
                    "displayName",
                    "description",           # 18. Description
                    "gPCFileSysPath",        # 19. gPCFileSysPath
                    "whenCreated",
                    "whenChanged",
                    "versionNumber",
                    "gPCUserExtensionNames",
                    "gPCMachineExtensionNames",
                    "flags",
                    "objectGUID",
                    "ntSecurityDescriptor",  # 17. Creator/Owner + 20. ACL
                    "managedBy",
                ],
            )

            # Preserve GPO search result before any other LDAP query rewrites conn.entries.
            gpo_entries = list(conn.entries)

            domainsid = _extract_domainsid(domain_dn, conn)
            gpos = []

            for entry in gpo_entries:
                def get_attr(a):
                    return getattr(entry, a, None)

                gpo_name     = normalize_value(get_attr("name"))
                gpo_guid_raw = normalize_value(get_attr("objectGUID"))
                # GUID-i {...} formatına normallaşdır
                gpo_guid = gpo_guid_raw.upper()
                if not gpo_guid.startswith("{"):
                    gpo_guid = "{" + gpo_guid + "}"

                user_ext     = normalize_value(get_attr("gPCUserExtensionNames"))
                machine_ext  = normalize_value(get_attr("gPCMachineExtensionNames"))
                managed_by   = normalize_value(get_attr("managedBy"))
                description  = normalize_value(get_attr("description"))      # 18
                gpc_fs_path  = normalize_value(get_attr("gPCFileSysPath"))   # 19
                version_num  = safe_int(get_attr("versionNumber"), 0)
                user_version     = (version_num >> 16) & 0xFFFF
                computer_version = version_num & 0xFFFF

                # ── Security Descriptor ──────────────────────────────────
                ntsd_attr = get_attr("ntSecurityDescriptor")
                ntsd_raw  = getattr(ntsd_attr, "value", None) if ntsd_attr else None
                if isinstance(ntsd_raw, (bytearray, memoryview)):
                    ntsd_raw = bytes(ntsd_raw)
                elif not isinstance(ntsd_raw, bytes):
                    ntsd_raw = b""

                isaclprotected = _parse_isaclprotected(ntsd_raw)
                owner_sid      = _parse_sd_owner(ntsd_raw)          # 17. Owner
                dacl_aces      = _parse_dacl_aces(ntsd_raw)         # 20. ACL

                # Owner SID-i LDAP-dan resolve et
                owner_name = _resolve_sid_to_name(owner_sid, conn, domain_dn) if owner_sid else ""

                # ── Extension GUID-lər ────────────────────────────────────
                user_extensions    = _parse_extension_guids(user_ext)
                machine_extensions = _parse_extension_guids(machine_ext)

                # ── Flags / GPO Status ─────────────────────────────────────
                # flags: 0=All enabled, 1=User disabled, 2=Computer disabled, 3=All disabled
                gpo_flags = safe_int(get_attr("flags"), 0)
                user_settings_disabled     = bool(gpo_flags & 1)
                computer_settings_disabled = bool(gpo_flags & 2)

                # ── highvalue ─────────────────────────────────────────────
                # FIX #5: gPLink GUID = CN (gpo_name), objectGUID (gpo_guid) deyil.
                # HIGH_VALUE_GUIDS-i gpo_name (CN) ilə müqayisə et.
                HIGH_VALUE_GUIDS = {
                    "{31B2F340-016D-11D2-945F-00C04FB984F9}",
                    "{6AC1786C-016F-11D2-945F-00C04FB984F9}",
                }
                cn_upper = gpo_name.upper()
                if not cn_upper.startswith("{"):
                    cn_upper = "{" + cn_upper + "}"
                settings_text = f"{user_ext} {machine_ext}".lower()
                has_settings_markers = any(
                    k in settings_text for k in ("script", "registry", "password")
                )
                highvalue = (
                    cn_upper in HIGH_VALUE_GUIDS
                    or has_settings_markers
                )

                gpo_info = {
                    # Əsas identifikasiya
                    "name":         gpo_name,
                    "guid":         gpo_guid,
                    "display_name": normalize_value(get_attr("displayName")) or gpo_name,
                    "description":  description,        # 18
                    "dn":           entry.entry_dn,
                    "path":         gpc_fs_path,        # 19
                    "domain":       domain,
                    "domainsid":    domainsid,

                    # Zaman damğaları
                    "created":  ldap_timestamp_to_iso(get_attr("whenCreated")),
                    "modified": ldap_timestamp_to_iso(get_attr("whenChanged")),

                    # Versiya
                    "version":          version_num,
                    "user_version":     user_version,
                    "computer_version": computer_version,

                    # Status flags
                    "flags":                      gpo_flags,
                    "user_settings_disabled":     user_settings_disabled,     # 2. Scope
                    "computer_settings_disabled": computer_settings_disabled,  # 2. Scope

                    # Link məlumatları (sonra doldurulur)
                    "linked_containers": [],  # 1. GPO Link
                    "linked_count":      0,
                    "enforced":          False,   # 4. Enforcement
                    "link_disabled":     False,   # 4. Enforcement
                    "isaclprotected":    isaclprotected,

                    # 17. Creator/Owner
                    "owner_sid":  owner_sid,
                    "owner_name": owner_name,

                    # 20. SYSVOL ACL (LDAP SD-dən)
                    "ldap_dacl_aces": dacl_aces,

                    # Extension-lər (2. Scope of Management)
                    "user_extensions":    user_extensions,
                    "machine_extensions": machine_extensions,

                    # highvalue
                    "highvalue": highvalue,

                    # SYSVOL məlumatları (SMB-dən sonra doldurulur)
                    "sysvol": {},

                    # Yığılmış risk qeydləri
                    "risk_controls": [],
                }

                gpos.append(gpo_info)

            # ── 2. gPLink-dən Link + Enforcement + Inheritance ────────────
            # Hər container-ın gPLink-i oxunur
            conn.search(
                domain_dn,
                "(gPLink=*)",
                attributes=["distinguishedName", "gPLink", "gPOptions"],
                search_scope=SUBTREE,
            )

            guid_pattern  = re.compile(r'\{([0-9A-Fa-f\-]{36})\}')
            link_map      = {}
            link_text_map = {}
            # 5. Block Inheritance: gpOptions=1 olan container-lər
            # FIX #3: gPLink=* filtri yalnız link-i olan container-ları qaytarır.
            # gPOptions=1 olan amma gPLink-i olmayan OU-lar qaçırılır.
            # Buna görə inheritance_blocked-ı ayrıca sorğu ilə doldururuq (aşağıda).
            inheritance_blocked = []

            for entry in conn.entries:
                container_dn = entry.entry_dn
                gp_link  = normalize_value(getattr(entry, "gPLink",   None))
                gp_opts  = safe_int(getattr(entry, "gPOptions", None), 0)

                # gPLink-i olan container-larda da gpOptions=1 ola bilər — onları da yaz
                if gp_opts & 1:
                    inheritance_blocked.append(container_dn)

                if not gp_link:
                    continue

                text = str(gp_link)
                for guid in guid_pattern.findall(text):
                    gu = "{" + guid.upper() + "}"
                    link_map.setdefault(gu, []).append(container_dn)
                    link_text_map.setdefault(gu, []).append(text)

            # FIX #3 (davam): gPLink-i olmayan amma gpOptions=1 olan bütün container-ları tap
            # Bunlar: OU-lar, domain kökü — istənilən gpOptions=1 olan obyekt
            conn.search(
                domain_dn,
                "(&(gpOptions=1)(!(gPLink=*)))",
                attributes=["distinguishedName"],
                search_scope=SUBTREE,
            )
            for entry in conn.entries:
                dn = entry.entry_dn
                if dn not in inheritance_blocked:
                    inheritance_blocked.append(dn)

            # ── 3. Inheritance — OU-ların inherit/block vəziyyəti ─────────
            # Bütün OU-ları çəkib gpOptions yoxla
            conn.search(
                domain_dn,
                "(objectClass=organizationalUnit)",
                attributes=["distinguishedName", "gPOptions"],
                search_scope=SUBTREE,
            )
            ou_inheritance = []
            for entry in conn.entries:
                gp_opts = safe_int(getattr(entry, "gPOptions", None), 0)
                ou_inheritance.append({
                    "dn":               entry.entry_dn,
                    "block_inheritance": bool(gp_opts & 1),
                })

            # ── GPO-lara Link + Enforcement məlumatlarını yaz ─────────────
            # FIX #4: gPLink-dəki GUID CN-dəki GUID-dir (objectGUID deyil).
            # Buna görə link_map-i "name" (CN) ilə yoxlamalıyıq.
            for gpo in gpos:
                # gpo["name"] = CN, yəni {31B2F340-...} — gPLink-dəki GUID ilə uyğundur
                cn_guid = gpo["name"].upper()
                if not cn_guid.startswith("{"):
                    cn_guid = "{" + cn_guid + "}"

                containers = link_map.get(cn_guid, [])
                gpo["linked_containers"] = containers
                gpo["linked_count"]      = len(containers)

                texts = link_text_map.get(cn_guid, [])
                gpo["enforced"]      = any(_is_gpo_enforced(t, cn_guid) for t in texts)
                gpo["link_disabled"] = any(_is_gpo_link_disabled(t, cn_guid) for t in texts)

                # Risk qeydləri
                rc = gpo["risk_controls"]
                if gpo["highvalue"]:
                    rc.append("High Value Target")
                if gpo["enforced"]:
                    rc.append("Enforced")
                if gpo["isaclprotected"]:
                    rc.append("ACL Inheritance Blocked")
                if gpo["user_settings_disabled"]:
                    rc.append("User Settings Disabled")
                if gpo["computer_settings_disabled"]:
                    rc.append("Computer Settings Disabled")

        # ── SMB / SYSVOL tara ────────────────────────────────────────────
        # FIX #1: _smb_connect indi (smb, error) tuple qaytarır
        smb, smb_error = _smb_connect(ip, domain, bind_user.split("\\")[-1], smb_password)
        sysvol_available = _probe_sysvol_access(smb, domain)

        all_cpasswords = []

        if smb:
            # FIX #1/#2: GPO CN adından (name) GUID-i götür, objectGUID deyil
            for gpo in gpos:
                # gpo["name"] = CN = SYSVOL-dakı qovluq adı, məs. {31B2F340-...}
                cn_raw = gpo["name"].strip("{}")
                try:
                    sv = _enumerate_sysvol_gpo(smb, "SYSVOL", cn_raw, domain,
                                                       gpc_fs_path=gpo.get("path", ""))
                    gpo["sysvol"] = sv

                    # cPassword-ləri qlobal siyahıya əlavə et
                    for cp in sv.get("cpasswords_found", []):
                        cp["gpo_name"] = gpo["display_name"]
                        cp["gpo_guid"] = gpo["name"]  # CN GUID (SYSVOL ilə uyğun)
                        all_cpasswords.append(cp)

                    # Risk qeydlərini yenilə
                    rc = gpo["risk_controls"]
                    if sv.get("cpasswords_found"):
                        rc.append("GPP cPassword Found")
                    if sv.get("scripts"):
                        rc.append("Scripts Configured")
                    if sv.get("security_settings", {}).get("restricted_groups"):
                        rc.append("Restricted Groups Defined")
                    if sv.get("software_packages"):
                        rc.append("Software Installation Configured")

                except Exception as ex:
                    gpo["sysvol"] = {"error": str(ex)}
            smb.logoff()
        else:
            # FIX #1/#2: SMB bağlantısı uğursuz olduqda səbəbi hər GPO-ya yaz
            for gpo in gpos:
                gpo["sysvol"] = {
                    "error": f"SMB connection failed: {smb_error}",
                    "gpt_ini": {}, "xml_files": [], "scripts": [],
                    "security_settings": {}, "software_packages": [],
                    "all_files": [], "cpasswords_found": [],
                    "sysvol_acl": [], "parse_errors": [],
                }

        import json as _json
        result = {
            "success":             True,
            "count":               len(gpos),
            "sysvol_available":    sysvol_available,
            "gpos":                gpos,
            "all_cpasswords":      all_cpasswords,
            "inheritance_blocked": inheritance_blocked,
            "ou_inheritance":      ou_inheritance,
        }

        # ── domain_gpos.jsonl-a yaz ──────────────────────────────────────────
        try:
            output_path = os.path.join(
                str(config.DOMAIN_OBJECT_DIR), "domain_gpos.jsonl"
            )
            with open(output_path, "w", encoding="utf-8") as f:
                # Meta sətir: success, count, sysvol_available
                meta = {
                    "success":          result["success"],
                    "count":            result["count"],
                    "sysvol_available": result["sysvol_available"],
                }
                f.write(_json.dumps(meta, ensure_ascii=False, default=str) + "\n")
                # Hər GPO ayrı sətirdə
                for gpo in result["gpos"]:
                    f.write(_json.dumps(gpo, ensure_ascii=False, default=str) + "\n")
                # all_cpasswords — tək sətir (ayrıca axtarış üçün)
                if result["all_cpasswords"]:
                    cp_line = {"all_cpasswords": result["all_cpasswords"]}
                    f.write(_json.dumps(cp_line, ensure_ascii=False, default=str) + "\n")
                # inheritance_blocked + ou_inheritance — tək sətir
                inh_line = {
                    "inheritance_blocked": result["inheritance_blocked"],
                    "ou_inheritance":      result["ou_inheritance"],
                }
                f.write(_json.dumps(inh_line, ensure_ascii=False, default=str) + "\n")
        except Exception as write_exc:
            result["json_export_error"] = str(write_exc)

        return result

    except LDAPException as e:
        return {"success": False, "error": f"LDAP error: {e}", "count": 0, "gpos": []}
    except Exception as e:
        return {"success": False, "error": f"Error: {e}", "count": 0, "gpos": []}


# ═══════════════════════════════════════════════════════
#  get_gpo_scope  (köhnə API ilə uyğunluq)
# ═══════════════════════════════════════════════════════

def get_gpo_scope(ip, gpo_guid, domain, username, password, config):
    """
    GPO-nun linked olduğu container-ları qaytarır.
    get_domain_gpos ilə eyni NTLM hash dəstəyi.
    """
    if not all([ip, gpo_guid, domain, username, password]):
        return []
    try:
        server   = Server(ip, get_info=ALL, connect_timeout=config.LDAP_CONNECT_TIMEOUT)
        domain_dn = "DC=" + ",DC=".join(domain.split("."))
        bind_user = get_bind_user(username, domain)
        auth_type = "SIMPLE"

        if is_ntlm_hash(password):
            password  = f"00000000000000000000000000000000:{password}"
            auth_type = "NTLM"

        with Connection(
            server,
            user=bind_user,
            password=password,
            authentication=auth_type,
            auto_bind=True,
            receive_timeout=config.LDAP_RECEIVE_TIMEOUT,
        ) as conn:
            conn.search(
                domain_dn,
                f"(gPLink=*{gpo_guid}*)",
                attributes=["dn"],
                search_scope=SUBTREE,
            )
            return [e.entry_dn for e in conn.entries]
    except Exception:
        return []