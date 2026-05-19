#!/usr/bin/env python3
"""
OXS Cert - AD CS Certificate Template Enumeration Tool
Usage: python3 template_enumeration.py -u USER -p PASS -dc-ip 10.10.10.10

Requires: pip install ldap3 pycryptodome

This module ONLY enumerates and collects data — no ESC analysis.
ESC analysis is handled by dedicated modules (esc1.py, esc2.py, etc.)
"""

import argparse
import json
import os
import sys
import uuid
import struct
from datetime import datetime, timezone

# ── MD4 monkey-patch ──────────────────────────────────────────────────────────

def _patch_md4():
    import hashlib
    try:
        hashlib.new("md4", b"test")
        return True
    except ValueError:
        pass
    try:
        from Crypto.Hash import MD4 as _CryptoMD4

        class _MD4Wrapper:
            name = "md4"
            digest_size = 16
            block_size  = 64

            def __init__(self, data=b""):
                self._h = _CryptoMD4.new()
                if data:
                    self._h.update(data)

            def update(self, data):
                self._h.update(data)
                return self

            def digest(self):    return self._h.digest()
            def hexdigest(self): return self._h.hexdigest()

            def copy(self):
                import copy
                n = _MD4Wrapper()
                n._h = copy.copy(self._h)
                return n

        _orig_new = hashlib.new

        def _patched_new(name, *args, **kwargs):
            if name.lower() == "md4":
                data = args[0] if args else kwargs.get("data", b"")
                return _MD4Wrapper(data)
            kwargs.pop("usedforsecurity", None)
            return _orig_new(name, *args, **kwargs)

        hashlib.new = _patched_new
        return True
    except ImportError:
        return False


_md4_ok = _patch_md4()
if not _md4_ok:
    print("[!] MD4 fix failed. Run: pip install pycryptodome")
    sys.exit(1)

try:
    from ldap3 import Server, Connection, ALL, NONE as LDAP_NONE, NTLM, SUBTREE, SYNC
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    print("[!] ldap3 not found. Run: pip install ldap3")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_VERSION = "2.0.0"

TEMPLATE_ATTRIBUTES = [
    # ── Identity & metadata ───────────────────────────────────────────────────
    "objectClass",
    "cn",
    "distinguishedName",
    "instanceType",
    "whenCreated",
    "whenChanged",
    "uSNCreated",
    "uSNChanged",
    "showInAdvancedViewOnly",
    "name",
    "displayName",
    "objectGUID",
    "objectCategory",
    "dSCorePropagationData",
    "flags",
    "revision",
    "nTSecurityDescriptor",
    # ── Core PKI attributes ───────────────────────────────────────────────────
    "pKIDefaultKeySpec",
    "pKIKeyUsage",
    "pKIMaxIssuingDepth",
    "pKICriticalExtensions",
    "pKIExpirationPeriod",
    "pKIOverlapPeriod",
    "pKIExtendedKeyUsage",
    "pKIDefaultCSPs",
    # ── msPKI-* attributes ────────────────────────────────────────────────────
    "msPKI-Key-Usage",
    "msPKI-RA-Signature",           # ESC1/ESC2/ESC3: must be 0
    "msPKI-Enrollment-Flag",        # ESC1/ESC2/ESC3/ESC6/ESC7/ESC9: various bits
    "msPKI-Private-Key-Flag",
    "msPKI-Certificate-Name-Flag",  # ESC1/ESC9: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
    "msPKI-Minimal-Key-Size",
    "msPKI-Subject-Name",           # ESC1/ESC9: subject name supply flags
    "msPKI-OID-Localizedname",      # ESC13: OID localised name
    "msPKI-Template-Schema-Version",# ESC15: schema version 1 check
    "msPKI-Template-Minor-Revision",
    "msPKI-Cert-Template-OID",      # ESC9/ESC13/ESC15: template OID
    "msPKI-Certificate-Application-Policy",  # ESC15: app policy vs EKU mismatch
    "msPKI-RA-Application-Policies",         # ESC3: agent template RA policies
    "msPKI-Supersede-Templates",
    "msPKI-RA-Auth-Descriptor",
    "msPKI-Auto-Enrollment-Flag",
    "msPKI-RA-Policies",
    "msPKI-Asymmetric-Key-Usage",
    "msPKI-Site-Enrollment-Servers",
    # ── Additional attributes for ESC9/ESC10 ─────────────────────────────────
    "altSecurityIdentities",        # ESC10: weak certificate mapping
]

# ── PKI infrastructure object enumeration ────────────────────────────────────
#
# These objects govern CA behaviour. Their ACL data is collected here and
# passed to the report. ESC5 analysis is performed by esc5.py.
#
# Each entry: (friendly_label, DN_template, scope)
#   DN_template uses {config_nc} as a placeholder.
#   scope: "BASE" = single object, "ONE" = one level (direct children only).
ESC5_PKI_OBJECT_BASES = [
    (
        "Enrollment Services",
        "CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}",
        "ONE",
    ),
    (
        "NTAuthCertificates",
        "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{config_nc}",
        "BASE",
    ),
    (
        "Certification Authorities",
        "CN=Certification Authorities,CN=Public Key Services,CN=Services,{config_nc}",
        "ONE",
    ),
    (
        "AIA",
        "CN=AIA,CN=Public Key Services,CN=Services,{config_nc}",
        "ONE",
    ),
    (
        "CDP",
        "CN=CDP,CN=Public Key Services,CN=Services,{config_nc}",
        "ONE",
    ),
]

# Attributes fetched for every PKI infrastructure object.
# nTSecurityDescriptor is mandatory (DACL parsing); the rest provide context.
PKI_OBJECT_ATTRIBUTES = [
    # ── Identity & metadata ───────────────────────────────────────────────────
    "objectClass",
    "cn",
    "distinguishedName",
    "instanceType",
    "whenCreated",
    "whenChanged",
    "uSNCreated",
    "uSNChanged",
    "showInAdvancedViewOnly",
    "name",
    "displayName",
    "objectGUID",
    "objectCategory",
    "dSCorePropagationData",
    "nTSecurityDescriptor",     # ESC5/ESC7: DACL ACE analysis
    # ── CA-specific attributes ────────────────────────────────────────────────
    "flags",                    # ESC6: CA flags
    "revision",
    "cACertificate",            # NTAuthCertificates / Certification Authorities
    "cACertificateDN",          # CA certificate subject DN
    "certificateTemplates",     # ESC8: published template list
    "certificateMessages",
    "dNSHostName",              # ESC8: CA host for HTTP probe URL construction
    "pKIExpirationPeriod",
    "pKIOverlapPeriod",
]

# Write rights collected on PKI objects — used by esc5.py for analysis.
ESC5_WRITE_RIGHTS = {
    "GenericAll",
    "GenericWrite",
    "WriteProperty",
    "WriteDACL",
    "WriteOwner",
}

# Well-known privileged SIDs — used only to filter PKI object ACL data
# collected by enumerate_pki_objects(). ESC analysis is done in esc5.py.
ESC5_ADMIN_SIDS = {
    "S-1-5-32-544",   # BUILTIN\Administrators
    "S-1-5-18",       # SYSTEM
}
ESC5_ADMIN_SID_SUFFIXES = [
    "-512",   # Domain Admins
    "-519",   # Enterprise Admins
    "-516",   # Domain Controllers
]


SUBJECT_NAME_FLAGS = {
    0x00000001: "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT",
    0x00010000: "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
    0x00400000: "CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
    0x00800000: "CT_FLAG_SUBJECT_ALT_REQUIRE_SPN",
    0x01000000: "CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
    0x02000000: "CT_FLAG_SUBJECT_ALT_REQUIRE_UPN",
    0x04000000: "CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL",
    0x08000000: "CT_FLAG_SUBJECT_ALT_REQUIRE_DNS",
    0x10000000: "CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN",
    0x20000000: "CT_FLAG_SUBJECT_REQUIRE_EMAIL",
    0x40000000: "CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME",
    0x80000000: "CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH",
}

PRIVATE_KEY_FLAGS = {
    0x00000010: "CTPRIVATEKEY_FLAG_EXPORTABLE_KEY",
    0x00000020: "CTPRIVATEKEY_FLAG_STRONG_KEY_PROTECTION_REQUIRED",
    0x00000040: "CTPRIVATEKEY_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM",
    0x00000080: "CTPRIVATEKEY_FLAG_REQUIRE_SAME_KEY_RENEWAL",
    0x00000100: "CTPRIVATEKEY_FLAG_USE_LEGACY_PROVIDER",
    0x00002000: "CTPRIVATEKEY_FLAG_EK_TRUST_ON_USE",
    0x00004000: "CTPRIVATEKEY_FLAG_EK_VALIDATE_CERT",
    0x00008000: "CTPRIVATEKEY_FLAG_EK_VALIDATE_KEY",
    0x00200000: "CTPRIVATEKEY_FLAG_ATTEST_PREFERRED",
    0x00400000: "CTPRIVATEKEY_FLAG_ATTEST_REQUIRED",
    0x00800000: "CTPRIVATEKEY_FLAG_ATTESTATION_WITHOUT_POLICY",
    0x01000000: "CTPRIVATEKEY_FLAG_EK_NONE",
}

ENROLLMENT_FLAGS = {
    0x00000001: "CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS",
    0x00000002: "CT_FLAG_PEND_ALL_REQUESTS",
    0x00000004: "CT_FLAG_PUBLISH_TO_KRA_CONTAINER",
    0x00000008: "CT_FLAG_PUBLISH_TO_DS",
    0x00000010: "CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE",
    0x00000020: "CT_FLAG_AUTO_ENROLLMENT",
    0x00000040: "CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT",
    0x00000100: "CT_FLAG_USER_INTERACTION_REQUIRED",
    0x00000400: "CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE",
    0x00000800: "CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF",    # ESC3: agent enroll-on-behalf
    0x00001000: "CT_FLAG_ADD_OCSP_NOCHECK",
    0x00002000: "CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL",
    0x00004000: "CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS",
    0x00008000: "CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS",
    0x00010000: "CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT",
    0x00020000: "CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST",
    0x00040000: "CT_FLAG_SKIP_AUTO_RENEWAL",
    0x00080000: "CT_FLAG_NO_SECURITY_EXTENSION",        # ESC9: no szOID_NTDS_CA_SECURITY_EXT
}

GENERAL_FLAGS = {
    0x00000020: "CT_FLAG_AUTO_ENROLLMENT",
    0x00000040: "CT_FLAG_MACHINE_TYPE",
    0x00000080: "CT_FLAG_IS_CA",
    0x00000200: "CT_FLAG_ADD_TEMPLATE_NAME",
    0x00000800: "CT_FLAG_DONOTPERSISTINDB",
    0x00001000: "CT_FLAG_IS_DEFAULT",
    0x00020000: "CT_FLAG_IS_MODIFIED",
}

EKU_MAP = {
    "1.3.6.1.5.5.7.3.1":       "Server Authentication",
    "1.3.6.1.5.5.7.3.2":       "Client Authentication",
    "1.3.6.1.5.5.7.3.3":       "Code Signing",
    "1.3.6.1.5.5.7.3.4":       "Email Protection",
    "1.3.6.1.5.5.7.3.8":       "Timestamp Signing",
    "1.3.6.1.5.5.7.3.9":       "OCSP Signing",
    "1.3.6.1.4.1.311.20.2.1":  "Certificate Request Agent",
    "1.3.6.1.4.1.311.20.2.2":  "Smart Card Logon",
    "1.3.6.1.4.1.311.10.3.1":  "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.4":  "EFS",
    "1.3.6.1.4.1.311.10.3.4.1":"EFS Recovery",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.21.5":    "CA Encryption Certificate",
    "1.3.6.1.4.1.311.21.6":    "Key Recovery Agent",
    "1.3.6.1.5.2.3.5":         "Kerberos PKINIT",
    "2.5.29.37.0":              "Any Purpose",
}

# ── Banner & args ─────────────────────────────────────────────────────────────

def banner(quiet=False):
    if quiet:
        print(f"[*] OXS CERT - AD CS Certificate Template Enumerator v{TOOL_VERSION}")
        return
    try:
        print(r"""
  ██████╗ ██╗  ██╗███████╗     ██████╗███████╗██████╗ ████████╗
 ██╔═══██╗╚██╗██╔╝██╔════╝    ██╔════╝██╔════╝██╔══██╗╚══██╔══╝
 ██║   ██║ ╚███╔╝ ███████╗    ██║     █████╗  ██████╔╝   ██║   
 ██║   ██║ ██╔██╗ ╚════██║    ██║     ██╔══╝  ██╔══██╗   ██║   
 ╚██████╔╝██╔╝ ██╗███████║    ╚██████╗███████╗██║  ██║   ██║   
  ╚═════╝ ╚═╝  ╚═╝╚══════╝     ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝  
  AD CS Certificate Template Enumerator  v{ver}
  ---------------------------------------------------------
""".format(ver=TOOL_VERSION))
    except UnicodeEncodeError:
        print(f"OXS CERT - AD CS Certificate Template Enumerator v{TOOL_VERSION}")


def parse_args():
    p = argparse.ArgumentParser(
        description="OXS Cert - AD CS Certificate Template Enumeration Tool",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    a = p.add_argument_group("Authentication")
    a.add_argument("-u", "--user",     metavar="USER",     help="Username (DOMAIN\\user or user@domain)")
    a.add_argument("-p", "--password", metavar="PASSWORD", help="Plaintext password")
    a.add_argument("-H", "--hash",     metavar="HASH",     help="NTLM hash (:NT or LM:NT)")

    t = p.add_argument_group("Target")
    t.add_argument("-dc-ip",  metavar="DC_IP",  required=True, help="Domain Controller IP")
    t.add_argument("-ns-ip",  metavar="NS_IP",  help="Name Server IP (optional)")
    t.add_argument("-ca-ip",  metavar="CA_IP",  help="Certificate Authority IP (optional)")
    t.add_argument("-domain", metavar="DOMAIN", help="Domain FQDN (auto-detected if omitted)")

    o = p.add_argument_group("Output")
    o.add_argument("-o", "--output",  metavar="FILE",      help="Output JSON file path")
    o.add_argument("-v", "--verbose", action="store_true", help="Verbose per-template output")
    o.add_argument("-q", "--quiet",   action="store_true", help="Suppress banner and box-drawing characters")

    return p.parse_args()

# ── LDAP helpers ──────────────────────────────────────────────────────────────

def _first(v):
    return v[0] if isinstance(v, (list, tuple)) else v


def get_naming_contexts(dc_ip):
    srv  = Server(dc_ip, get_info=ALL, connect_timeout=10)
    conn = Connection(srv, client_strategy=SYNC, raise_exceptions=False)
    conn.open()
    conn.bind()

    default_nc = config_nc = None

    if srv.info and srv.info.other:
        default_nc = _first(srv.info.other.get("defaultNamingContext"))
        config_nc  = _first(srv.info.other.get("configurationNamingContext"))

    if not default_nc or not config_nc:
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["defaultNamingContext", "configurationNamingContext"],
        )
        if conn.entries:
            e = conn.entries[0]
            if not default_nc:
                try: default_nc = str(e["defaultNamingContext"].value)
                except Exception: pass
            if not config_nc:
                try: config_nc = str(e["configurationNamingContext"].value)
                except Exception: pass

    try: conn.unbind()
    except Exception: pass

    return default_nc, config_nc


def dn_to_domain(dn):
    if not dn:
        return None
    parts = [c.strip()[3:] for c in dn.split(",") if c.strip().upper().startswith("DC=")]
    return ".".join(parts).lower() if parts else None


def build_ntlm_user(user, domain):
    if "\\" in user:
        return user
    if "@" in user:
        username, fqdn = user.split("@", 1)
        return f"{fqdn.split('.')[0].upper()}\\{username}"
    if domain:
        return f"{domain.split('.')[0].upper()}\\{user}"
    return user


def connect_ldap(dc_ip, user, password=None, ntlm_hash=None, domain=None):
    # LDAP_NONE disables schema download so ldap3 never validates attribute
    # names — required for hyphenated msPKI-* attrs (e.g. msPKI-Key-Usage).
    srv = Server(dc_ip, get_info=LDAP_NONE, connect_timeout=10)
    ntlm_user = build_ntlm_user(user, domain)

    if ntlm_hash:
        if ":" not in ntlm_hash:
            ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"
        auth_pw = ntlm_hash
    else:
        auth_pw = password

    return Connection(
        srv,
        user=ntlm_user,
        password=auth_pw,
        authentication=NTLM,
        auto_bind=True,
        raise_exceptions=True,
        client_strategy=SYNC,
        check_names=False,      # Allow hyphenated msPKI-* attribute names
    )

# ── Data helpers ──────────────────────────────────────────────────────────────

def decode_bitmask(value, flag_map):
    try:
        val = int(value)
    except (TypeError, ValueError):
        return []
    return [name for bit, name in flag_map.items() if val & bit]


def format_guid(raw):
    try:
        if isinstance(raw, bytes) and len(raw) == 16:
            return "{" + str(uuid.UUID(bytes_le=raw)).upper() + "}"
    except Exception:
        pass
    return str(raw)


def safe_val(val):
    if val is None:
        return None
    if isinstance(val, bytes):
        try:    return val.decode("utf-8")
        except: return val.hex()
    if isinstance(val, list):
        return [safe_val(v) for v in val]
    return str(val)


def parse_acl(sd_hex):
    """
    Parse nTSecurityDescriptor hex and extract ACEs relevant to enrollment
    AND template/PKI object modification.

    Returns list of {sid, mask, type, rights, right, object_type} dicts.

    Enrollment rights:
      Enroll     — RIGHT_DS_CONTROL_ACCESS (0x100) with Enroll GUID
                   0e10c968-78fb-11d2-90d4-00c04f79dc55
      AutoEnroll — RIGHT_DS_CONTROL_ACCESS (0x100) with AutoEnroll GUID
                   a05b8cc2-8c38-4802-a710-e7c15ab866a2

    Write rights (collected raw, analysed by ESC modules):
      GenericAll    — 0x000F01FF
      GenericWrite  — 0x40000000
      WriteProperty — 0x00000020
      WriteDACL     — 0x00040000
      WriteOwner    — 0x00080000
    """
    import uuid as _uuid

    # Extended right GUIDs (bytes_le / COM mixed-endian as stored in SD)
    ENROLL_GUID     = _uuid.UUID("0e10c968-78fb-11d2-90d4-00c04f79dc55").bytes_le
    AUTOENROLL_GUID = _uuid.UUID("a05b8cc2-8c38-4802-a710-e7c15ab866a2").bytes_le

    # Access mask constants
    _GENERIC_ALL      = 0x10000000  # maps to full control on DS objects
    _GENERIC_ALL_DS   = 0x000F01FF  # concrete DS object full-control mask
    _GENERIC_WRITE    = 0x40000000
    _WRITE_PROPERTY   = 0x00000020  # ADS_RIGHT_DS_WRITE_PROP
    _WRITE_DACL       = 0x00040000  # ADS_RIGHT_WRITE_DAC
    _WRITE_OWNER      = 0x00080000  # ADS_RIGHT_WRITE_OWNER
    _DS_CONTROL_ACCESS = 0x00000100 # ADS_RIGHT_DS_CONTROL_ACCESS (extended rights)

    aces = []
    try:
        sd = bytes.fromhex(sd_hex)

        # DACL offset at byte 16 (little-endian DWORD)
        dacl_offset = struct.unpack_from("<I", sd, 16)[0]
        if dacl_offset == 0:
            return aces

        # ACE count at dacl_offset+4
        ace_count = struct.unpack_from("<H", sd, dacl_offset + 4)[0]
        pos = dacl_offset + 8

        for _ in range(ace_count):
            if pos + 4 > len(sd):
                break
            ace_type = sd[pos]
            ace_size = struct.unpack_from("<H", sd, pos + 2)[0]
            ace_data = sd[pos:pos + ace_size]
            pos += ace_size

            if ace_size < 8:
                continue

            # Access mask
            mask = struct.unpack_from("<I", ace_data, 4)[0]

            # Resolve SID offset and optional object GUID for object ACE types
            obj_guid = b""
            if ace_type in (0x05, 0x06):  # ACCESS_ALLOWED_OBJECT_ACE / ACCESS_DENIED_OBJECT_ACE
                flags = struct.unpack_from("<I", ace_data, 8)[0]
                g_pos = 12
                if flags & 0x1:           # ACE_OBJECT_TYPE_PRESENT
                    obj_guid = ace_data[g_pos:g_pos + 16]
                    g_pos += 16
                if flags & 0x2:           # ACE_INHERITED_OBJECT_TYPE_PRESENT
                    g_pos += 16
                sid_offset = g_pos
            else:
                sid_offset = 8

            # Parse SID
            try:
                sid_str = _parse_sid(ace_data[sid_offset:])
            except Exception:
                sid_str = "unknown"

            is_allow = ace_type in (0x00, 0x05)
            rights = []

            # ── Enrollment rights (object ACEs with specific GUIDs or no GUID) ──
            if mask & _DS_CONTROL_ACCESS:
                if obj_guid == ENROLL_GUID or obj_guid == b"":
                    rights.append("Enroll")
                if obj_guid == AUTOENROLL_GUID or obj_guid == b"":
                    if "AutoEnroll" not in rights:
                        rights.append("AutoEnroll")

            # ── Write rights (GenericAll, GenericWrite, WriteProperty, WriteDACL, WriteOwner) ──
            # GenericAll implies everything; check concrete DS mask too.
            if mask & _GENERIC_ALL or (mask & _GENERIC_ALL_DS) == _GENERIC_ALL_DS:
                rights.append("GenericAll")
            else:
                # Only append finer-grained rights when GenericAll is absent to
                # avoid redundant entries — GenericAll already implies them all.
                if mask & _GENERIC_WRITE:
                    rights.append("GenericWrite")
                if mask & _WRITE_PROPERTY:
                    rights.append("WriteProperty")
                if mask & _WRITE_DACL:
                    rights.append("WriteDACL")
                if mask & _WRITE_OWNER:
                    rights.append("WriteOwner")

            if not rights:
                continue  # ACE carries no right relevant to enrollment or modification

            aces.append({
                "sid":    sid_str,
                "mask":   hex(mask),
                "type":   "Allow" if is_allow else "Deny",
                "rights": rights,
                # Legacy single-string field for backwards compatibility.
                "right":  rights[0] if rights else hex(mask),
                # Object-type GUID for scoped WriteProperty ACEs (hex string,
                # empty string = ACE applies to ALL properties).
                "object_type": obj_guid.hex() if obj_guid else "",
            })

    except Exception:
        pass

    return aces


def _parse_sid(data):
    if len(data) < 8:
        return "invalid"
    rev       = data[0]
    sub_count = data[1]
    authority = int.from_bytes(data[2:8], "big")
    subs      = [struct.unpack_from("<I", data, 8 + i * 4)[0] for i in range(sub_count)]
    return "S-{}-{}-{}".format(rev, authority, "-".join(str(s) for s in subs))


def parse_filetime(hex_str):
    """Convert Windows FILETIME (8-byte little-endian hex) to human-readable."""
    try:
        raw = bytes.fromhex(hex_str)
        val = struct.unpack("<q", raw)[0]
        if val == 0:
            return "0"
        # Negative = relative time
        if val < 0:
            val = -val
            seconds = val / 10_000_000
            days    = int(seconds // 86400)
            hours   = int((seconds % 86400) // 3600)
            weeks   = days // 7
            rem_days = days % 7
            parts = []
            if weeks:   parts.append(f"{weeks}w")
            if rem_days: parts.append(f"{rem_days}d")
            if hours:   parts.append(f"{hours}h")
            return " ".join(parts) if parts else "0"
        return str(val)
    except Exception:
        return hex_str

# ── ESC5 PKI object enumeration ───────────────────────────────────────────────

def _is_admin_sid(sid):
    """Return True if the SID belongs to a well-known privileged principal."""
    if sid in ESC5_ADMIN_SIDS:
        return True
    return any(sid.endswith(sfx) for sfx in ESC5_ADMIN_SID_SUFFIXES)


def enumerate_pki_objects(conn, config_nc, verbose=False):
    """Enumerate PKI infrastructure objects and collect their raw ACL data.

    For each object defined in ESC5_PKI_OBJECT_BASES, performs an LDAP search
    and parses the nTSecurityDescriptor DACL into ACE records.
    ESC analysis (e.g. ESC5) is performed by the dedicated esc5.py module.

    Returns a list of dicts, one per discovered object:
      {
        "category"               : str   — friendly label (e.g. "Enrollment Services")
        "dn"                     : str   — distinguished name
        "cn"                     : str   — common name
        "object_class"           : list  — objectClass values
        "certificate_templates"  : list  — published templates (Enrollment Services)
        "dns_host_name"          : str   — CA hostname (Enrollment Services)
        "acl_aces"               : list  — all parsed ACEs
      }
    """
    results = []

    for label, dn_tmpl, scope_str in ESC5_PKI_OBJECT_BASES:
        base_dn = dn_tmpl.format(config_nc=config_nc)
        ldap_scope = SUBTREE if scope_str == "ONE" else "BASE"

        # For ONE-level searches we want direct children of the container,
        # not the container itself.  ldap3 SUBTREE would recurse too deep;
        # use a one-level search via the search_scope argument.
        from ldap3 import BASE as LDAP_BASE, LEVEL as LDAP_LEVEL
        scope_arg = LDAP_LEVEL if scope_str == "ONE" else LDAP_BASE

        try:
            ok = conn.search(
                search_base=base_dn,
                search_filter="(objectClass=*)",
                search_scope=scope_arg,
                attributes=PKI_OBJECT_ATTRIBUTES,
                get_operational_attributes=False,
                controls=security_descriptor_control(sdflags=0x04),
            )
        except Exception as exc:
            if verbose:
                print(f"    [!] {label}: search error -- {exc}")
            continue

        if not ok:
            if verbose:
                print(f"    [!] {label}: LDAP search failed -- {conn.result}")
            continue

        for entry in conn.entries:
            dn = str(entry.entry_dn)

            def _attr(name, default=None):
                try:
                    val = entry[name].value
                    return val if val is not None else default
                except Exception:
                    return default

            cn           = _attr("cn", "")
            object_class = _attr("objectClass") or []
            if isinstance(object_class, str):
                object_class = [object_class]

            cert_templates = _attr("certificateTemplates") or []
            if isinstance(cert_templates, str):
                cert_templates = [cert_templates]

            dns_host = _attr("dNSHostName", "")

            # Parse DACL
            sd_raw = _attr("nTSecurityDescriptor")
            if isinstance(sd_raw, bytes):
                sd_hex = sd_raw.hex()
            elif isinstance(sd_raw, str):
                sd_hex = sd_raw
            else:
                sd_hex = None

            acl_aces = parse_acl(sd_hex) if sd_hex else []

            obj = {
                "category":                label,
                "dn":                      dn,
                "cn":                      str(cn) if cn else "",
                "object_class":            [str(c) for c in object_class],
                "certificate_templates":   [str(t) for t in cert_templates],
                "dns_host_name":           str(dns_host) if dns_host else "",
                "acl_aces":                acl_aces,
                # ── Extended metadata (full Enrollment Services attribute set) ──
                "display_name":   str(_attr("displayName", "")),
                "object_guid":    format_guid(_attr("objectGUID")) if _attr("objectGUID") else "",
                "flags":          _attr("flags"),
                "revision":       _attr("revision"),
                "ca_certificate": safe_val(_attr("cACertificate")),
                "ca_certificate_dn": str(_attr("cACertificateDN", "")),
                "certificate_messages": safe_val(_attr("certificateMessages")),
                "pki_expiration_period": parse_filetime(safe_val(_attr("pKIExpirationPeriod"))) if _attr("pKIExpirationPeriod") else "",
                "pki_overlap_period":    parse_filetime(safe_val(_attr("pKIOverlapPeriod")))    if _attr("pKIOverlapPeriod")    else "",
                "when_created":   str(_attr("whenCreated", "")),
                "when_changed":   str(_attr("whenChanged", "")),
            }
            results.append(obj)

            name_str = str(cn) if cn else dn
            if verbose:
                print(f"    [+] [{label}] {name_str}")
            else:
                print(f"  [+] [{label}] {name_str}")

    return results


# ── Certificate template enumeration ──────────────────────────────────────────

def enumerate_templates(conn, config_nc, verbose=False):
    templates_base = (
        f"CN=Certificate Templates,"
        f"CN=Public Key Services,"
        f"CN=Services,"
        f"{config_nc}"
    )
    print(f"[*] Search base : {templates_base}\n")

    ok = conn.search(
        search_base=templates_base,
        search_filter="(objectClass=pKICertificateTemplate)",
        search_scope=SUBTREE,
        attributes=TEMPLATE_ATTRIBUTES,
        get_operational_attributes=False,
        # SD_FLAGS control (sdflags=0x04) requests only the DACL portion of
        # nTSecurityDescriptor. Without this control, Active Directory returns
        # the attribute as empty/null for non-privileged callers because the
        # full SD (including SACL) is protected. DACL is sufficient for ACL parsing.
        controls=security_descriptor_control(sdflags=0x04),
    )

    if not ok:
        print(f"[!] LDAP search failed: {conn.result}")
        return []

    results = []
    for entry in conn.entries:
        raw = {}
        for attr in TEMPLATE_ATTRIBUTES:
            try:
                val = entry[attr].value
            except Exception:
                val = None

            if attr == "objectGUID" and isinstance(val, bytes):
                val = format_guid(val)
            elif attr == "nTSecurityDescriptor" and isinstance(val, bytes):
                val = val.hex()

            raw[attr] = safe_val(val)

        parsed = {}

        def _dec(attr_name, flag_map, key):
            v = raw.get(attr_name)
            if v is not None:
                try:
                    parsed[f"{key}_value"]   = int(v)
                    parsed[f"{key}_decoded"] = decode_bitmask(v, flag_map)
                except (TypeError, ValueError):
                    pass

        _dec("msPKI-Certificate-Name-Flag", SUBJECT_NAME_FLAGS, "subject_name_flags")
        _dec("msPKI-Private-Key-Flag",      PRIVATE_KEY_FLAGS,  "private_key_flags")
        _dec("msPKI-Enrollment-Flag",        ENROLLMENT_FLAGS,   "enrollment_flags")
        _dec("flags",                        GENERAL_FLAGS,      "general_flags")

        # msPKI-RA-Signature — integer value surfaced for ESC module use.
        ra_sig_raw = raw.get("msPKI-RA-Signature")
        try:
            parsed["ra_signature"] = int(ra_sig_raw) if ra_sig_raw is not None else None
        except (TypeError, ValueError):
            parsed["ra_signature"] = None

        # msPKI-Template-Schema-Version — ESC15: schema version 1 check
        schema_ver_raw = raw.get("msPKI-Template-Schema-Version")
        try:
            parsed["schema_version"] = int(schema_ver_raw) if schema_ver_raw is not None else None
        except (TypeError, ValueError):
            parsed["schema_version"] = None

        # ESC9: CT_FLAG_NO_SECURITY_EXTENSION (0x00080000) in msPKI-Enrollment-Flag
        enroll_flag_raw = raw.get("msPKI-Enrollment-Flag")
        try:
            ef_int = int(enroll_flag_raw) if enroll_flag_raw is not None else 0
            parsed["no_security_extension"] = bool(ef_int & 0x00080000)   # ESC9
            parsed["manager_approval_required"] = bool(ef_int & 0x00000002)  # CT_FLAG_PEND_ALL_REQUESTS
            parsed["allow_enroll_on_behalf_of"] = bool(ef_int & 0x00000800)  # ESC3 agent template
        except (TypeError, ValueError):
            parsed["no_security_extension"]      = None
            parsed["manager_approval_required"]  = None
            parsed["allow_enroll_on_behalf_of"]  = None

        # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001) in msPKI-Certificate-Name-Flag — ESC1/ESC9
        cert_name_flag_raw = raw.get("msPKI-Certificate-Name-Flag")
        try:
            cnf_int = int(cert_name_flag_raw) if cert_name_flag_raw is not None else 0
            parsed["enrollee_supplies_subject"] = bool(cnf_int & 0x00000001)  # ESC1/ESC9
        except (TypeError, ValueError):
            parsed["enrollee_supplies_subject"] = None

        # EKU
        ekus_raw = raw.get("pKIExtendedKeyUsage") or []
        if isinstance(ekus_raw, str): ekus_raw = [ekus_raw]
        parsed["eku_friendly"] = [
            {"oid": o, "name": EKU_MAP.get(o, "Unknown")} for o in ekus_raw
        ]

        # Empty EKU is as permissive as Any Purpose (2.5.29.37.0).
        parsed["eku_is_empty"]       = len(parsed["eku_friendly"]) == 0
        parsed["eku_is_any_purpose"] = any(
            e["oid"] == "2.5.29.37.0" for e in parsed["eku_friendly"]
        )

        # Application policies
        app_pol = raw.get("msPKI-Certificate-Application-Policy") or []
        if isinstance(app_pol, str): app_pol = [app_pol]
        parsed["application_policies_friendly"] = [
            {"oid": o, "name": EKU_MAP.get(o, "Unknown")} for o in app_pol
        ]

        # When msPKI-Certificate-Application-Policy and pKIExtendedKeyUsage differ,
        # the CA uses Application Policy. Both sets are surfaced for ESC modules.
        app_oids = {e["oid"] for e in parsed["application_policies_friendly"]}
        eku_oids  = {e["oid"] for e in parsed["eku_friendly"]}
        parsed["app_policy_any_purpose"]  = "2.5.29.37.0" in app_oids
        parsed["app_policy_eku_mismatch"] = app_oids != eku_oids

        # msPKI-RA-Application-Policies — surfaced for ESC3 pair-matching.
        # empty  -> any enrollment agent cert is accepted
        # OID(s) -> agent cert must carry those specific EKUs
        RA_REQUEST_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"
        ra_app_raw = raw.get("msPKI-RA-Application-Policies") or []
        if isinstance(ra_app_raw, str):
            ra_app_raw = [ra_app_raw]
        parsed["ra_app_policies_friendly"] = [
            {"oid": o, "name": EKU_MAP.get(o, "Unknown")} for o in ra_app_raw
        ]
        parsed["ra_app_policies_is_empty"] = len(ra_app_raw) == 0
        parsed["ra_app_policies_requires_request_agent"] = (
            RA_REQUEST_AGENT_OID in ra_app_raw or len(ra_app_raw) == 0
        )

        # Validity / renewal periods
        exp = raw.get("pKIExpirationPeriod")
        ovl = raw.get("pKIOverlapPeriod")
        parsed["validity_period"]  = parse_filetime(exp) if exp else "unknown"
        parsed["renewal_period"]   = parse_filetime(ovl) if ovl else "unknown"

        # General flags
        flags_val = raw.get("flags")
        if flags_val:
            try:
                fv = int(flags_val)
                parsed["is_machine_type"] = bool(fv & 0x40)
                parsed["is_ca"]           = bool(fv & 0x80)
            except (TypeError, ValueError):
                parsed["is_machine_type"] = None
                parsed["is_ca"]           = None

        # ACL — parse all ACEs from the security descriptor.
        # ESC1/ESC2/ESC3 consumers use acl_enrollment_aces for enroll-right checks.
        # ESC4 consumers use the full rights list and object_type field.
        sd_hex = raw.get("nTSecurityDescriptor")
        acl_aces = parse_acl(sd_hex) if sd_hex else []

        parsed["acl_enrollment_aces"] = acl_aces

        template = {
            "dn":     str(entry.entry_dn),
            "raw":    raw,
            "parsed": parsed,
        }
        results.append(template)

        name = raw.get("cn") or raw.get("displayName") or "?"
        if verbose:
            print(f"    [+] {name}")
        else:
            print(f"  [+] {name}")

    return results

# ── RPC / ICertAdminD2 CA property enumeration ───────────────────────────────
#
# These properties are NOT available via LDAP — they live in the CA's registry
# and are exposed only through the MS-CSRA RPC interface (ICertAdminD2).
#
# Relevant ESC mappings:
#   EditFlags  bit 0x00040000 (EDITF_ATTRIBUTESUBJECTALTNAME2) → ESC6
#   InterfaceFlags / RequestDisposition                        → ESC7 context
#
# impacket >= 0.11 ships a DCE/RPC client for MS-CSRA.  We use it when
# available and fall back to a "not_collected" stub when it is absent so the
# rest of the tool continues to work without the dependency.

def _rpc_get_ca_int_property(dce, ca_name, prop_id):
    """
    Call ICertAdminD2::GetCAProperty for a single integer property.

    prop_id constants (from [MS-CSRA] section 3.1.4.1.4):
      CR_PROP_EDITFLAGS        = 0x0004
      CR_PROP_CATYPE           = 0x0006  (0=Enterprise Root, 1=Enterprise Sub,
                                          2=Standalone Root, 3=Standalone Sub)
      CR_PROP_CAXCHGCOUNT      = 0x0008
      CR_PROP_CASIGCOUNT       = 0x000B
      CR_PROP_REQUESTDISPOSITION= 0x0012
      CR_PROP_INTERFACEFLAGS   = 0x001C

    Returns integer value or None on failure.
    """
    from impacket.dcerpc.v5 import csra as _csra
    try:
        req = _csra.GetCAProperty()
        req["pwszAuthority"] = ca_name + "\x00"
        req["PropId"]        = prop_id
        req["PropIndex"]     = 0
        req["PropType"]      = 1  # PROPTYPE_LONG
        resp = dce.request(req)
        return resp["pctbPropertyValue"]["pb"][0] | \
               (resp["pctbPropertyValue"]["pb"][1] << 8) | \
               (resp["pctbPropertyValue"]["pb"][2] << 16) | \
               (resp["pctbPropertyValue"]["pb"][3] << 24)
    except Exception:
        return None


def _rpc_get_ca_str_property(dce, ca_name, prop_id, prop_index=0):
    """
    Call ICertAdminD2::GetCAProperty for a single string property.

    Useful prop_ids:
      CR_PROP_SANITIZEDCANAME   = 0x0001
      CR_PROP_PRODUCTVERSION    = 0x0002
      CR_PROP_COMMONNAME        = 0x000D
      CR_PROP_CASIGCERTDN       = 0x000E  (signing cert DN)
    """
    from impacket.dcerpc.v5 import csra as _csra
    try:
        req = _csra.GetCAProperty()
        req["pwszAuthority"] = ca_name + "\x00"
        req["PropId"]        = prop_id
        req["PropIndex"]     = prop_index
        req["PropType"]      = 4  # PROPTYPE_STRING
        resp = dce.request(req)
        raw = bytes(resp["pctbPropertyValue"]["pb"])
        return raw.decode("utf-16-le").rstrip("\x00")
    except Exception:
        return None


# Bitmask tables for decoded output
_EDITFLAGS_MAP = {
    0x00000001: "EDITF_REQUESTEXTENSIONS",
    0x00000002: "EDITF_DISABLEEXTENSIONS",
    0x00000020: "EDITF_ADDOLDKEYUSAGE",
    0x00000040: "EDITF_ADDOLDCERTTYPE",
    0x00000100: "EDITF_ATTRIBUTEEKU",
    0x00000200: "EDITF_ENABLEAKEREQUIRED",
    0x00010000: "EDITF_ENABLEOCSPREVNOCHECK",
    0x00040000: "EDITF_ATTRIBUTESUBJECTALTNAME2",   # ESC6 flag
    0x00100000: "EDITF_ATTRIBUTESUBJECTALTNAME",
    0x00200000: "EDITF_SERVERUPGRADED",
}

_CATYPE_MAP = {
    0: "Enterprise Root CA",
    1: "Enterprise Subordinate CA",
    2: "Standalone Root CA",
    3: "Standalone Subordinate CA",
}

_INTERFACEFLAGS_MAP = {
    0x00000001: "IF_LOCKICERTREQUEST",
    0x00000002: "IF_NOREMOTEICERTREQUEST",
    0x00000004: "IF_NOLOCERICERTREQUEST",
    0x00000008: "IF_NORPCICERTREQUEST",
    0x00000200: "IF_ENFORCEENCRYPTICERTREQUEST",    # ESC11: must be SET; if 0 → vulnerable
    0x00000400: "IF_ENFORCEENCRYPTICERTADMIN",
}

# CA Security Descriptor access rights (MS-CSRA 3.1.1.7)
_CA_ACCESS_RIGHTS_MAP = {
    0x00000001: "CA_ACCESS_ADMIN",          # ESC7: ManageCA
    0x00000002: "CA_ACCESS_OFFICER",        # ESC7: ManageCertificates (approve/deny)
    0x00000004: "CA_ACCESS_AUDITOR",
    0x00000008: "CA_ACCESS_OPERATOR",
    0x00000010: "CA_ACCESS_READ",
    0x00000020: "CA_ACCESS_ENROLL",
    0x00000100: "CA_ACCESS_LOCALADMIN",
}

# CertificateMappingMethods bits (HKLM\...\Kdc\CertificateMappingMethods)
_CERT_MAPPING_METHODS_MAP = {
    0x0001: "SUBJECT_ALTNAME_MAPPING",      # SAN UPN mapping
    0x0002: "ISSUER_SUBJECT_MAPPING",
    0x0004: "UPN_MAPPING",                  # ESC10-A: UPN bit
    0x0008: "S4U2SELF_MAPPING",
    0x0010: "EXPLICIT_MAPPING",
}


def _rpc_get_ca_security_descriptor(dce, ca_name):
    """
    Fetch CA Security Descriptor via CR_PROP_CASECURITYDESCRIPTOR (0x0016).
    Returns raw bytes or None.

    ESC7 analysis:
      CA_ACCESS_ADMIN   (0x00000001) → ManageCA  right
      CA_ACCESS_OFFICER (0x00000002) → ManageCertificates right
    If either of these is held by a low-privileged principal → ESC7 vulnerable.
    """
    from impacket.dcerpc.v5 import csra as _csra
    try:
        req = _csra.GetCAProperty()
        req["pwszAuthority"] = ca_name + "\x00"
        req["PropId"]        = 0x0016   # CR_PROP_CASECURITYDESCRIPTOR
        req["PropIndex"]     = 0
        req["PropType"]      = 3        # PROPTYPE_BINARY
        resp = dce.request(req)
        return bytes(resp["pctbPropertyValue"]["pb"])
    except Exception:
        return None


def _parse_ca_security_descriptor(sd_bytes):
    """
    Parse CA Security Descriptor binary and return list of ACE dicts:
      {sid, access_mask, rights_decoded, type}

    Used by ESC7 analysis: any ACE granting CA_ACCESS_ADMIN or
    CA_ACCESS_OFFICER to a non-admin SID is a finding.
    """
    if not sd_bytes:
        return []
    aces = []
    try:
        sd_hex = sd_bytes.hex()
        raw_aces = parse_acl(sd_hex)
        # Augment with CA-specific rights decoding
        for ace in raw_aces:
            try:
                mask = int(ace.get("mask", "0x0"), 16)
            except ValueError:
                mask = 0
            ca_rights = [
                name for bit, name in _CA_ACCESS_RIGHTS_MAP.items() if mask & bit
            ]
            ace["ca_rights"] = ca_rights
            aces.append(ace)
    except Exception:
        pass
    return aces


def _rpc_get_ca_registry_value(dce, ca_name, value_name):
    """
    Read a CA registry value via ICertAdminD2::BackupGetAttachmentInformation
    or via GetCAProperty with a vendor-specific prop.

    NOTE: Direct registry reads over RPC are only possible through
    ICertAdminD2 on the CA host itself (not a general-purpose registry
    read). This helper attempts to surface registry-backed CA properties
    that MS-CSRA exposes as named properties.

    Returns string value or None.
    """
    from impacket.dcerpc.v5 import csra as _csra
    # MS-CSRA does not expose StrongCertificateBindingEnforcement or
    # CertificateMappingMethods as standard GetCAProperty prop IDs.
    # These live in HKLM\SYSTEM\...\Kdc\ on the DC, not on the CA.
    # Returning None signals caller to fall back to OS-inference.
    return None


def enumerate_ca_rpc(ca_host, ca_name, username, password=None,
                     ntlm_hash=None, domain=None, verbose=False):
    """
    Connect to a CA over MS-CSRA (ncacn_ip_tcp, port 135 → dynamic endpoint)
    and collect properties that are unavailable via LDAP:

      EditFlags        — raw integer + decoded flag list (ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2)
      CAType           — Enterprise/Standalone Root/Subordinate
      ProductVersion   — CA software version string
      InterfaceFlags   — RPC interface restrictions (ESC11: IF_ENFORCEENCRYPTICERTREQUEST)
      SigningCertDN    — CA signing certificate subject DN
      CASigCount       — number of CA signing certificates
      CAXchgCount      — number of CA exchange certificates
      CA Security Descriptor ACEs — ESC7: CA_ACCESS_ADMIN / CA_ACCESS_OFFICER on low-priv SIDs
      ESC11 flag       — IF_ENFORCEENCRYPTICERTREQUEST (0x00000200) absent → vulnerable

    Returns a dict. On import failure (impacket not installed) or
    connection failure the dict carries source="not_collected" and a
    manual_check_command so downstream ESC modules can surface a hint.

    Authentication mirrors the LDAP layer: NTLM password or pass-the-hash.
    """
    _NOT_COLLECTED = {
        "source":               "not_collected",
        "ca_host":              ca_host,
        "ca_name":              ca_name,
        # ── ESC6 ──────────────────────────────────────────────────────────────
        "edit_flags_raw":       None,
        "edit_flags_decoded":   [],
        "esc6_vulnerable":      None,
        # ── ESC7 ──────────────────────────────────────────────────────────────
        "ca_security_aces":     [],         # parsed CA SD ACEs with ca_rights
        "esc7_manage_ca_sids":  [],         # SIDs holding CA_ACCESS_ADMIN
        "esc7_officer_sids":    [],         # SIDs holding CA_ACCESS_OFFICER
        # ── ESC11 ─────────────────────────────────────────────────────────────
        "interface_flags_raw":     None,
        "interface_flags_decoded": [],
        "esc11_vulnerable":        None,    # True if IF_ENFORCEENCRYPTICERTREQUEST absent
        # ── General CA info ───────────────────────────────────────────────────
        "ca_type_raw":          None,
        "ca_type_label":        "",
        "product_version":      "",
        "signing_cert_dn":      "",
        "ca_sig_count":         None,
        "ca_xchg_count":        None,
        "manual_check_command": (
            f'certutil -config "{ca_host}\\{ca_name}" -getreg policy\\EditFlags'
        ),
        "error":                "",
    }

    # ── dependency check ──
    try:
        from impacket.dcerpc.v5 import transport, epm, csra as _csra
        from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        from impacket import ntlm as _ntlm
    except ImportError:
        result = dict(_NOT_COLLECTED)
        result["source"] = "impacket_not_installed"
        result["error"]  = (
            "impacket is required for RPC enumeration. "
            "Run: pip install impacket"
        )
        if verbose:
            print(f"  [!] RPC: impacket not installed — skipping CA property fetch")
        return result

    result = dict(_NOT_COLLECTED)
    result["source"] = "rpc"

    try:
        # ── build NTLM credentials ──
        lm_hash  = ""
        nt_hash  = ""
        if ntlm_hash:
            if ":" in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(":", 1)
            else:
                lm_hash, nt_hash = "aad3b435b51404eeaad3b435b51404ee", ntlm_hash
        ntlm_domain   = (domain or "").split(".")[0].upper()
        ntlm_username = username.split("\\")[-1].split("@")[0]

        # ── endpoint mapper → dynamic port ──
        string_binding = f"ncacn_ip_tcp:{ca_host}[135]"
        trans = transport.DCERPCTransportFactory(string_binding)
        trans.set_credentials(ntlm_username, password or "", ntlm_domain,
                              lm_hash, nt_hash)
        trans.set_connect_timeout(10)

        dce_epm = trans.get_dce_rpc()
        dce_epm.connect()
        dce_epm.bind(epm.MSRPC_UUID_PORTMAP)
        endpoint = epm.hept_map(ca_host, _csra.MSRPC_UUID_ICERTADMIN2,
                                protocol="ncacn_ip_tcp", dce=dce_epm)
        dce_epm.disconnect()

        # ── connect to ICertAdminD2 ──
        trans2 = transport.DCERPCTransportFactory(endpoint)
        trans2.set_credentials(ntlm_username, password or "", ntlm_domain,
                               lm_hash, nt_hash)
        trans2.set_connect_timeout(10)
        dce = trans2.get_dce_rpc()
        dce.set_auth_type(RPC_C_AUTHN_WINNT)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(_csra.MSRPC_UUID_ICERTADMIN2)

        if verbose:
            print(f"  [+] RPC connected to {ca_host} — fetching CA properties ...")

        # ── CR_PROP_EDITFLAGS = 0x0004 (ESC6) ─────────────────────────────────
        edit_flags = _rpc_get_ca_int_property(dce, ca_name, 0x0004)
        result["edit_flags_raw"] = edit_flags
        if edit_flags is not None:
            result["edit_flags_decoded"] = [
                name for bit, name in _EDITFLAGS_MAP.items() if edit_flags & bit
            ]
            result["esc6_vulnerable"] = bool(edit_flags & 0x00040000)

        # ── CR_PROP_CATYPE = 0x0006 ────────────────────────────────────────────
        ca_type = _rpc_get_ca_int_property(dce, ca_name, 0x0006)
        result["ca_type_raw"]   = ca_type
        result["ca_type_label"] = _CATYPE_MAP.get(ca_type, str(ca_type)) if ca_type is not None else ""

        # ── CR_PROP_PRODUCTVERSION = 0x0002 ───────────────────────────────────
        result["product_version"] = _rpc_get_ca_str_property(dce, ca_name, 0x0002) or ""

        # ── CR_PROP_INTERFACEFLAGS = 0x001C (ESC11) ───────────────────────────
        iface_flags = _rpc_get_ca_int_property(dce, ca_name, 0x001C)
        result["interface_flags_raw"] = iface_flags
        if iface_flags is not None:
            result["interface_flags_decoded"] = [
                name for bit, name in _INTERFACEFLAGS_MAP.items() if iface_flags & bit
            ]
            # ESC11: IF_ENFORCEENCRYPTICERTREQUEST (0x00000200) must be SET.
            # If it is absent → CA accepts unencrypted RPC requests → NTLM relay possible.
            result["esc11_vulnerable"] = not bool(iface_flags & 0x00000200)

        # ── CR_PROP_CASECURITYDESCRIPTOR = 0x0016 (ESC7) ──────────────────────
        ca_sd_bytes = _rpc_get_ca_security_descriptor(dce, ca_name)
        ca_sd_aces  = _parse_ca_security_descriptor(ca_sd_bytes)
        result["ca_security_aces"] = ca_sd_aces

        # Extract SIDs that hold ManageCA or ManageCertificates — ESC7 consumers
        # will cross-reference these against low-privileged principal lists.
        manage_ca_sids  = []
        officer_sids    = []
        for ace in ca_sd_aces:
            if ace.get("type") != "Allow":
                continue
            ca_rights = ace.get("ca_rights", [])
            sid = ace.get("sid", "")
            if "CA_ACCESS_ADMIN" in ca_rights:
                manage_ca_sids.append(sid)
            if "CA_ACCESS_OFFICER" in ca_rights:
                officer_sids.append(sid)
        result["esc7_manage_ca_sids"] = manage_ca_sids
        result["esc7_officer_sids"]   = officer_sids

        # ── CR_PROP_CASIGCERTDN = 0x000E ──────────────────────────────────────
        result["signing_cert_dn"] = _rpc_get_ca_str_property(dce, ca_name, 0x000E, 0) or ""

        # ── CR_PROP_CASIGCOUNT = 0x000B ───────────────────────────────────────
        result["ca_sig_count"] = _rpc_get_ca_int_property(dce, ca_name, 0x000B)

        # ── CR_PROP_CAXCHGCOUNT = 0x0008 ──────────────────────────────────────
        result["ca_xchg_count"] = _rpc_get_ca_int_property(dce, ca_name, 0x0008)

        dce.disconnect()

    except Exception as exc:
        result["source"] = "rpc_error"
        result["error"]  = str(exc)
        if verbose:
            print(f"  [!] RPC error for {ca_host}\\{ca_name}: {exc}")

    return result


def probe_esc8_http(ca_host, ca_name=None, timeout=10, verbose=False):
    """
    ESC8: Probe the CA Web Enrollment endpoint for NTLM authentication.

    Checks:
      1. http://<ca_host>/certsrv/ returns HTTP 200 or 401
      2. WWW-Authenticate header contains 'NTLM'
      3. HTTPS redirect is NOT enforced (plaintext NTLM relay possible)

    Returns dict:
      {
        "ca_host"          : str,
        "url"              : str,
        "http_status"      : int or None,
        "ntlm_auth_present": bool,
        "https_enforced"   : bool,
        "esc8_vulnerable"  : bool,   # True if HTTP+NTLM and no HTTPS enforcement
        "error"            : str,
      }
    """
    import urllib.request
    import urllib.error
    import ssl

    url = f"http://{ca_host}/certsrv/"
    result = {
        "ca_host":           ca_host,
        "ca_name":           ca_name or "",
        "url":               url,
        "http_status":       None,
        "ntlm_auth_present": False,
        "https_enforced":    False,
        "esc8_vulnerable":   False,
        "www_authenticate":  "",
        "error":             "",
    }

    try:
        # Use a no-redirect opener so we can inspect 401 responses directly
        opener = urllib.request.build_opener(
            urllib.request.HTTPRedirectHandler()
        )
        # Disable redirect following to catch 301/302 to HTTPS
        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        opener = urllib.request.build_opener(_NoRedirect())
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

        try:
            resp = opener.open(req, timeout=timeout)
            result["http_status"] = resp.status
            www_auth = resp.headers.get("WWW-Authenticate", "")
        except urllib.error.HTTPError as e:
            result["http_status"] = e.code
            www_auth = e.headers.get("WWW-Authenticate", "")
        except urllib.error.URLError as e:
            # Connection refused or timeout — endpoint not listening
            result["error"] = str(e)
            return result

        result["www_authenticate"]  = www_auth
        result["ntlm_auth_present"] = "NTLM" in www_auth.upper() or "NEGOTIATE" in www_auth.upper()

        # Check if HTTPS is enforced by probing the HTTPS endpoint
        https_url = f"https://{ca_host}/certsrv/"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            https_req  = urllib.request.Request(https_url, headers={"User-Agent": "Mozilla/5.0"})
            https_resp = urllib.request.urlopen(https_req, context=ctx, timeout=timeout)
            result["https_enforced"] = https_resp.status in (200, 401)
        except Exception:
            result["https_enforced"] = False

        # ESC8 vulnerable: endpoint reachable + NTLM offered + no HTTPS enforcement
        if result["http_status"] in (200, 401) and result["ntlm_auth_present"]:
            result["esc8_vulnerable"] = not result["https_enforced"]

    except Exception as exc:
        result["error"] = str(exc)

    return result


def enumerate_all_cas_rpc(pki_objects, username, password=None,
                          ntlm_hash=None, domain=None, verbose=False,
                          ca_ip_override=None):
    """
    Iterate over all Enrollment Services objects collected by
    enumerate_pki_objects() and call enumerate_ca_rpc() + probe_esc8_http()
    for each CA.

    CA host and name are extracted from:
      dns_host_name  → ca_host (overridden by ca_ip_override if provided)
      cn             → ca_name

    Returns list of CA RPC result dicts (one per CA found),
    each augmented with an "esc8_http_probe" key.
    """
    cas = [
        obj for obj in pki_objects
        if obj.get("category") == "Enrollment Services"
        and obj.get("dns_host_name")
        and obj.get("cn")
    ]

    if not cas:
        if verbose:
            print("  [!] No Enrollment Services objects found — skipping RPC CA enumeration")
        return []

    results = []
    for ca_obj in cas:
        ca_host = ca_ip_override or ca_obj["dns_host_name"]
        ca_name = ca_obj["cn"]
        print(f"  [*] RPC → {ca_host}\\{ca_name}")
        rpc_data = enumerate_ca_rpc(
            ca_host, ca_name,
            username=username,
            password=password,
            ntlm_hash=ntlm_hash,
            domain=domain,
            verbose=verbose,
        )

        # ── ESC6 summary ──────────────────────────────────────────────────────
        esc6 = rpc_data.get("esc6_vulnerable")
        if esc6 is True:
            print(f"  [!] ESC6 VULNERABLE — EDITF_ATTRIBUTESUBJECTALTNAME2 is SET on {ca_name}")
        elif esc6 is False:
            print(f"  [+] ESC6 safe — EDITF_ATTRIBUTESUBJECTALTNAME2 not set on {ca_name}")
        else:
            print(f"  [?] ESC6 unknown — RPC not available. Manual: {rpc_data['manual_check_command']}")

        # ── ESC7 summary ──────────────────────────────────────────────────────
        manage_sids  = rpc_data.get("esc7_manage_ca_sids", [])
        officer_sids = rpc_data.get("esc7_officer_sids", [])
        if manage_sids or officer_sids:
            print(f"  [*] ESC7: ManageCA SIDs: {manage_sids} | Officer SIDs: {officer_sids}")
        elif rpc_data.get("source") == "rpc":
            print(f"  [+] ESC7: CA Security Descriptor collected ({len(rpc_data.get('ca_security_aces', []))} ACEs)")

        # ── ESC11 summary ─────────────────────────────────────────────────────
        esc11 = rpc_data.get("esc11_vulnerable")
        if esc11 is True:
            print(f"  [!] ESC11 VULNERABLE — IF_ENFORCEENCRYPTICERTREQUEST is NOT SET on {ca_name}")
        elif esc11 is False:
            print(f"  [+] ESC11 safe — IF_ENFORCEENCRYPTICERTREQUEST is set on {ca_name}")

        # ── ESC8 HTTP probe ───────────────────────────────────────────────────
        print(f"  [*] ESC8 HTTP probe → http://{ca_host}/certsrv/")
        esc8 = probe_esc8_http(ca_host, ca_name=ca_name, verbose=verbose)
        rpc_data["esc8_http_probe"] = esc8
        if esc8.get("esc8_vulnerable"):
            print(f"  [!] ESC8 VULNERABLE — NTLM auth on HTTP certsrv on {ca_host}")
        elif esc8.get("error"):
            print(f"  [?] ESC8 probe error: {esc8['error']}")
        else:
            print(f"  [+] ESC8 safe — HTTP/NTLM not exposed on {ca_host}")

        results.append(rpc_data)

    return results


# ── Report ────────────────────────────────────────────────────────────────────

def get_strong_binding(conn, default_nc):
    """
    Attempt to surface StrongCertificateBindingEnforcement context.

    The registry key HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\
    StrongCertificateBindingEnforcement is NOT exposed over LDAP/ADWS.
    We therefore collect the best available proxy information:

      1. DC computer object: operatingSystem + operatingSystemVersion
         These let the ESC analysis modules infer the likely default value.
      2. Domain functional level (msDS-Behavior-Version on domain NC root)
         Provides additional context.

    Default values by OS (when registry key is absent):
      Windows Server 2025+      : 2 (Full Enforcement)
      Windows Server 2019/2022  : 1 (Compatibility mode) — changed to 2 after May 2025 patches
      Windows Server 2016       : 0 (Disabled)
      Earlier                   : 0 (Disabled)

    Returns dict:
      value       — None (registry not readable via LDAP)
      source      — "registry_not_readable_via_ldap"
      os_name     — e.g. "Windows Server 2022 Standard"
      os_version  — e.g. "10.0 (20348)"
      dfl         — domain functional level integer or None
      note        — manual check command
    """
    result = {
        "value":      None,
        "source":     "registry_not_readable_via_ldap",
        "os_name":    "",
        "os_version": "",
        "dfl":        None,
        "note": (
            "StrongCertificateBindingEnforcement cannot be read via LDAP. "
            "Check manually on DC: "
            "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\" "
            "/v StrongCertificateBindingEnforcement"
        ),
    }

    # --- Step 1: DC computer object (userAccountControl bit 0x2000 = SERVER_TRUST_ACCOUNT) ---
    try:
        ok = conn.search(
            search_base=default_nc,
            search_filter="(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            search_scope=SUBTREE,
            attributes=["cn", "operatingSystem", "operatingSystemVersion"],
        )
        if ok and conn.entries:
            entry = conn.entries[0]

            def _str(attr):
                try:
                    v = entry[attr].value
                    return str(v) if v else ""
                except Exception:
                    return ""

            result["os_name"]    = _str("operatingSystem")
            result["os_version"] = _str("operatingSystemVersion")
    except Exception as e:
        result["_dc_search_error"] = str(e)

    # --- Step 2: Domain functional level ---
    try:
        ok2 = conn.search(
            search_base=default_nc,
            search_filter="(objectClass=domain)",
            search_scope="BASE",
            attributes=["msDS-Behavior-Version"],
        )
        if ok2 and conn.entries:
            try:
                dfl_val = conn.entries[0]["msDS-Behavior-Version"].value
                result["dfl"] = int(dfl_val) if dfl_val is not None else None
            except Exception:
                pass
    except Exception as e:
        result["_dfl_search_error"] = str(e)

    return result


def build_report(args, domain, config_nc, templates, pki_objects=None,
                 strong_binding=None, ca_rpc_data=None):
    report_id = uuid.uuid4().hex[:8].upper()

    # ── ESC6 summary ─────────────────────────────────────────────────────────
    esc6_summary = []
    for ca in (ca_rpc_data or []):
        esc6_summary.append({
            "ca_host":         ca.get("ca_host", ""),
            "ca_name":         ca.get("ca_name", ""),
            "esc6_vulnerable": ca.get("esc6_vulnerable"),
            "edit_flags_raw":  ca.get("edit_flags_raw"),
            "source":          ca.get("source", "not_collected"),
        })

    # ── ESC7 summary ─────────────────────────────────────────────────────────
    esc7_summary = []
    for ca in (ca_rpc_data or []):
        esc7_summary.append({
            "ca_host":              ca.get("ca_host", ""),
            "ca_name":              ca.get("ca_name", ""),
            "manage_ca_sids":       ca.get("esc7_manage_ca_sids", []),
            "officer_sids":         ca.get("esc7_officer_sids", []),
            "ca_security_ace_count": len(ca.get("ca_security_aces", [])),
            "source":               ca.get("source", "not_collected"),
        })

    # ── ESC8 summary ─────────────────────────────────────────────────────────
    esc8_summary = []
    for ca in (ca_rpc_data or []):
        probe = ca.get("esc8_http_probe", {})
        esc8_summary.append({
            "ca_host":           ca.get("ca_host", ""),
            "ca_name":           ca.get("ca_name", ""),
            "url":               probe.get("url", ""),
            "http_status":       probe.get("http_status"),
            "ntlm_auth_present": probe.get("ntlm_auth_present", False),
            "https_enforced":    probe.get("https_enforced", False),
            "esc8_vulnerable":   probe.get("esc8_vulnerable", False),
        })

    # ── ESC11 summary ─────────────────────────────────────────────────────────
    esc11_summary = []
    for ca in (ca_rpc_data or []):
        esc11_summary.append({
            "ca_host":            ca.get("ca_host", ""),
            "ca_name":            ca.get("ca_name", ""),
            "esc11_vulnerable":   ca.get("esc11_vulnerable"),
            "interface_flags_raw": ca.get("interface_flags_raw"),
            "interface_flags_decoded": ca.get("interface_flags_decoded", []),
            "source":             ca.get("source", "not_collected"),
        })

    return {
        "report_id":    report_id,
        "tool":         f"oxs_cert v{TOOL_VERSION}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_info": {
            "dc_ip":       args.dc_ip,
            "ns_ip":       args.ns_ip,
            "ca_ip":       args.ca_ip,
            "domain":      domain,
            "config_nc":   config_nc,
            "user":        args.user,
            "auth_method": "NTLM-Hash" if args.hash else "NTLM-Password",
            "kdc_strong_certificate_binding": strong_binding or {
                "value":      None,
                "source":     "not_collected",
                "os_name":    "",
                "os_version": "",
                "dfl":        None,
                "note":       "",
            },
        },
        "summary": {
            "total_templates":      len(templates),
            "total_pki_objects":    len(pki_objects or []),
            "total_cas_rpc":        len(ca_rpc_data or []),
            "esc6_vulnerable_cas":  sum(
                1 for c in (ca_rpc_data or []) if c.get("esc6_vulnerable") is True
            ),
            "esc8_vulnerable_cas":  sum(
                1 for c in (ca_rpc_data or [])
                if c.get("esc8_http_probe", {}).get("esc8_vulnerable") is True
            ),
            "esc11_vulnerable_cas": sum(
                1 for c in (ca_rpc_data or []) if c.get("esc11_vulnerable") is True
            ),
        },
        "templates":    templates,
        "pki_objects":  pki_objects or [],
        "ca_rpc_data":  ca_rpc_data or [],
        "esc6_summary":  esc6_summary,
        "esc7_summary":  esc7_summary,
        "esc8_summary":  esc8_summary,
        "esc11_summary": esc11_summary,
    }, report_id


def save_report(report, report_id, output_path=None):
    if not output_path:
        output_dir = os.getcwd()
        output_path = os.path.join(output_dir, f"oxs_cert_{report_id}.json")
    else:
        output_dir = os.path.dirname(output_path)
    
    # Delete previous report files (oxs_cert_*.json)
    if os.path.exists(output_dir):
        for file in os.listdir(output_dir):
            if file.startswith("oxs_cert_") and file.endswith(".json"):
                try:
                    os.remove(os.path.join(output_dir, file))
                except Exception:
                    pass
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    return output_path

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    banner(quiet=args.quiet)

    if not args.user:
        print("[!] Username required (-u)"); sys.exit(1)
    if not args.password and not args.hash:
        print("[!] Password (-p) or NTLM hash (-H) required"); sys.exit(1)

    print(f"[*] Reading rootDSE from {args.dc_ip} ...")
    default_nc, config_nc = get_naming_contexts(args.dc_ip)

    if not default_nc:
        print("[!] Cannot read defaultNamingContext.")
        sys.exit(1)

    if not config_nc:
        config_nc = f"CN=Configuration,{default_nc}"

    domain    = args.domain or dn_to_domain(default_nc)
    ntlm_user = build_ntlm_user(args.user, domain)

    print(f"[+] Domain     : {domain}")
    print(f"[+] Default NC : {default_nc}")
    print(f"[+] Config NC  : {config_nc}")
    print(f"[*] Connecting : {ntlm_user} ...")

    try:
        conn = connect_ldap(
            args.dc_ip, args.user,
            password=args.password,
            ntlm_hash=args.hash,
            domain=domain,
        )
        print("[+] Authenticated successfully\n")
    except Exception as e:
        print(f"[!] Authentication failed: {e}")
        sys.exit(1)

    print("[*] Enumerating certificate templates ...")
    templates = enumerate_templates(conn, config_nc, verbose=args.verbose)

    print(f"\n[*] Enumerating PKI infrastructure objects ...")
    pki_objects = enumerate_pki_objects(conn, config_nc, verbose=args.verbose)

    print(f"\n[*] Reading KDC StrongCertificateBindingEnforcement ...")
    strong_binding = get_strong_binding(conn, default_nc)
    sb_val = strong_binding.get("value")
    if sb_val is None:
        print(f"  [!] StrongCertificateBindingEnforcement: cannot read via LDAP — check DC manually")
        print(f"      {strong_binding.get('note', '')}")
    else:
        label = {0: "DISABLED (0)", 1: "Compatibility (1)", 2: "Full Enforcement (2)"}.get(sb_val, str(sb_val))
        print(f"  [+] StrongCertificateBindingEnforcement: {label}")

    conn.unbind()

    print(f"\n[+] {len(templates)} template(s) found")
    print(f"[+] {len(pki_objects)} PKI object(s) found")

    print(f"\n[*] Enumerating CA properties via RPC (MS-CSRA) ...")
    ca_rpc_data = enumerate_all_cas_rpc(
        pki_objects,
        username=args.user,
        password=args.password,
        ntlm_hash=args.hash,
        domain=domain,
        verbose=args.verbose,
        ca_ip_override=args.ca_ip,
    )
    if not ca_rpc_data:
        print(f"  [!] No CA RPC data collected (no Enrollment Services found or RPC failed)")

    report, report_id = build_report(args, domain, config_nc, templates, pki_objects,
                                     strong_binding=strong_binding,
                                     ca_rpc_data=ca_rpc_data)
    path = save_report(report, report_id, args.output)
    print(f"[+] Report saved -> {path}")
    print(f"[*] Run ESC checks: python3 esc1.py -f {path}")


if __name__ == "__main__":
    main()