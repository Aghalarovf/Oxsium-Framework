#!/usr/bin/env python3
"""
esc2.py -- ESC2 vulnerability checker for oxs_cert JSON reports.
Usage: python3 esc2.py -f oxs_cert_XXXXXXXX.json

ESC2 conditions (ALL must be true):
  1. Template is NOT a CA template         (is_ca == False)
  2. Template is NOT a machine type        (is_machine_type == False)
  3. EKU is Any Purpose (2.5.29.37.0) OR pKIExtendedKeyUsage is empty
     -- Checked against eku_is_empty, eku_is_any_purpose, and
        app_policy_any_purpose (CA uses Application Policy when it
        differs from EKU, so checking only one field causes false negatives).
  4. Manager approval is NOT required      (no CT_FLAG_PEND_ALL_REQUESTS)
  5. RA signature count is 0               (msPKI-RA-Signature == 0)
  6. At least one non-admin principal has Enroll right (ACL check)
     -- Uses the `rights` list from template_enumeration.py >= 1.4.0.
        If ACL data is missing the result is flagged UNKNOWN, not vulnerable.

Exploitation paths:
  Path 1 (Direct / ESC1-like):
    CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set -- requester controls SAN and
    can authenticate directly as any principal.

  Path 2 (Sub-CA abuse):
    The Any Purpose / No-EKU cert acts as a subordinate CA.
    Attacker enrolls with their own identity, then signs a new cert on
    behalf of a privileged user via certipy-ad --on-behalf-of.
    CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF (0x800) is a confirming signal
    but is not required -- Any Purpose EKU alone is sufficient.

Requires template_enumeration.py >= 1.4.0:
  parsed["ra_signature"]            -- integer
  parsed["eku_is_empty"]            -- True when pKIExtendedKeyUsage is null/[]
  parsed["eku_is_any_purpose"]      -- True when 2.5.29.37.0 is in EKU list
  parsed["app_policy_any_purpose"]  -- True when 2.5.29.37.0 is in App Policy
  parsed["app_policy_eku_mismatch"] -- True when App Policy != EKU set
  ace["rights"]                     -- list of right names (replaces single "right")
"""

import argparse
import json
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ANY_PURPOSE_OID = "2.5.29.37.0"

# Well-known admin-only SID values and suffixes.
# A SID matching any of these is considered privileged and excluded from
# the non-admin Enroll check.
ADMIN_SIDS = {
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-18",      # SYSTEM
}
ADMIN_SID_SUFFIXES = (
    "-512",  # Domain Admins
    "-519",  # Enterprise Admins
    "-516",  # Domain Controllers
)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="ESC2 checker for oxs_cert JSON reports",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-f", "--file", metavar="FILE", required=True,
                   help="Path to oxs_cert JSON report")
    p.add_argument("--skip-acl", action="store_true",
                   help="Skip ACL check (use if ACL data is unavailable)")
    p.add_argument("--verbose-skip", action="store_true",
                   help="Print why each non-vulnerable template was skipped")
    return p.parse_args()


def load_report(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {path}")
    except json.JSONDecodeError as exc:
        sys.exit(f"[!] Invalid JSON: {exc}")

# ---------------------------------------------------------------------------
# ACL helpers
# ---------------------------------------------------------------------------

def _is_admin_sid(sid):
    return sid in ADMIN_SIDS or any(sid.endswith(s) for s in ADMIN_SID_SUFFIXES)


def _has_non_admin_enroll(aces):
    """Return (True, sid) if a non-admin principal has an Enroll right.

    Uses the `rights` list populated by template_enumeration.py >= 1.4.0.
    Falls back to the legacy `right` string for older reports.

    Deny ACEs are evaluated first -- an explicit Deny cancels any Allow
    for the same SID, matching AD's ACE evaluation order.

    FIX vs original esc2.py:
      The original checked `mask & 0x100` (DS_CONTROL_ACCESS) directly,
      which matches ANY extended right, not just Enroll.  template_enumeration
      already resolves the object-type GUID to the correct right name, so we
      delegate to that result instead of re-checking the raw mask.
    """
    denied_sids = set()

    for ace in aces:
        if ace.get("type") != "Deny":
            continue
        rights = ace.get("rights") or ([ace["right"]] if ace.get("right") else [])
        if "Enroll" in rights or "GenericAll" in rights:
            denied_sids.add(ace.get("sid", ""))

    for ace in aces:
        if ace.get("type") != "Allow":
            continue
        sid = ace.get("sid", "")
        if _is_admin_sid(sid) or sid in denied_sids:
            continue
        rights = ace.get("rights") or ([ace["right"]] if ace.get("right") else [])
        if "Enroll" in rights or "GenericAll" in rights:
            return True, sid

    return False, None

# ---------------------------------------------------------------------------
# Exploit path detection
# ---------------------------------------------------------------------------

def _detect_exploit_paths(parsed):
    """Return a list of applicable exploitation paths.

    Path 1 requires CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT.
    Path 2 is always applicable when ESC2 conditions are met.
    """
    paths = []

    name_flags = parsed.get("subject_name_flags_decoded", [])
    if "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT" in name_flags:
        paths.append(
            "Path 1 -- Direct (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set; exploit like ESC1)"
        )

    enroll_flags = parsed.get("enrollment_flags_decoded", [])
    on_behalf_note = (
        " [CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF confirmed]"
        if "CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF" in enroll_flags
        else " [CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF not set -- sub-CA signing still works]"
    )
    paths.append(f"Path 2 -- Sub-CA abuse (Any Purpose / No-EKU){on_behalf_note}")

    return paths

# ---------------------------------------------------------------------------
# ESC2 core check
# ---------------------------------------------------------------------------

def check_esc2(template, skip_acl=False):
    """Evaluate one template for ESC2.

    Returns:
        is_vulnerable  (bool)
        reasons_failed (list[str])  -- empty when vulnerable
        acl_unknown    (bool)       -- True when ACL data was absent
        enroll_sid     (str|None)   -- SID that has Enroll right
        exploit_paths  (list[str])  -- populated when vulnerable or ACL unknown
    """
    raw    = template.get("raw", {})
    parsed = template.get("parsed", {})

    failed      = []
    acl_unknown = False

    # -- Filter 1: CA templates -----------------------------------------------
    # A template that IS itself a CA cannot be the basis of an ESC2 attack.
    # Empty-EKU CA templates would otherwise match Condition 3 and produce
    # false positives.
    if parsed.get("is_ca", False):
        return False, ["CA template (is_ca=True) -- ESC2 does not apply"], False, None, []

    # -- Filter 2: Machine-type templates -------------------------------------
    # Domain Users cannot enroll in machine templates.
    if parsed.get("is_machine_type", False):
        return False, ["Machine-type template -- domain users cannot enroll"], False, None, []

    # -- Condition 1: Any Purpose EKU or empty EKU ----------------------------
    # Three derived booleans are checked (all populated by template_enumeration
    # >= 1.4.0).  A raw fallback handles older reports gracefully.
    eku_is_empty       = parsed.get("eku_is_empty")
    eku_is_any_purpose = parsed.get("eku_is_any_purpose")
    app_policy_any     = parsed.get("app_policy_any_purpose")

    if eku_is_empty is None:
        # Older report -- derive from raw fields directly.
        ekus_raw = raw.get("pKIExtendedKeyUsage") or []
        if isinstance(ekus_raw, str):
            ekus_raw = [ekus_raw]
        app_raw = raw.get("msPKI-Certificate-Application-Policy") or []
        if isinstance(app_raw, str):
            app_raw = [app_raw]

        eku_is_empty       = not ekus_raw and not app_raw
        eku_is_any_purpose = ANY_PURPOSE_OID in ekus_raw
        app_policy_any     = ANY_PURPOSE_OID in app_raw

    if not (eku_is_empty or eku_is_any_purpose or app_policy_any):
        ekus_friendly = parsed.get("eku_friendly", [])
        found = (
            ", ".join(f"{e['name']} ({e['oid']})" for e in ekus_friendly)
            or "none"
        )
        failed.append(f"EKU is not Any Purpose / not empty (found: {found})")

    # -- Condition 2: No manager approval -------------------------------------
    enroll_flags = parsed.get("enrollment_flags_decoded", [])
    if "CT_FLAG_PEND_ALL_REQUESTS" in enroll_flags:
        failed.append("Manager approval required (CT_FLAG_PEND_ALL_REQUESTS)")

    # -- Condition 3: RA signature count = 0 ----------------------------------
    # parsed["ra_signature"] is an integer (template_enumeration >= 1.3.0).
    # Fall back to the raw string for older reports.
    ra_sig = parsed.get("ra_signature")
    if ra_sig is not None:
        ra_required = ra_sig != 0
    else:
        ra_raw = raw.get("msPKI-RA-Signature")
        ra_required = ra_raw is not None and str(ra_raw).strip() not in ("0", "", "None")
        ra_sig = ra_raw

    if ra_required:
        failed.append(f"RA signature required (msPKI-RA-Signature={ra_sig})")

    # -- Condition 4: Non-admin principal has Enroll right --------------------
    enroll_sid = None
    if not skip_acl:
        aces = parsed.get("acl_enrollment_aces", [])
        if aces:
            ok, enroll_sid = _has_non_admin_enroll(aces)
            if not ok:
                failed.append("No non-admin principal has Enroll right")
        else:
            acl_unknown = True

    is_vulnerable = len(failed) == 0

    exploit_paths = []
    if is_vulnerable or (acl_unknown and not failed):
        exploit_paths = _detect_exploit_paths(parsed)

    return is_vulnerable, failed, acl_unknown, enroll_sid, exploit_paths

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _print_template(t, enroll_sid=None, acl_unknown=False, exploit_paths=None):
    raw    = t.get("raw", {})
    parsed = t.get("parsed", {})

    cn           = raw.get("cn", "N/A")
    display_name = raw.get("displayName", "N/A")
    dn           = t.get("dn", "N/A")
    schema_ver   = raw.get("msPKI-Template-Schema-Version", "N/A")
    validity     = parsed.get("validity_period", "unknown")
    is_machine   = parsed.get("is_machine_type")

    ra_sig = parsed.get("ra_signature")
    if ra_sig is None:
        ra_sig = raw.get("msPKI-RA-Signature", "N/A")

    name_flags   = parsed.get("subject_name_flags_decoded", [])
    enroll_flags = parsed.get("enrollment_flags_decoded", [])
    pk_flags     = parsed.get("private_key_flags_decoded", [])
    ekus         = parsed.get("eku_friendly", [])

    eku_is_empty = parsed.get("eku_is_empty", not ekus)
    app_mismatch = parsed.get("app_policy_eku_mismatch", False)

    eku_str = (
        "none (Any Purpose -- empty EKU)"
        if eku_is_empty
        else ", ".join(f"{e['name']} ({e['oid']})" for e in ekus)
    )

    print(f"Template      : {cn} ({display_name})")
    print(f"DN            : {dn}")
    print(f"Schema Ver    : {schema_ver}")
    print(f"Validity      : {validity}")
    print(f"Machine Type  : {is_machine}")
    print(f"RA Signature  : {ra_sig}")
    print(f"Subject Flags : {', '.join(name_flags) if name_flags else 'none'}")
    print(f"Enroll Flags  : {', '.join(enroll_flags) if enroll_flags else 'none'}")
    print(f"PK Flags      : {', '.join(pk_flags) if pk_flags else 'none'}")
    print(f"EKU           : {eku_str}")

    if app_mismatch:
        app_pol = parsed.get("application_policies_friendly", [])
        app_str = (
            ", ".join(f"{e['name']} ({e['oid']})" for e in app_pol) or "none"
        )
        print(f"App Policy    : {app_str}  [!] differs from EKU -- CA uses App Policy")

    if enroll_sid:
        print(f"Enroll SID    : {enroll_sid}")
    if acl_unknown:
        print("ACL           : [!] No ACL data -- verify manually")

    if exploit_paths:
        print("Exploit Paths :")
        for path in exploit_paths:
            print(f"  > {path}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args   = parse_args()
    report = load_report(args.file)

    scan   = report.get("scan_info", {})
    print(f"[*] Report : {report.get('report_id', 'N/A')}")
    print(f"[*] Domain : {scan.get('domain', 'N/A')}")
    print(f"[*] DC IP  : {scan.get('dc_ip', 'N/A')}")
    print(f"[*] User   : {scan.get('user', 'N/A')}")
    print()

    templates   = report.get("templates", [])
    vulnerable  = []
    acl_unknown = []
    skipped     = []

    for t in templates:
        is_vuln, failed, unk, enroll_sid, paths = check_esc2(t, skip_acl=args.skip_acl)
        if is_vuln:
            vulnerable.append((t, enroll_sid, unk, paths))
        elif unk and not failed:
            # All conditions passed; only ACL is unconfirmed.
            acl_unknown.append((t, enroll_sid, paths))
        else:
            skipped.append((t, failed))

    SEP = "-" * 60

    # -- Vulnerable -----------------------------------------------------------
    if vulnerable:
        print(f"[!] ESC2 found in {len(vulnerable)} template(s)\n")
        print(SEP)
        for t, sid, unk, paths in vulnerable:
            _print_template(t, enroll_sid=sid, acl_unknown=unk, exploit_paths=paths)
            print(SEP)
    else:
        print("[+] No ESC2 vulnerabilities found.")

    # -- ACL unknown (potential) ----------------------------------------------
    if acl_unknown:
        print(
            f"\n[?] {len(acl_unknown)} template(s) -- all conditions met "
            f"but ACL could not be verified (check manually):\n"
        )
        print(SEP)
        for t, sid, paths in acl_unknown:
            _print_template(t, enroll_sid=sid, acl_unknown=True, exploit_paths=paths)
            print(SEP)

    # -- Verbose skip ---------------------------------------------------------
    if args.verbose_skip and skipped:
        print(f"\n[*] Skipped templates ({len(skipped)}):")
        for t, reasons in skipped:
            cn = t.get("raw", {}).get("cn", "?")
            print(f"  - {cn}: {'; '.join(reasons)}")

    print()
    print(
        f"[*] {len(templates)} templates checked  |  "
        f"{len(vulnerable)} vulnerable  |  "
        f"{len(acl_unknown)} ACL-unknown  |  "
        f"{len(skipped)} not vulnerable"
    )


if __name__ == "__main__":
    main()