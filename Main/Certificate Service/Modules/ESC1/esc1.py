#!/usr/bin/env python3
import argparse
import json
import sys

# ── EKUs that satisfy Client Authentication requirement ───────────────────────

CLIENT_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",   # Client Authentication
    "2.5.29.37.0",          # Any Purpose (explicit OID)
}

# ── Known admin-only SIDs ─────────────────────────────────────────────────────

ADMIN_SIDS = {
    "S-1-5-32-544",         # BUILTIN\Administrators
    "S-1-5-18",             # SYSTEM
}

ADMIN_SID_SUFFIXES = [
    "-512",  # Domain Admins
    "-519",  # Enterprise Admins
    "-516",  # Domain Controllers
    # Note: -517 (Cert Publishers) intentionally excluded — a compromised
    # Cert Publisher with Enroll rights IS a valid ESC1 finding.
]


def parse_args():
    p = argparse.ArgumentParser(
        description="ESC1 checker for oxs_cert JSON reports",
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


def has_non_admin_enroll(aces):
    """Returns (True, sid) if at least one non-admin has Enroll right.

    Correctly handles Deny ACEs: AD evaluates Deny before Allow, so an explicit
    Deny for a SID cancels any Allow for the same SID.
    """
    # Collect SIDs that are explicitly denied Enroll
    denied_sids = set()
    for ace in aces:
        if ace.get("type") != "Deny":
            continue
        sid  = ace.get("sid", "")
        right = ace.get("right", "")
        mask  = ace.get("mask", "0x0")
        try:
            mask_int = int(mask, 16)
        except (ValueError, TypeError):
            mask_int = 0
        if (right == "Enroll") or (mask_int & 0x100) or (mask_int & 0x10000000):
            denied_sids.add(sid)

    for ace in aces:
        if ace.get("type") != "Allow":
            continue
        sid   = ace.get("sid", "")
        right = ace.get("right", "")
        mask  = ace.get("mask", "0x0")

        try:
            mask_int = int(mask, 16)
        except (ValueError, TypeError):
            mask_int = 0

        has_enroll = (right == "Enroll") or (mask_int & 0x100) or (mask_int & 0x10000000)

        if has_enroll and not is_admin_sid(sid) and sid not in denied_sids:
            return True, sid

    return False, None


# ── Core ESC1 check ───────────────────────────────────────────────────────────

def check_esc1(template, skip_acl=False):
    """
    Returns (is_vulnerable, reasons_failed, acl_unknown, enroll_sid)

    acl_unknown=True → ACL məlumatı yox idi, nəticə tam deyil
    """
    raw    = template.get("raw", {})
    parsed = template.get("parsed", {})

    failed = []
    acl_unknown = False

    # ── Filter 1: CA / SubCA templates ───────────────────────────────────────
    # Certipy excludes CA templates from ESC1 via ACL checks (no domain user
    # can enroll). We filter by is_ca directly. Also fixes the false-positive
    # where an empty EKU list was treated as "Any Purpose" for CA templates.
    is_ca = parsed.get("is_ca", False)
    if is_ca:
        failed.append("CA template (is_ca=True) — ESC1 does not apply")
        return False, failed, acl_unknown, None

    # ── Filter 2: Machine-type templates ─────────────────────────────────────
    # CT_FLAG_MACHINE_TYPE means only computer accounts can enroll.
    # Certipy reaches the same conclusion via live ACL resolution
    # (Domain Users / Authenticated Users are not in the ACE list).
    # We filter by the parsed flag since nTSecurityDescriptor is null in the report.
    is_machine = parsed.get("is_machine_type", False)
    if is_machine:
        failed.append("Machine-type template (is_machine_type=True) — domain users cannot enroll")
        return False, failed, acl_unknown, None

    # ── Condition 1: Enrollee supplies subject ───────────────────────────────
    name_flags = parsed.get("subject_name_flags_decoded", [])
    enrollee_supplies = (
        "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT" in name_flags or
        "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME" in name_flags
    )
    if not enrollee_supplies:
        failed.append("Enrollee does not supply subject")

    # ── Condition 2: Client Authentication EKU ──────────────────────────────
    # Empty EKU list = Any Purpose, which satisfies client auth.
    # This is safe to assume here because CA and machine templates are already
    # excluded by the filters above, so the only remaining empty-EKU templates
    # are user-enrollable ones (e.g. old schema v1 templates).
    ekus = raw.get("pKIExtendedKeyUsage") or []
    if isinstance(ekus, str):
        ekus = [ekus]

    app_policies = raw.get("msPKI-Certificate-Application-Policy") or []
    if isinstance(app_policies, str):
        app_policies = [app_policies]

    all_oids = set(ekus) | set(app_policies)
    no_eku   = not ekus and not app_policies   # no EKU = Any Purpose

    has_client_auth = bool(all_oids & CLIENT_AUTH_EKUS) or no_eku
    if not has_client_auth:
        failed.append(f"No Client Authentication EKU (found: {sorted(all_oids) or 'none'})")

    # ── Condition 3: No manager approval ────────────────────────────────────
    enroll_flags = parsed.get("enrollment_flags_decoded", [])
    if "CT_FLAG_PEND_ALL_REQUESTS" in enroll_flags:
        failed.append("Manager approval required")

    # ── Condition 4: RA signature count = 0 ─────────────────────────────────
    ra_sig = raw.get("msPKI-RA-Signature")
    ra_required = ra_sig is not None and str(ra_sig) not in ("0", "None", "")
    if ra_required:
        failed.append(f"RA signature required ({ra_sig})")

    # ── Condition 5: ACL — non-admin principal has Enroll right ─────────────
    enroll_sid = None
    if not skip_acl:
        aces = parsed.get("acl_enrollment_aces", [])
        if aces:
            non_admin_enroll, enroll_sid = has_non_admin_enroll(aces)
            if not non_admin_enroll:
                failed.append("No non-admin principal has Enroll right")
        else:
            # ACL data missing — cannot confirm enrollability, treat as not vulnerable.
            # Bug fix: previously acl_unknown=True did not prevent is_vulnerable=True
            # because is_vulnerable = len(failed)==0, and failed was still empty.
            acl_unknown = True
            failed.append("ACL data missing — enrollability unconfirmed")

    is_vulnerable = len(failed) == 0
    # Strip the sentinel before returning so callers see a clean failed list
    if acl_unknown and "ACL data missing — enrollability unconfirmed" in failed:
        failed.remove("ACL data missing — enrollability unconfirmed")
    return is_vulnerable, failed, acl_unknown, enroll_sid


# ── Output ────────────────────────────────────────────────────────────────────

def print_template(t, enroll_sid=None, acl_unknown=False):
    raw    = t.get("raw", {})
    parsed = t.get("parsed", {})

    cn           = raw.get("cn", "N/A")
    display_name = raw.get("displayName", "N/A")
    dn           = t.get("dn", "N/A")
    ra_sig       = raw.get("msPKI-RA-Signature", "N/A")
    schema_ver   = raw.get("msPKI-Template-Schema-Version", "N/A")
    validity     = parsed.get("validity_period", "unknown")
    is_machine   = parsed.get("is_machine_type", None)

    name_flags   = parsed.get("subject_name_flags_decoded", [])
    enroll_flags = parsed.get("enrollment_flags_decoded", [])
    pk_flags     = parsed.get("private_key_flags_decoded", [])
    ekus         = parsed.get("eku_friendly", [])

    print(f"Template      : {cn} ({display_name})")
    print(f"DN            : {dn}")
    print(f"Schema Ver    : {schema_ver}")
    print(f"Validity      : {validity}")
    print(f"Machine Type  : {is_machine}")
    print(f"RA Signature  : {ra_sig}")
    print(f"Subject Flags : {', '.join(name_flags) if name_flags else 'none'}")
    print(f"Enroll Flags  : {', '.join(enroll_flags) if enroll_flags else 'none'}")
    print(f"PK Flags      : {', '.join(pk_flags) if pk_flags else 'none'}")
    print(f"EKU           : {', '.join(e['name'] + ' (' + e['oid'] + ')' for e in ekus) if ekus else 'none (Any Purpose)'}")
    if enroll_sid:
        print(f"Enroll SID    : {enroll_sid}")
    if acl_unknown:
        print(f"ACL           : [!] No ACL data — verify manually")


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

    templates   = report.get("templates", [])
    vulnerable  = []
    acl_unknown = []
    skipped     = []

    for t in templates:
        is_vuln, failed, unk, enroll_sid = check_esc1(t, skip_acl=args.skip_acl)
        if is_vuln:
            vulnerable.append((t, enroll_sid, unk))
        elif unk and len(failed) == 0:
            # Bütün şərtlər keçdi, yalnız ACL naməlumdur
            acl_unknown.append((t, enroll_sid))
        else:
            skipped.append((t, failed))

    # ── Vulnerable ────────────────────────────────────────────────────────────
    if vulnerable:
        print(f"[!] ESC1 found in {len(vulnerable)} template(s)\n")
        print("-" * 60)
        for t, enroll_sid, unk in vulnerable:
            print_template(t, enroll_sid=enroll_sid, acl_unknown=unk)
            print("-" * 60)
    else:
        print("[+] No ESC1 vulnerabilities found.")

    # ── ACL unknown (potential) ───────────────────────────────────────────────
    if acl_unknown:
        print(f"\n[?] {len(acl_unknown)} template(s) — all conditions met but ACL could not be verified (check manually):\n")
        print("-" * 60)
        for t, enroll_sid in acl_unknown:
            print_template(t, enroll_sid=enroll_sid, acl_unknown=True)
            print("-" * 60)

    # ── Verbose skip ─────────────────────────────────────────────────────────
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