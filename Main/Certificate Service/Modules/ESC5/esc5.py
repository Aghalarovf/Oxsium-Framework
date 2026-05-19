#!/usr/bin/env python3
"""
esc5.py — ESC5 vulnerability checker for oxs_cert JSON reports.
Usage: python3 esc5.py -f oxs_cert_XXXXXXXX.json

ESC5 — PKI Object Misconfigured Access Control (ALL must be true):

  1. The object is an ESC5-relevant PKI infrastructure object — one of:
       Enrollment Services    (pKIEnrollmentService)
       NTAuthCertificates
       Certification Authorities
       AIA  (Authority Information Access container)
       CDP  (CRL Distribution Point container)
  2. At least one non-admin principal has a write-capable right over the
     object (ACL check):
       GenericAll    — full control, implies all rights below
       GenericWrite  — write any property
       WriteProperty — dangerous regardless of object-type scoping for PKI
                        objects (all attributes on these objects are critical).
                        No GUID filtering is applied — unlike ESC4.
       WriteDACL     — modify DACL → attacker can self-grant any right
       WriteOwner    — take ownership → attacker can then grant WriteDACL

  Note on ESC5 vs ESC4:
    ESC4 targets individual certificate templates.
    ESC5 targets the CA infrastructure itself — Enrollment Services,
    NTAuthCertificates, root CA objects, AIA, and CDP containers.
    A write right over any of these lets an attacker manipulate CA trust,
    published template lists, or certificate revocation — ultimately enabling
    arbitrary certificate issuance without touching a single template.

    Unlike ESC4 there is no separate Enroll check: the attacker modifies the
    PKI object directly (e.g. adds a template to certificateTemplates on the
    Enrollment Services object) and then exploits the resulting condition
    (typically ESC1 or a new trust anchor) using any enrolled principal.

  ACL unknown:
    If ACL data is entirely missing for an object, it is flagged UNCERTAIN —
    manual verification required.

Exploitation flow (certipy — Enrollment Services target):
  Step 1 — Confirm write right over the Enrollment Services object:
             certipy find ... -stdout
  Step 2 — Modify a CA-published template to ESC1-equivalent conditions:
             certipy template ... -template <NAME> -save-old
  Step 3 — Request a certificate with a privileged UPN via SAN:
             certipy req   ... -template <NAME> -upn administrator@domain
  Step 4 — Authenticate with the resulting certificate:
             certipy auth  ... -pfx administrator.pfx
  Step 5 (optional) — Restore original template config:
             certipy template ... -template <NAME> -configuration <NAME>.json

Requires template_enumeration.py >= 1.4.0 with ESC5 fields applied:
  report["pki_objects"]                    — list of PKI infrastructure objects
  pki_object["acl_aces"]                   — all parsed ACEs for the object
  pki_object["acl_esc5_write_aces"]        — Allow ACEs with ESC5-dangerous
                                              write rights held by non-admin
                                              principals (pre-filtered)
  pki_object["acl_has_esc5_write_right"]   — True when any dangerous ACE found
  pki_object["category"]                   — friendly label (e.g. "Enrollment Services")
  pki_object["certificate_templates"]      — published templates (Enrollment Services)
  pki_object["dns_host_name"]              — CA hostname (Enrollment Services)
"""

import argparse
import json
import sys

# ── ESC5-dangerous write rights ───────────────────────────────────────────────
#
# All five rights are dangerous regardless of object-type GUID scoping.
# PKI infrastructure objects (Enrollment Services, NTAuthCertificates, etc.)
# have a small, fully security-critical attribute set — there is no "safe"
# attribute to write to on these objects.  No GUID filtering is applied
# (contrast with ESC4 where WriteProperty requires a specific attribute GUID).

ESC5_WRITE_RIGHTS = {
    "GenericAll",
    "GenericWrite",
    "WriteProperty",
    "WriteDACL",
    "WriteOwner",
}

# ── Known admin-only SIDs (mirrored from esc4.py) ────────────────────────────

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
        description="ESC5 checker for oxs_cert JSON reports",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-f", "--file", metavar="FILE", required=True,
                   help="Path to oxs_cert JSON report")
    p.add_argument("--skip-acl", action="store_true",
                   help="Skip ACL check (use if ACL data is unavailable)")
    p.add_argument("--verbose-skip", action="store_true",
                   help="Print why each non-qualifying object was skipped")
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

    Supports both the new `rights` list (template_enumeration >= 1.4.0) and
    the legacy single `right` string for older reports.
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
    """True if the ACE carries at least one ESC5-dangerous write right.

    For PKI infrastructure objects WriteProperty is always dangerous regardless
    of object-type GUID scoping — no GUID filtering is applied here.

    This function is used only for the legacy fallback path (pre-1.4.0 reports
    where acl_esc5_write_aces is absent and acl_aces must be re-filtered).
    For reports produced by template_enumeration.py >= 1.4.0 the filtering is
    already done by the enumerator and acl_esc5_write_aces contains only
    non-admin dangerous ACEs.
    """
    return bool(ESC5_WRITE_RIGHTS & _ace_rights(ace))


def has_non_admin_write(aces):
    """Returns (True, sid, rights_found) if at least one non-admin principal
    holds an ESC5-dangerous write right.

    Deny ACEs are evaluated first — an explicit Deny for a SID cancels
    any Allow for the same SID, matching AD's ACE evaluation order.
    Only Deny ACEs that cover the specific write right being checked are
    counted (a Deny on one right does not block an Allow on another).
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
            rights_found = sorted(ESC5_WRITE_RIGHTS & _ace_rights(ace))
            return True, sid, rights_found

    return False, None, []


# ── Core ESC5 check ───────────────────────────────────────────────────────────

def check_esc5(pki_obj, skip_acl=False):
    """
    Returns (qualifies, reasons_failed, acl_unknown, write_sid, write_rights)

    qualifies    = True  → object is confirmed ESC5-vulnerable
    acl_unknown  = True  → conditions passed but ACL data was missing
    write_sid    = SID of the principal with the dangerous write right (or None)
    write_rights = list of specific write rights that SID holds

    Note: ESC5 has no Enroll check (unlike ESC4).  The attacker uses the write
    right to manipulate the PKI object directly; Enroll is exercised separately
    on a template that becomes reachable as a result of the modification.
    """
    failed      = []
    acl_unknown = False
    write_sid   = None
    write_rights = []

    # ── Condition: Non-admin has ESC5-dangerous write right ───────────────────
    if not skip_acl:

        # Prefer the pre-computed ESC5 ACE list (template_enumeration >= 1.4.0).
        # acl_esc5_write_aces already excludes admin SIDs and contains only
        # Allow ACEs with ESC5-dangerous rights, so no further filtering needed.
        # Fall back to full acl_aces list for older reports.
        write_aces = pki_obj.get("acl_esc5_write_aces")
        all_aces   = pki_obj.get("acl_aces", [])

        if write_aces is None:
            # Pre-1.4.0 report: derive write ACEs from full ACE list.
            # Admin SID filtering is handled inside has_non_admin_write().
            write_aces = [a for a in all_aces if _ace_has_write(a)]

        if write_aces:
            non_admin_write, write_sid, write_rights = has_non_admin_write(write_aces)
            if not non_admin_write:
                failed.append(
                    "No non-admin principal has a write right over the PKI object"
                )
        elif all_aces:
            # Full ACE list present but no write rights found at all
            failed.append(
                "No non-admin principal has a write right over the PKI object"
            )
        else:
            # No ACL data at all
            acl_unknown = True
            failed.append("ACL data missing — write rights unconfirmed")

    # Strip the ACL-missing message before returning so it is not counted as a
    # hard failure — mirrors esc4.py logic for acl_unknown handling.
    qualifies = len(failed) == 0
    if acl_unknown and "ACL data missing — write rights unconfirmed" in failed:
        failed.remove("ACL data missing — write rights unconfirmed")

    return qualifies, failed, acl_unknown, write_sid, write_rights


# ── Output ────────────────────────────────────────────────────────────────────

def _templates_str(pki_obj):
    """Return a readable list of published certificate templates or a placeholder."""
    templates = pki_obj.get("certificate_templates") or []
    if not templates:
        return "none / not applicable"
    return ", ".join(str(t) for t in templates)


def print_finding(pki_obj, write_sid, write_rights, acl_unknown=False):
    category   = pki_obj.get("category", "N/A")
    cn         = pki_obj.get("cn", "N/A")
    dn         = pki_obj.get("dn", "N/A")
    dns_host   = pki_obj.get("dns_host_name", "")
    rights_str = ", ".join(write_rights) if write_rights else "N/A"

    print(f"  Category     : {category}")
    print(f"  Object       : {cn}")
    print(f"  DN           : {dn}")
    if dns_host:
        print(f"  CA Host      : {dns_host}")
    if pki_obj.get("category") == "Enrollment Services":
        print(f"  Templates    : {_templates_str(pki_obj)}")
    print(f"  Write SID    : {write_sid or 'N/A'}")
    print(f"  Write Rights : {rights_str}")
    if acl_unknown:
        print(f"  ACL          : [!] Incomplete ACL data — verify manually")


def print_exploit(pki_obj):
    """Print the certipy exploitation steps contextualised for the object type."""
    category = pki_obj.get("category", "")
    cn       = pki_obj.get("cn", "?")
    dns_host = pki_obj.get("dns_host_name", "<CA-HOST>")

    print("  Exploit (certipy):")

    if category == "Enrollment Services":
        templates = pki_obj.get("certificate_templates") or []
        tpl       = templates[0] if templates else "<TEMPLATE>"
        print(f"    # Target: pKIEnrollmentService object — '{cn}'")
        print(f"    # WriteDACL path: self-grant GenericAll first, then modify the template.")
        print(f"    Step 1 — Self-grant GenericAll on the Enrollment Services object:")
        print(f"             $acl = Get-Acl 'AD:\\{cn}'; <add GenericAll ACE>; Set-Acl ...")
        print(f"             (or: dacledit.py -action write -rights FullControl -principal <USER> ...)")
        print(f"    Step 2 — Modify the target template to ESC1-equivalent conditions:")
        print(f"             certipy template ... -template '{tpl}' -save-old")
        print(f"    Step 3 — Request a certificate with a privileged UPN via SAN:")
        print(f"             certipy req     ... -template '{tpl}' \\")
        print( "                 -upn 'administrator@DOMAIN'")
        print( "    Step 4 — certipy auth    ... -pfx administrator.pfx -dc-ip <DC-IP>")
        print(f"    Step 5 — certipy template ... -template '{tpl}' \\")
        print(f"                 -configuration '{tpl}.json'  # restore (optional)")

    elif category == "NTAuthCertificates":
        print(f"    # Target: NTAuthCertificates — CA trust store")
        print(f"    Step 1 — forge or obtain a rogue CA certificate")
        print(f"    Step 2 — write rogue cert to cACertificate attribute of '{cn}'")
        print(f"             ldapmodify / Set-ADObject -Replace @{{cACertificate=...}}")
        print(f"    Step 3 — certipy req     ... -ca '<ROGUE-CA>' -template <NAME> \\")
        print( "                 -upn 'administrator@DOMAIN'")
        print( "    Step 4 — certipy auth    ... -pfx administrator.pfx -dc-ip <DC-IP>")

    elif category == "Certification Authorities":
        print(f"    # Target: Root/Sub CA object — '{cn}'")
        print(f"    Step 1 — obtain or forge a certificate issued by '{cn}'")
        print(f"    Step 2 — certipy req     ... -ca '{cn}' -template <NAME> \\")
        print( "                 -upn 'administrator@DOMAIN'")
        print( "    Step 3 — certipy auth    ... -pfx administrator.pfx -dc-ip <DC-IP>")

    else:
        # AIA / CDP — indirect impact; modify to redirect CRL/CA cert fetching
        print(f"    # Target: {category} object — '{cn}'")
        print(f"    Step 1 — modify '{cn}' to redirect CRL or CA cert fetching")
        print(f"             (WriteDACL path: self-grant GenericAll first)")
        print(f"    Step 2 — combine with another ESC to complete the chain")
        print(f"    Step 3 — manual exploitation — no single certipy command applies")


# ── Main ──────────────────────────────────────────────────────────────────────

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

    pki_objects = report.get("pki_objects", [])

    if not pki_objects:
        print("[!] No PKI object data found in report.")
        print("    Re-run template_enumeration.py >= 1.4.0 to collect ESC5 data.")
        sys.exit(0)

    # ── Classify every PKI object ─────────────────────────────────────────────
    findings_vulnerable = []   # (pki_obj, write_sid, write_rights)
    findings_unknown    = []   # (pki_obj, write_sid, write_rights)
    skipped             = []   # (pki_obj, reasons)

    for obj in pki_objects:
        qualifies, failed, acl_unknown, write_sid, write_rights = \
            check_esc5(obj, skip_acl=args.skip_acl)

        if qualifies:
            findings_vulnerable.append((obj, write_sid, write_rights))
        elif acl_unknown and len(failed) == 0:
            findings_unknown.append((obj, write_sid, write_rights))
        else:
            skipped.append((obj, failed))

    # ── Vulnerable findings ───────────────────────────────────────────────────
    if findings_vulnerable:
        print(f"[!] ESC5 found — {len(findings_vulnerable)} vulnerable PKI object(s)\n")
        print("=" * 60)
        for i, (obj, ws, wr) in enumerate(findings_vulnerable, 1):
            print(f"Finding {i} of {len(findings_vulnerable)}")
            print("-" * 60)
            print_finding(obj, ws, wr, acl_unknown=False)
            print()
            print_exploit(obj)
            print("=" * 60)
    else:
        print("[+] No ESC5 vulnerable PKI objects found.")

    # ── Uncertain findings (ACL data missing) ─────────────────────────────────
    if findings_unknown:
        print(
            f"\n[?] {len(findings_unknown)} uncertain PKI object(s) — "
            f"ACL data incomplete (verify manually):\n"
        )
        print("=" * 60)
        for i, (obj, ws, wr) in enumerate(findings_unknown, 1):
            print(f"Finding {i} of {len(findings_unknown)}")
            print("-" * 60)
            print_finding(obj, ws, wr, acl_unknown=True)
            print()
            print_exploit(obj)
            print("=" * 60)

    # ── Verbose skip ──────────────────────────────────────────────────────────
    if args.verbose_skip:
        if skipped:
            print(f"\n[*] PKI objects that did not qualify ({len(skipped)}):")
            for obj, reasons in skipped:
                label = f"{obj.get('category', '?')} / {obj.get('cn', '?')}"
                print(f"  - {label}: {'; '.join(sorted(reasons))}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print(
        f"[*] {len(pki_objects)} PKI objects checked  |  "
        f"{len(findings_vulnerable)} vulnerable  |  "
        f"{len(findings_unknown)} uncertain  |  "
        f"{len(skipped)} clean"
    )


if __name__ == "__main__":
    main()