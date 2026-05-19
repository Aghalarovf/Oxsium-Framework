#!/usr/bin/env python3
"""
esc3.py — ESC3 vulnerability checker for oxs_cert JSON reports.
Usage: python3 esc3.py -f oxs_cert_XXXXXXXX.json

ESC3 requires TWO templates that work together as a pair:

  Condition 1 — Enrollment Agent template (ALL must be true):
    1. Template is NOT a CA template         (is_ca == False)
    2. Template is NOT a machine type        (is_machine_type == False)
    3. Certificate Request Agent EKU present (1.3.6.1.4.1.311.20.2.1)
       — checked in both pKIExtendedKeyUsage and
         msPKI-Certificate-Application-Policy
    4. msPKI-RA-Signature == 0               (no prior agent cert required)
    5. Manager approval is NOT required      (no CT_FLAG_PEND_ALL_REQUESTS)
    6. At least one non-admin principal has Enroll right (ACL check)

  Condition 2 — On-Behalf-Of target template (ALL must be true):
    1. Template is NOT a CA template         (is_ca == False)
    2. Template is NOT a machine type        (is_machine_type == False)
    3. Client Authentication EKU present
       (1.3.6.1.5.5.7.3.2  or  Any Purpose 2.5.29.37.0  or  no EKU)
    4. msPKI-RA-Signature >= 1               (enrollment agent cert required)
    5. Manager approval is NOT required      (no CT_FLAG_PEND_ALL_REQUESTS)
    6. At least one non-admin principal has Enroll right (ACL check)
    7. msPKI-RA-Application-Policies accepts a Certificate Request Agent cert
       — empty policies  → any agent cert is accepted
       — 1.3.6.1.4.1.311.20.2.1 in policies → explicitly requires Request Agent

  Pair matching:
    A Condition 1 template is paired with a Condition 2 template only when
    the Condition 1 cert satisfies the Condition 2 RA policy requirement.
    A single Condition 1 template may pair with multiple Condition 2 templates.
    Only matched pairs are reported as exploitable.

  ACL unknown:
    If ACL data is missing for either template in a pair, the pair is flagged
    UNKNOWN (not vulnerable) — both templates must pass the ACL check.

Exploitation flow:
  Step 1 — Enroll in Condition 1 template → get enrollment agent cert
  Step 2 — Use agent cert with --on-behalf-of to enroll in Condition 2
           template as a privileged user (e.g. Domain Admin)
  Step 3 — Authenticate with the resulting cert → NT Hash / TGT

Requires template_enumeration.py >= 1.3.0 with all ESC fixes applied:
  parsed["ra_signature"]                       — integer (Fix 1)
  parsed["eku_is_empty"]                       — True when EKU is null/[] (Fix 2)
  parsed["eku_is_any_purpose"]                 — True when 2.5.29.37.0 in EKU (Fix 2)
  parsed["app_policy_any_purpose"]             — True when 2.5.29.37.0 in App Policy (Fix 3)
  parsed["app_policy_eku_mismatch"]            — True when App Policy != EKU set (Fix 3)
  parsed["ra_app_policies_friendly"]           — decoded RA policy list (Fix 4)
  parsed["ra_app_policies_is_empty"]           — True when RA policies are empty (Fix 4)
  parsed["ra_app_policies_requires_request_agent"] — True when Cond1 cert satisfies (Fix 4)
"""

import argparse
import json
import sys

# ── OIDs ─────────────────────────────────────────────────────────────────────

REQUEST_AGENT_OID = "1.3.6.1.4.1.311.20.2.1"   # Certificate Request Agent

CLIENT_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",   # Client Authentication
    "2.5.29.37.0",          # Any Purpose (explicit OID)
}

# ── Known admin-only SIDs (mirrored from esc1.py / esc2.py) ──────────────────

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
        description="ESC3 checker for oxs_cert JSON reports",
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


def has_non_admin_enroll(aces):
    """Returns (True, sid) if at least one non-admin has Enroll right.

    Deny ACEs are evaluated first — an explicit Deny for a SID cancels
    any Allow for the same SID, matching AD's ACE evaluation order.
    """
    denied_sids = set()
    for ace in aces:
        if ace.get("type") != "Deny":
            continue
        sid  = ace.get("sid", "")
        mask = ace.get("mask", "0x0")
        try:
            mask_int = int(mask, 16)
        except (ValueError, TypeError):
            mask_int = 0
        if ace.get("right") == "Enroll" or (mask_int & 0x100) or (mask_int & 0x10000000):
            denied_sids.add(sid)

    for ace in aces:
        if ace.get("type") != "Allow":
            continue
        sid  = ace.get("sid", "")
        mask = ace.get("mask", "0x0")
        try:
            mask_int = int(mask, 16)
        except (ValueError, TypeError):
            mask_int = 0

        has_enroll = (
            ace.get("right") == "Enroll" or
            (mask_int & 0x100) or
            (mask_int & 0x10000000)
        )
        if has_enroll and not is_admin_sid(sid) and sid not in denied_sids:
            return True, sid

    return False, None


def _get_ra_sig(template):
    """Return msPKI-RA-Signature as int. Prefers parsed integer (Fix 1),
    falls back to raw string for pre-fix reports."""
    parsed = template.get("parsed", {})
    raw    = template.get("raw", {})

    ra_parsed = parsed.get("ra_signature")
    if ra_parsed is not None:
        return ra_parsed
    ra_raw = raw.get("msPKI-RA-Signature")
    try:
        return int(ra_raw) if ra_raw is not None else None
    except (TypeError, ValueError):
        return None


def _has_request_agent_eku(template):
    """True if the template carries the Certificate Request Agent EKU in
    either pKIExtendedKeyUsage or msPKI-Certificate-Application-Policy."""
    parsed = template.get("parsed", {})
    raw    = template.get("raw", {})

    # Prefer decoded friendly list (always populated by enumerator >= 1.3.0)
    for entry in parsed.get("eku_friendly", []):
        if entry.get("oid") == REQUEST_AGENT_OID:
            return True
    for entry in parsed.get("application_policies_friendly", []):
        if entry.get("oid") == REQUEST_AGENT_OID:
            return True

    # Fallback for older reports: inspect raw fields directly
    ekus_raw = raw.get("pKIExtendedKeyUsage") or []
    if isinstance(ekus_raw, str):
        ekus_raw = [ekus_raw]
    app_raw = raw.get("msPKI-Certificate-Application-Policy") or []
    if isinstance(app_raw, str):
        app_raw = [app_raw]
    return REQUEST_AGENT_OID in ekus_raw or REQUEST_AGENT_OID in app_raw


def _has_client_auth_eku(template):
    """True if the template carries a Client Authentication-compatible EKU.
    Empty EKU (Any Purpose) satisfies this after CA / machine filters pass."""
    parsed = template.get("parsed", {})
    raw    = template.get("raw", {})

    # Use the pre-computed flags from Fix 2/3 when available
    if parsed.get("eku_is_empty") or parsed.get("eku_is_any_purpose") or \
       parsed.get("app_policy_any_purpose"):
        return True

    # Fallback: raw OID intersection
    ekus_raw = raw.get("pKIExtendedKeyUsage") or []
    if isinstance(ekus_raw, str):
        ekus_raw = [ekus_raw]
    app_raw = raw.get("msPKI-Certificate-Application-Policy") or []
    if isinstance(app_raw, str):
        app_raw = [app_raw]
    all_oids = set(ekus_raw) | set(app_raw)
    no_eku   = not ekus_raw and not app_raw
    return bool(all_oids & CLIENT_AUTH_EKUS) or no_eku


def _cond2_accepts_request_agent(template):
    """True if a Condition 2 template's RA Application Policy can be satisfied
    by a Certificate Request Agent cert (i.e. a Condition 1 cert).

    Uses the pre-computed flag from Fix 4 when available.
    Falls back to raw msPKI-RA-Application-Policies for older reports."""
    parsed = template.get("parsed", {})
    raw    = template.get("raw", {})

    flag = parsed.get("ra_app_policies_requires_request_agent")
    if flag is not None:
        return flag

    # Fallback for reports generated before Fix 4
    ra_app = raw.get("msPKI-RA-Application-Policies") or []
    if isinstance(ra_app, str):
        ra_app = [ra_app]
    # Empty → any agent cert accepted; explicit OID → must match
    return len(ra_app) == 0 or REQUEST_AGENT_OID in ra_app


# ── Core ESC3 checks ──────────────────────────────────────────────────────────

def check_cond1(template, skip_acl=False):
    """
    Returns (qualifies, reasons_failed, acl_unknown, enroll_sid)

    qualifies=True  → template is a valid Condition 1 (Enrollment Agent) candidate
    acl_unknown=True → all conditions passed but ACL data was missing
    """
    raw    = template.get("raw", {})
    parsed = template.get("parsed", {})

    failed      = []
    acl_unknown = False

    # ── Filter 1: CA templates ────────────────────────────────────────────────
    if parsed.get("is_ca", False):
        failed.append("CA template (is_ca=True)")
        return False, failed, acl_unknown, None

    # ── Filter 2: Machine-type templates ─────────────────────────────────────
    if parsed.get("is_machine_type", False):
        failed.append("Machine-type template (is_machine_type=True)")
        return False, failed, acl_unknown, None

    # ── Condition 1: Certificate Request Agent EKU ───────────────────────────
    if not _has_request_agent_eku(template):
        ekus = parsed.get("eku_friendly", [])
        found = ", ".join(e["name"] + " (" + e["oid"] + ")" for e in ekus) or "none"
        failed.append(f"No Certificate Request Agent EKU (found: {found})")

    # ── Condition 2: msPKI-RA-Signature must be 0 ────────────────────────────
    # A non-zero value means this template itself requires a prior agent cert,
    # which makes it a Condition 2 candidate — not a Condition 1 source.
    ra_sig = _get_ra_sig(template)
    if ra_sig is None or ra_sig != 0:
        failed.append(f"msPKI-RA-Signature is not 0 (value: {ra_sig})")

    # ── Condition 3: No manager approval ─────────────────────────────────────
    enroll_flags = parsed.get("enrollment_flags_decoded", [])
    if "CT_FLAG_PEND_ALL_REQUESTS" in enroll_flags:
        failed.append("Manager approval required (CT_FLAG_PEND_ALL_REQUESTS)")

    # ── Condition 4: Non-admin has Enroll right ───────────────────────────────
    enroll_sid = None
    if not skip_acl:
        aces = parsed.get("acl_enrollment_aces", [])
        if aces:
            non_admin_enroll, enroll_sid = has_non_admin_enroll(aces)
            if not non_admin_enroll:
                failed.append("No non-admin principal has Enroll right")
        else:
            acl_unknown = True
            failed.append("ACL data missing — enrollability unconfirmed")

    qualifies = len(failed) == 0
    if acl_unknown and "ACL data missing — enrollability unconfirmed" in failed:
        failed.remove("ACL data missing — enrollability unconfirmed")

    return qualifies, failed, acl_unknown, enroll_sid


def check_cond2(template, skip_acl=False):
    """
    Returns (qualifies, reasons_failed, acl_unknown, enroll_sid)

    qualifies=True  → template is a valid Condition 2 (on-behalf-of target) candidate
    acl_unknown=True → all conditions passed but ACL data was missing
    """
    raw    = template.get("raw", {})
    parsed = template.get("parsed", {})

    failed      = []
    acl_unknown = False

    # ── Filter 1: CA templates ────────────────────────────────────────────────
    if parsed.get("is_ca", False):
        failed.append("CA template (is_ca=True)")
        return False, failed, acl_unknown, None

    # ── Filter 2: Machine-type templates ─────────────────────────────────────
    if parsed.get("is_machine_type", False):
        failed.append("Machine-type template (is_machine_type=True)")
        return False, failed, acl_unknown, None

    # ── Condition 1: msPKI-RA-Signature >= 1 ─────────────────────────────────
    # This is the defining characteristic of a Condition 2 template —
    # it requires an enrollment agent cert to enroll on behalf of someone.
    ra_sig = _get_ra_sig(template)
    if ra_sig is None or ra_sig < 1:
        failed.append(f"msPKI-RA-Signature is not >= 1 (value: {ra_sig})")

    # ── Condition 2: Client Authentication EKU ───────────────────────────────
    if not _has_client_auth_eku(template):
        ekus = parsed.get("eku_friendly", [])
        found = ", ".join(e["name"] + " (" + e["oid"] + ")" for e in ekus) or "none"
        failed.append(f"No Client Authentication EKU (found: {found})")

    # ── Condition 3: No manager approval ─────────────────────────────────────
    enroll_flags = parsed.get("enrollment_flags_decoded", [])
    if "CT_FLAG_PEND_ALL_REQUESTS" in enroll_flags:
        failed.append("Manager approval required (CT_FLAG_PEND_ALL_REQUESTS)")

    # ── Condition 4: RA Application Policy accepts Request Agent cert ─────────
    # Even if all other conditions pass, if the CA only accepts a different
    # agent EKU, a Condition 1 cert cannot be used with this template.
    if not _cond2_accepts_request_agent(template):
        ra_pol = parsed.get("ra_app_policies_friendly", [])
        pol_str = ", ".join(e["name"] + " (" + e["oid"] + ")" for e in ra_pol) or "none"
        failed.append(
            f"RA Application Policy rejects Certificate Request Agent certs "
            f"(required: {pol_str})"
        )

    # ── Condition 5: Non-admin has Enroll right ───────────────────────────────
    enroll_sid = None
    if not skip_acl:
        aces = parsed.get("acl_enrollment_aces", [])
        if aces:
            non_admin_enroll, enroll_sid = has_non_admin_enroll(aces)
            if not non_admin_enroll:
                failed.append("No non-admin principal has Enroll right")
        else:
            acl_unknown = True
            failed.append("ACL data missing — enrollability unconfirmed")

    qualifies = len(failed) == 0
    if acl_unknown and "ACL data missing — enrollability unconfirmed" in failed:
        failed.remove("ACL data missing — enrollability unconfirmed")

    return qualifies, failed, acl_unknown, enroll_sid


# ── Pair matching ─────────────────────────────────────────────────────────────

def pair_conditions(cond1_list, cond2_list):
    """
    Match every qualifying Condition 1 template against every qualifying
    Condition 2 template. Returns a list of (cond1_entry, cond2_entry) pairs.

    cond1_list entries: (template, enroll_sid, acl_unknown)
    cond2_list entries: (template, enroll_sid, acl_unknown)

    A pair is only returned when BOTH templates passed the ACL check, or
    both have acl_unknown=True (reported separately as uncertain pairs).

    Cross-ACL-state pairs (one known, one unknown) are treated as uncertain.
    """
    pairs_vulnerable = []
    pairs_unknown    = []

    for c1_t, c1_sid, c1_unk in cond1_list:
        for c2_t, c2_sid, c2_unk in cond2_list:
            # Avoid pairing a template with itself in case of overlap
            if c1_t.get("dn") == c2_t.get("dn"):
                continue

            either_unknown = c1_unk or c2_unk
            if either_unknown:
                pairs_unknown.append((c1_t, c1_sid, c2_t, c2_sid))
            else:
                pairs_vulnerable.append((c1_t, c1_sid, c2_t, c2_sid))

    return pairs_vulnerable, pairs_unknown


# ── Output ────────────────────────────────────────────────────────────────────

def _eku_str(template):
    parsed = template.get("parsed", {})
    ekus   = parsed.get("eku_friendly", [])
    if parsed.get("eku_is_empty", not ekus):
        return "none (Any Purpose — empty EKU)"
    return ", ".join(e["name"] + " (" + e["oid"] + ")" for e in ekus)


def _ra_sig_str(template):
    parsed = template.get("parsed", {})
    raw    = template.get("raw", {})
    ra     = parsed.get("ra_signature")
    if ra is None:
        ra = raw.get("msPKI-RA-Signature", "N/A")
    return str(ra)


def print_cond1(template, enroll_sid=None, acl_unknown=False):
    raw    = template.get("raw", {})
    parsed = template.get("parsed", {})

    cn           = raw.get("cn", "N/A")
    display_name = raw.get("displayName", "N/A")
    dn           = template.get("dn", "N/A")
    schema_ver   = raw.get("msPKI-Template-Schema-Version", "N/A")
    validity     = parsed.get("validity_period", "unknown")
    enroll_flags = parsed.get("enrollment_flags_decoded", [])

    print(f"  [Cond 1] Template  : {cn} ({display_name})")
    print(f"           DN        : {dn}")
    print(f"           Schema    : {schema_ver}  |  Validity: {validity}")
    print(f"           EKU       : {_eku_str(template)}")
    print(f"           RA Sig    : {_ra_sig_str(template)}")
    print(f"           Enroll Fl : {', '.join(enroll_flags) if enroll_flags else 'none'}")
    if enroll_sid:
        print(f"           Enroll SID: {enroll_sid}")
    if acl_unknown:
        print(f"           ACL       : [!] No ACL data — verify manually")


def print_cond2(template, enroll_sid=None, acl_unknown=False):
    raw    = template.get("raw", {})
    parsed = template.get("parsed", {})

    cn           = raw.get("cn", "N/A")
    display_name = raw.get("displayName", "N/A")
    dn           = template.get("dn", "N/A")
    schema_ver   = raw.get("msPKI-Template-Schema-Version", "N/A")
    validity     = parsed.get("validity_period", "unknown")
    enroll_flags = parsed.get("enrollment_flags_decoded", [])

    ra_pol       = parsed.get("ra_app_policies_friendly", [])
    ra_pol_str   = (
        "any (empty)" if parsed.get("ra_app_policies_is_empty", not ra_pol)
        else ", ".join(e["name"] + " (" + e["oid"] + ")" for e in ra_pol)
    )
    app_mismatch = parsed.get("app_policy_eku_mismatch", False)

    print(f"  [Cond 2] Template  : {cn} ({display_name})")
    print(f"           DN        : {dn}")
    print(f"           Schema    : {schema_ver}  |  Validity: {validity}")
    print(f"           EKU       : {_eku_str(template)}")
    print(f"           RA Sig    : {_ra_sig_str(template)}")
    print(f"           RA Policy : {ra_pol_str}")
    print(f"           Enroll Fl : {', '.join(enroll_flags) if enroll_flags else 'none'}")
    if app_mismatch:
        app_pol = parsed.get("application_policies_friendly", [])
        app_str = ", ".join(e["name"] + " (" + e["oid"] + ")" for e in app_pol) or "none"
        print(f"           App Policy: {app_str}  [!] differs from EKU — CA uses App Policy")
    if enroll_sid:
        print(f"           Enroll SID: {enroll_sid}")
    if acl_unknown:
        print(f"           ACL       : [!] No ACL data — verify manually")


def print_pair(c1_t, c1_sid, c2_t, c2_sid, c1_unk=False, c2_unk=False):
    c1_cn = c1_t.get("raw", {}).get("cn", "?")
    c2_cn = c2_t.get("raw", {}).get("cn", "?")
    print(f"Pair  :  [{c1_cn}]  →  [{c2_cn}]")
    print()
    print_cond1(c1_t, enroll_sid=c1_sid, acl_unknown=c1_unk)
    print()
    print_cond2(c2_t, enroll_sid=c2_sid, acl_unknown=c2_unk)
    print()
    print("  Exploit:")
    print(f"    Step 1 — certipy req ... -template '{c1_cn}'")
    print(f"    Step 2 — certipy req ... -template '{c2_cn}' \\")
    print( "                -on-behalf-of 'DOMAIN\\administrator' \\")
    print(f"                -pfx {c1_cn.lower().replace(' ', '_')}.pfx")
    print( "    Step 3 — certipy auth -pfx administrator.pfx -dc-ip <DC-IP>")


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

    templates = report.get("templates", [])

    # ── Pass 1: classify every template ──────────────────────────────────────
    cond1_pass    = []   # (template, enroll_sid, acl_unknown)
    cond2_pass    = []   # (template, enroll_sid, acl_unknown)
    cond1_skipped = []   # (template, reasons)
    cond2_skipped = []   # (template, reasons)

    for t in templates:
        q1, f1, u1, s1 = check_cond1(t, skip_acl=args.skip_acl)
        if q1 or (u1 and len(f1) == 0):
            cond1_pass.append((t, s1, u1))
        else:
            cond1_skipped.append((t, f1))

        q2, f2, u2, s2 = check_cond2(t, skip_acl=args.skip_acl)
        if q2 or (u2 and len(f2) == 0):
            cond2_pass.append((t, s2, u2))
        else:
            cond2_skipped.append((t, f2))

    # ── Pass 2: pair matching ─────────────────────────────────────────────────
    pairs_vulnerable, pairs_unknown = pair_conditions(cond1_pass, cond2_pass)

    # ── Vulnerable pairs ──────────────────────────────────────────────────────
    if pairs_vulnerable:
        print(f"[!] ESC3 found — {len(pairs_vulnerable)} exploitable pair(s)\n")
        print("=" * 60)
        for i, (c1_t, c1_sid, c2_t, c2_sid) in enumerate(pairs_vulnerable, 1):
            print(f"Pair {i} of {len(pairs_vulnerable)}")
            print("-" * 60)
            print_pair(c1_t, c1_sid, c2_t, c2_sid)
            print("=" * 60)
    else:
        print("[+] No ESC3 vulnerable pairs found.")

    # ── Uncertain pairs (ACL unknown on either side) ──────────────────────────
    if pairs_unknown:
        print(
            f"\n[?] {len(pairs_unknown)} uncertain pair(s) — all conditions met "
            f"but ACL unverified on one or both templates (check manually):\n"
        )
        print("=" * 60)
        for i, (c1_t, c1_sid, c2_t, c2_sid) in enumerate(pairs_unknown, 1):
            c1_unk = next(
                (u for t, s, u in cond1_pass if t.get("dn") == c1_t.get("dn")), False
            )
            c2_unk = next(
                (u for t, s, u in cond2_pass if t.get("dn") == c2_t.get("dn")), False
            )
            print(f"Pair {i} of {len(pairs_unknown)}")
            print("-" * 60)
            print_pair(c1_t, c1_sid, c2_t, c2_sid, c1_unk=c1_unk, c2_unk=c2_unk)
            print("=" * 60)

    # ── Verbose skip ──────────────────────────────────────────────────────────
    if args.verbose_skip:
        unique_skipped = {}
        for t, reasons in cond1_skipped + cond2_skipped:
            dn = t.get("dn", "?")
            if dn not in unique_skipped:
                cn = t.get("raw", {}).get("cn", "?")
                unique_skipped[dn] = (cn, set())
            unique_skipped[dn][1].update(reasons)

        if unique_skipped:
            print(f"\n[*] Templates that did not qualify for either condition "
                  f"({len(unique_skipped)}):")
            for dn, (cn, reasons) in unique_skipped.items():
                print(f"  - {cn}: {'; '.join(sorted(reasons))}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print(
        f"[*] {len(templates)} templates checked  |  "
        f"{len(cond1_pass)} Cond1 candidates  |  "
        f"{len(cond2_pass)} Cond2 candidates  |  "
        f"{len(pairs_vulnerable)} vulnerable pairs  |  "
        f"{len(pairs_unknown)} uncertain pairs"
    )


if __name__ == "__main__":
    main()