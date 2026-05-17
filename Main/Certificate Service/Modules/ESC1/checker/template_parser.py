"""
template_parser.py
Analyse raw TemplateEntry attributes to determine ESC1 conditions.
Produces a TemplateAnalysis with a structured verdict per condition.
"""

from dataclasses import dataclass, field
from typing import Optional
from .ldap_client import TemplateEntry


# ── ESC1-relevant flag constants ──────────────────────────────

# msPKI-Certificate-Name-Flag
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT         = 0x00000001
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000

# msPKI-Enrollment-Flag
CT_FLAG_NO_SECURITY_EXTENSION = 0x80000

# EKUs that make a certificate usable for authentication
DANGEROUS_EKUS: dict[str, str] = {
    "1.3.6.1.5.5.7.3.2":       "Client Authentication",
    "1.3.6.1.5.5.7.3.9":       "PKINIT Client Auth",
    "1.3.6.1.4.1.311.20.2.2":  "Smart Card Logon",
    "2.5.29.37.0":              "Any Purpose",
    "1.3.6.1.4.1.311.10.12.1": "Any Purpose (MS)",
}

# If the template has no EKU at all it is also dangerous
NO_EKU_LABEL = "No EKU (unrestricted)"


# ── Result dataclasses ────────────────────────────────────────
@dataclass
class Condition:
    """Represents a single ESC1 condition check."""
    name:    str
    passed:  bool           # True = condition met (moves toward vulnerable)
    detail:  str            # Human-readable explanation


@dataclass
class TemplateAnalysis:
    template_name:  str
    display_name:   str
    conditions:     list[Condition] = field(default_factory=list)
    dangerous_ekus: list[str]       = field(default_factory=list)
    is_vulnerable:  bool            = False
    risk_notes:     list[str]       = field(default_factory=list)

    # Raw values kept for the reporter
    name_flag:       int = 0
    enrollment_flag: int = 0
    ra_signature:    int = 0


# ── TemplateParser ────────────────────────────────────────────
class TemplateParser:
    """
    Evaluate a TemplateEntry against the four ESC1 conditions.

    Conditions (all must be True for ESC1 to apply):
        C1 — CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is set in msPKI-Certificate-Name-Flag
        C2 — Template contains at least one authentication-capable EKU
        C3 — msPKI-RA-Signature == 0  (no manager approval required)
        C4 — Template is published to at least one CA
             (checked externally in esc1_checker; flagged as a note here)

    ACL check (C5 — who can enroll) is handled by acl_parser.py.
    """

    def analyse(
        self,
        template: TemplateEntry,
        published_on: Optional[list[str]] = None,
    ) -> TemplateAnalysis:
        """
        Run all ESC1 condition checks on a single TemplateEntry.

        Args:
            template:     TemplateEntry from ldap_client.
            published_on: List of CA names that publish this template.
                          Pass None if publication status is unknown.

        Returns:
            TemplateAnalysis with is_vulnerable set accordingly.
        """
        analysis = TemplateAnalysis(
            template_name=template.cn,
            display_name=template.display_name,
            name_flag=template.name_flag,
            enrollment_flag=template.enrollment_flag,
            ra_signature=template.ra_signature,
        )

        c1 = self._check_name_flag(template)
        c2 = self._check_ekus(template, analysis)
        c3 = self._check_approval(template)
        c4 = self._check_publication(template, published_on)

        analysis.conditions = [c1, c2, c3, c4]

        # ESC1 requires C1 + C2 + C3.
        # C4 (publication) is a strong additional indicator but not gating —
        # an unpublished template could still be enabled later.
        analysis.is_vulnerable = c1.passed and c2.passed and c3.passed

        self._add_risk_notes(analysis, template, published_on)

        return analysis

    # ── Condition Checks ──────────────────────────────────────
    @staticmethod
    def _check_name_flag(t: TemplateEntry) -> Condition:
        """
        C1: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT must be set.
        This is the core ESC1 flag — it lets the requester specify
        an arbitrary Subject Alternative Name (SAN).
        """
        flag_set = bool(t.name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
        also_san = bool(t.name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)

        if flag_set:
            detail = (
                f"CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is SET "
                f"(msPKI-Certificate-Name-Flag = 0x{t.name_flag:08X}). "
                "Requester can supply an arbitrary SAN."
            )
            if also_san:
                detail += " ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME is also set."
        else:
            detail = (
                f"CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT is NOT set "
                f"(msPKI-Certificate-Name-Flag = 0x{t.name_flag:08X})."
            )

        return Condition(
            name="ENROLLEE_SUPPLIES_SUBJECT flag",
            passed=flag_set,
            detail=detail,
        )

    @staticmethod
    def _check_ekus(t: TemplateEntry, analysis: TemplateAnalysis) -> Condition:
        """
        C2: Template must include at least one authentication EKU.
        Combines pKIExtendedKeyUsage and msPKI-Certificate-Application-Policy.
        """
        all_oids = set(t.ekus) | set(t.app_policies)
        found: list[str] = []

        # No EKU at all → unrestricted, equally dangerous
        if not all_oids:
            found.append(NO_EKU_LABEL)
        else:
            for oid, label in DANGEROUS_EKUS.items():
                if oid in all_oids:
                    found.append(f"{label} ({oid})")

        analysis.dangerous_ekus = found

        if found:
            detail = "Authentication-capable EKU(s) present: " + ", ".join(found)
        else:
            detail = (
                "No authentication-capable EKU found. "
                f"EKUs: {', '.join(all_oids) or 'none'}"
            )

        return Condition(
            name="Authentication EKU present",
            passed=bool(found),
            detail=detail,
        )

    @staticmethod
    def _check_approval(t: TemplateEntry) -> Condition:
        """
        C3: msPKI-RA-Signature must be 0 (no manager approval required).
        If approval is required an attacker cannot self-enroll without
        a CA manager countersigning the request.
        """
        no_approval = t.ra_signature == 0

        if no_approval:
            detail = "Manager approval is NOT required (msPKI-RA-Signature = 0)."
        else:
            detail = (
                f"Manager approval IS required "
                f"(msPKI-RA-Signature = {t.ra_signature}). "
                "Self-enrollment is blocked without a countersignature."
            )

        return Condition(
            name="No manager approval required",
            passed=no_approval,
            detail=detail,
        )

    @staticmethod
    def _check_publication(
        t: TemplateEntry,
        published_on: Optional[list[str]],
    ) -> Condition:
        """
        C4: Template should be published on at least one CA.
        An unpublished template cannot be enrolled against directly,
        but may be enabled by an attacker who has write access to a CA.
        """
        if published_on is None:
            return Condition(
                name="Published on CA",
                passed=False,
                detail="Publication status unknown (no CA data supplied).",
            )

        if published_on:
            detail = "Published on CA(s): " + ", ".join(published_on)
            passed = True
        else:
            detail = (
                "Template is NOT published on any CA. "
                "Direct enrollment is not possible in current state."
            )
            passed = False

        return Condition(name="Published on CA", passed=passed, detail=detail)

    # ── Risk Notes ────────────────────────────────────────────
    @staticmethod
    def _add_risk_notes(
        analysis: TemplateAnalysis,
        t: TemplateEntry,
        published_on: Optional[list[str]],
    ) -> None:
        notes: list[str] = []

        if analysis.is_vulnerable:
            notes.append(
                "CRITICAL: An attacker with Enroll rights can request a certificate "
                "with an arbitrary SAN (e.g. Administrator@corp.local) and use it "
                "for PKINIT Kerberos authentication → Domain Admin takeover."
            )

        if not analysis.is_vulnerable and (
            bool(t.name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) and
            not bool(t.ra_signature == 0)
        ):
            notes.append(
                "Template has ENROLLEE_SUPPLIES_SUBJECT set but manager approval "
                "is required. If approval is removed this becomes ESC1-vulnerable."
            )

        if t.enrollment_flag & CT_FLAG_NO_SECURITY_EXTENSION:
            notes.append(
                "msPKI-Enrollment-Flag has NO_SECURITY_EXTENSION set — "
                "related to ESC9 (weak binding enforcement)."
            )

        if t.min_key_size < 2048:
            notes.append(
                f"Minimum key size is {t.min_key_size} bits — below recommended 2048."
            )

        if published_on is not None and not published_on and analysis.is_vulnerable:
            notes.append(
                "Template is not currently published but conditions are met. "
                "An attacker with CA write access could publish and exploit it."
            )

        analysis.risk_notes = notes