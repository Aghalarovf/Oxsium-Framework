"""
acl_parser.py
Parse the raw nTSecurityDescriptor from a certificate template to
determine which principals hold Enroll or AutoEnroll rights.

Requires: impacket  (pip install impacket)
"""

from dataclasses import dataclass
from typing import Optional

try:
    from impacket.ldap.ldaptypes import (
        SR_SECURITY_DESCRIPTOR,
        ACCESS_ALLOWED_ACE,
        ACCESS_ALLOWED_OBJECT_ACE,
    )
except ImportError:
    raise ImportError("impacket is not installed: pip install impacket")


# ── Certificate enrollment right GUIDs ───────────────────────
# These are the object-type GUIDs that grant enroll/autoenroll.
ENROLL_GUID      = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTOENROLL_GUID  = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"

# Standard AD access mask bits
GENERIC_ALL         = 0x000F01FF
GENERIC_WRITE       = 0x00040000
WRITE_DACL          = 0x00040000
WRITE_OWNER         = 0x00080000

# Well-known SID → friendly name mapping
WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-1-0":        "Everyone",
    "S-1-5-11":       "Authenticated Users",
    "S-1-5-32-544":   "BUILTIN\\Administrators",
    "S-1-5-32-545":   "BUILTIN\\Users",
    "S-1-5-32-546":   "BUILTIN\\Guests",
    "S-1-5-18":       "SYSTEM",
    "S-1-5-9":        "Enterprise Domain Controllers",
    # Domain-relative (last sub-authority)
    "-512":           "Domain Admins",
    "-513":           "Domain Users",
    "-515":           "Domain Computers",
    "-516":           "Domain Controllers",
    "-519":           "Enterprise Admins",
    "-520":           "Group Policy Creator Owners",
    "-553":           "RAS and IAS Servers",
}

# SIDs considered dangerous when they can enroll
HIGH_RISK_SIDS = {
    "S-1-1-0",    # Everyone
    "S-1-5-11",   # Authenticated Users
    # Domain Users and Domain Computers identified by last sub-authority
}
HIGH_RISK_SUFFIXES = {"-513", "-515"}   # Domain Users, Domain Computers


# ── Result dataclasses ────────────────────────────────────────
@dataclass
class ACLEntry:
    sid:         str
    sid_label:   str          # friendly name or raw SID
    rights:      list[str]    # e.g. ["Enroll", "AutoEnroll"] or ["GenericAll"]
    is_high_risk: bool        # True if this is a broad/dangerous principal


@dataclass
class ACLAnalysis:
    enroll_principals:    list[ACLEntry]   # principals with Enroll right
    high_risk_principals: list[ACLEntry]   # subset that are broad/dangerous
    parse_error:          Optional[str] = None


# ── ACLParser ─────────────────────────────────────────────────
class ACLParser:
    """
    Parse a raw nTSecurityDescriptor byte string and extract
    which principals can enroll against the template.

    Usage:
        parser   = ACLParser()
        analysis = parser.parse(template.raw_sd)
    """

    def parse(self, raw_sd: Optional[bytes]) -> ACLAnalysis:
        if not raw_sd:
            return ACLAnalysis(
                enroll_principals=[],
                high_risk_principals=[],
                parse_error="No security descriptor available.",
            )

        try:
            sd = SR_SECURITY_DESCRIPTOR()
            sd.fromString(raw_sd)
            return self._analyse_dacl(sd)
        except Exception as exc:
            return ACLAnalysis(
                enroll_principals=[],
                high_risk_principals=[],
                parse_error=f"Failed to parse security descriptor: {exc}",
            )

    # ── Internal ──────────────────────────────────────────────
    def _analyse_dacl(self, sd: SR_SECURITY_DESCRIPTOR) -> ACLAnalysis:
        dacl = sd["Dacl"]
        if not dacl:
            return ACLAnalysis(
                enroll_principals=[],
                high_risk_principals=[],
                parse_error="DACL is empty or null.",
            )

        enroll_entries: list[ACLEntry] = []

        for ace in dacl.aces:
            ace_type = ace["TypeName"]

            # We only care about allow ACEs
            if ace_type not in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"):
                continue

            sid   = ace["Ace"]["Sid"].formatCanonical()
            mask  = ace["Ace"]["Mask"]["Mask"]
            label = self._sid_label(sid)
            rights: list[str] = []

            if ace_type == "ACCESS_ALLOWED_OBJECT_ACE":
                object_type = self._object_type_guid(ace)
                if object_type == ENROLL_GUID:
                    rights.append("Enroll")
                elif object_type == AUTOENROLL_GUID:
                    rights.append("AutoEnroll")
                # Object ACE with no matching GUID — skip
                if not rights:
                    continue
            else:
                # Plain ACCESS_ALLOWED_ACE — check broad masks
                if mask & GENERIC_ALL:
                    rights.append("GenericAll")
                if mask & GENERIC_WRITE:
                    rights.append("GenericWrite")
                # Plain ACEs don't grant certificate-specific rights
                # unless paired with broad masks — include only if broad
                if not rights:
                    continue

            entry = ACLEntry(
                sid=sid,
                sid_label=label,
                rights=rights,
                is_high_risk=self._is_high_risk(sid),
            )
            enroll_entries.append(entry)

        high_risk = [e for e in enroll_entries if e.is_high_risk]

        return ACLAnalysis(
            enroll_principals=enroll_entries,
            high_risk_principals=high_risk,
        )

    # ── Helpers ───────────────────────────────────────────────
    @staticmethod
    def _object_type_guid(ace) -> Optional[str]:
        """Extract the ObjectType GUID from an OBJECT ACE as a lowercase string."""
        try:
            flags = ace["Ace"]["Flags"]
            if flags & 0x01:   # ACE_OBJECT_TYPE_PRESENT
                guid_bytes = ace["Ace"]["ObjectType"]
                # impacket stores as bytes — convert to standard GUID string
                import uuid
                return str(uuid.UUID(bytes_le=bytes(guid_bytes))).lower()
        except Exception:
            pass
        return None

    @staticmethod
    def _sid_label(sid: str) -> str:
        """Return a friendly name for a SID if known, otherwise return the SID."""
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]
        # Check domain-relative suffix (last sub-authority)
        suffix = "-" + sid.split("-")[-1]
        if suffix in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[suffix]
        return sid

    @staticmethod
    def _is_high_risk(sid: str) -> bool:
        """Return True if this SID represents a broad/low-privilege group."""
        if sid in HIGH_RISK_SIDS:
            return True
        suffix = "-" + sid.split("-")[-1]
        return suffix in HIGH_RISK_SUFFIXES