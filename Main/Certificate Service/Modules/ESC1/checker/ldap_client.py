"""
ldap_client.py
Establish LDAP connection to DC and retrieve certificate templates.
"""

import ssl
from dataclasses import dataclass, field
from typing import Optional

try:
    from ldap3 import Server, Connection, ALL, SIMPLE, SUBTREE, Tls
    from ldap3.core.exceptions import LDAPException
except ImportError:
    raise ImportError("ldap3 is not installed: pip install ldap3")


# ── Constants ─────────────────────────────────────────────────
TEMPLATE_BASE   = "CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_nc}"
TEMPLATE_FILTER = "(objectClass=pKICertificateTemplate)"
TEMPLATE_ATTRS  = [
    "cn",
    "displayName",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Enrollment-Flag",
    "msPKI-RA-Signature",
    "msPKI-Cert-Template-OID",
    "pKIExtendedKeyUsage",
    "nTSecurityDescriptor",
    "msPKI-Certificate-Application-Policy",
    "msPKI-Minimal-Key-Size",
    "whenCreated",
    "whenChanged",
]

CA_BASE   = "CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}"
CA_FILTER = "(objectClass=pKIEnrollmentService)"
CA_ATTRS  = ["cn", "dNSHostName", "certificateTemplates", "cACertificate"]


# ── Data Classes ──────────────────────────────────────────────
@dataclass
class LDAPConfig:
    host:     str               # DC IP or hostname
    domain:   str               # e.g. corp.local
    username: str               # username without domain prefix
    password: str
    auth:     str  = "SIMPLE"  # SIMPLE | NTLM | KERBEROS
    port:     int  = 389
    use_tls:  bool = False
    timeout:  int  = 10


@dataclass
class TemplateEntry:
    cn:              str
    display_name:    str
    name_flag:       int            # msPKI-Certificate-Name-Flag
    enrollment_flag: int            # msPKI-Enrollment-Flag
    ra_signature:    int            # msPKI-RA-Signature (manager approval count)
    ekus:            list[str]      # pKIExtendedKeyUsage OIDs
    app_policies:    list[str]      # msPKI-Certificate-Application-Policy OIDs
    raw_sd:          Optional[bytes]  # nTSecurityDescriptor raw bytes for ACL parsing
    min_key_size:    int  = 2048
    oid:             str  = ""
    when_created:    str  = ""
    when_changed:    str  = ""


@dataclass
class CAEntry:
    cn:           str
    dns_hostname: str
    templates:    list[str] = field(default_factory=list)  # published template names


# ── LDAPClient ────────────────────────────────────────────────
class LDAPClient:
    """
    Connect to a Domain Controller and retrieve certificate
    templates and CA enrollment service objects via LDAP.

    Usage:
        cfg    = LDAPConfig(host="10.10.0.1", domain="corp.local",
                            username="jdoe", password="Pass123")
        client = LDAPClient(cfg)
        client.connect()
        templates = client.get_templates()
        cas       = client.get_cas()
        client.disconnect()
    """

    def __init__(self, cfg: LDAPConfig):
        self.cfg         = cfg
        self._conn:       Optional[Connection] = None
        self._config_nc:  Optional[str]        = None

    # ── Connection ────────────────────────────────────────────
    def connect(self) -> None:
        tls  = None
        port = self.cfg.port

        if self.cfg.use_tls:
            tls  = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)
            port = 636

        server = Server(
            self.cfg.host,
            port=port,
            get_info=ALL,
            tls=tls,
            connect_timeout=self.cfg.timeout,
        )

        user      = f"{self.cfg.username}@{self.cfg.domain}"
        auth_map  = {"SIMPLE": SIMPLE}
        auth_type = auth_map.get(self.cfg.auth.upper(), SIMPLE)

        try:
            self._conn = Connection(
                server,
                user=user,
                password=self.cfg.password,
                authentication=auth_type,
                auto_bind=True,
                raise_exceptions=True,
            )
            self._config_nc = self._get_config_nc()
            print(f"[+] LDAP connected  → {self.cfg.host}:{port}")
            print(f"[+] Config NC       → {self._config_nc}")
        except LDAPException as exc:
            raise ConnectionError(f"[-] LDAP bind failed: {exc}") from exc

    def disconnect(self) -> None:
        if self._conn:
            self._conn.unbind()
            self._conn = None
            print("[*] LDAP connection closed.")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    # ── Internal Helpers ──────────────────────────────────────
    def _get_config_nc(self) -> str:
        """
        Read configurationNamingContext from the DC rootDSE.
        Falls back to building it from the domain name string.
        Example: CN=Configuration,DC=corp,DC=local
        """
        info = self._conn.server.info
        if info and info.other.get("configurationNamingContext"):
            return info.other["configurationNamingContext"][0]
        # Fallback
        parts = self.cfg.domain.split(".")
        return "CN=Configuration," + ",".join(f"DC={p}" for p in parts)

    @staticmethod
    def _int(entry, name: str) -> int:
        v = entry[name].value
        return int(v) if v is not None else 0

    @staticmethod
    def _list(entry, name: str) -> list[str]:
        v = entry[name].value
        if v is None:
            return []
        return v if isinstance(v, list) else [str(v)]

    @staticmethod
    def _bytes(entry, name: str) -> Optional[bytes]:
        v = entry[name].value
        return bytes(v) if v else None

    @staticmethod
    def _str(entry, name: str) -> str:
        v = entry[name].value
        return str(v) if v else ""

    # ── Templates ─────────────────────────────────────────────
    def get_templates(self) -> list[TemplateEntry]:
        """
        Search LDAP for all certificate template objects and
        return them as a list of TemplateEntry instances.
        """
        if not self._conn:
            raise RuntimeError("Call connect() first.")

        base = TEMPLATE_BASE.format(config_nc=self._config_nc)
        self._conn.search(
            search_base=base,
            search_filter=TEMPLATE_FILTER,
            search_scope=SUBTREE,
            attributes=TEMPLATE_ATTRS,
        )

        results = [self._parse_template(e) for e in self._conn.entries]
        print(f"[+] {len(results)} certificate template(s) found.")
        return results

    def _parse_template(self, entry) -> TemplateEntry:
        return TemplateEntry(
            cn=self._str(entry, "cn"),
            display_name=self._str(entry, "displayName"),
            name_flag=self._int(entry, "msPKI-Certificate-Name-Flag"),
            enrollment_flag=self._int(entry, "msPKI-Enrollment-Flag"),
            ra_signature=self._int(entry, "msPKI-RA-Signature"),
            ekus=self._list(entry, "pKIExtendedKeyUsage"),
            app_policies=self._list(entry, "msPKI-Certificate-Application-Policy"),
            raw_sd=self._bytes(entry, "nTSecurityDescriptor"),
            min_key_size=self._int(entry, "msPKI-Minimal-Key-Size"),
            oid=self._str(entry, "msPKI-Cert-Template-OID"),
            when_created=self._str(entry, "whenCreated"),
            when_changed=self._str(entry, "whenChanged"),
        )

    # ── CAs ───────────────────────────────────────────────────
    def get_cas(self) -> list[CAEntry]:
        """
        Find all Certificate Authority enrollment service objects
        published in Active Directory.
        """
        if not self._conn:
            raise RuntimeError("Call connect() first.")

        base = CA_BASE.format(config_nc=self._config_nc)
        self._conn.search(
            search_base=base,
            search_filter=CA_FILTER,
            search_scope=SUBTREE,
            attributes=CA_ATTRS,
        )

        results: list[CAEntry] = []
        for entry in self._conn.entries:
            cn    = self._str(entry, "cn")
            dns   = self._str(entry, "dNSHostName")
            raw   = entry["certificateTemplates"].value or []
            tmpls = raw if isinstance(raw, list) else [raw]
            results.append(CAEntry(cn=cn, dns_hostname=dns, templates=tmpls))

        print(f"[+] {len(results)} CA(s) found.")
        return results