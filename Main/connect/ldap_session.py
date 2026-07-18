import logging

from ldap3.core.exceptions import LDAPBindError, LDAPInvalidCredentialsResult

from connect.utils import (
    build_ldap_bind_users, domain_to_dn, is_ntlm_hash,
    pfx_bytes_to_pem, write_temp_pem_pair, write_temp_ccache, cleanup_temp_paths,
)
from connect.ldap_core import (
    _is_ldap_bind_failure,
    _is_hard_stop_bind_error,
    _open_ldap_connection,
    _open_ldap_connection_gssapi,
    _open_ldap_connection_certificate,
)
from connect.utils import extract_ad_bind_subcode

logger = logging.getLogger("ad_api")


class LdapSessionError(Exception):
    def __init__(self, message: str, code: int = 500):
        super().__init__(message)
        self.message = message
        self.code = code


class LdapSession:
    def __init__(
        self, ip, domain, username, password, config, use_ssl: bool = False,
        ccache_bytes: bytes | None = None, pfx_bytes: bytes | None = None,
        pfx_password: str | None = None, dc_host: str | None = None,
    ):
        self.ip = ip
        self.domain = domain
        self.username = username
        self.password = password
        self.config = config
        self.use_ssl = use_ssl
        self.ccache_bytes = ccache_bytes
        self.pfx_bytes = pfx_bytes
        self.pfx_password = pfx_password

        # Explicit DC hostname (e.g. dc01.corp.local), as opposed to `ip`
        # which may be a bare IP address. Kerberos/GSSAPI resolves its SPN
        # (ldap/<hostname>) against a hostname, so any GSSAPI bind must
        # target dc_host rather than ip whenever one was supplied.
        self.dc_host = (dc_host or "").strip() or None

        self.conn = None
        self.server = None
        self.bind_user = None
        self.auth_type = "SIMPLE"
        self.base_dn = domain_to_dn(domain)

        # Temp material cleaned up in close()
        self._ccache_path: str | None = None
        self._cert_path: str | None = None
        self._key_path: str | None = None

    @property
    def _gssapi_target(self) -> str:
        """Host used for Kerberos/GSSAPI SASL binds. Must be a resolvable
        hostname (not a bare IP) so the KDC can find the matching
        ldap/<hostname> service principal. Falls back to `ip` only if no
        explicit DC hostname was provided (this will fail Kerberos lookups
        against most real environments, but preserves prior behavior for
        callers that already pass a hostname in `ip`)."""
        return self.dc_host or self.ip

    def _open_via_ccache(self) -> "LdapSession":
        try:
            self._ccache_path = write_temp_ccache(self.ccache_bytes)
        except Exception as exc:
            raise LdapSessionError(f"Could not stage ccache file: {exc}", code=400) from exc

        # TCP bağlantısı üçün ip (və ya dc_host varsa o), SPN üçün isə
        # mütləq dc_host (FQDN) lazımdır. Hər ikisini ayrı-ayrı veririk:
        # _open_ldap_connection_gssapi ldap_target-ə TCP açır,
        # dc_fqdn-dən isə "ldap/<dc_fqdn>" SPN-ini qurur.
        tcp_target = self.ip           # TCP bağlantısı hara gedir
        spn_host   = self.dc_host      # SPN üçün FQDN (None ola bilər)

        logger.debug(
            "GSSAPI ccache bind: tcp_target=%s spn_host=%s ccache=%s",
            tcp_target, spn_host, self._ccache_path,
        )

        try:
            conn = _open_ldap_connection_gssapi(
                ldap_target=tcp_target,
                ccache_path=self._ccache_path,
                use_ssl=self.use_ssl,
                dc_fqdn=spn_host,
            )
        except (LDAPInvalidCredentialsResult, LDAPBindError) as exc:
            logger.error(
                "GSSAPI ccache bind rejected by AD | tcp=%s spn_host=%s ccache=%s: %s",
                tcp_target, spn_host, self._ccache_path, exc, exc_info=True,
            )
            raise LdapSessionError(
                f"Kerberos ccache bind rejected by AD: {exc}", code=401
            ) from exc
        except Exception as exc:
            logger.error(
                "GSSAPI ccache bind failed | tcp=%s spn_host=%s ccache=%s | %s: %s",
                tcp_target, spn_host, self._ccache_path,
                type(exc).__name__, exc, exc_info=True,
            )
            raise LdapSessionError(f"Kerberos ccache bind failed: {exc}", code=503) from exc

        self.conn = conn
        self.server = conn.server
        self.auth_type = "GSSAPI"
        self.bind_user = self.username or "(ccache)"
        return self

    def _open_via_pfx(self) -> "LdapSession":
        try:
            cert_pem, key_pem = pfx_bytes_to_pem(self.pfx_bytes, self.pfx_password)
            self._cert_path, self._key_path = write_temp_pem_pair(cert_pem, key_pem)
        except ValueError as exc:
            raise LdapSessionError(str(exc), code=400) from exc
        except Exception as exc:
            raise LdapSessionError(f"Could not stage PFX certificate: {exc}", code=400) from exc

        try:
            conn = _open_ldap_connection_certificate(
                ldap_target=self._gssapi_target,
                cert_file=self._cert_path,
                key_file=self._key_path,
            )
        except (LDAPInvalidCredentialsResult, LDAPBindError) as exc:
            raise LdapSessionError(
                f"Certificate bind rejected by AD: {exc}", code=401
            ) from exc
        except Exception as exc:
            raise LdapSessionError(f"Certificate bind failed: {exc}", code=503) from exc

        self.conn = conn
        self.server = conn.server
        self.auth_type = "EXTERNAL"
        self.bind_user = self.username or "(certificate)"
        return self

    def open(self) -> "LdapSession":
        if self.ccache_bytes:
            return self._open_via_ccache()
        if self.pfx_bytes:
            return self._open_via_pfx()

        secret = self.password
        if is_ntlm_hash(self.password):
            secret = f"00000000000000000000000000000000:{self.password}"
            self.auth_type = "NTLM"

        last_error = None
        for bind_user in build_ldap_bind_users(self.username, self.domain):
            try:
                conn = _open_ldap_connection(
                    ldap_target=self.ip,
                    bind_user=bind_user,
                    bind_secret=secret,
                    auth_type=self.auth_type,
                    use_ssl=self.use_ssl,
                )
                self.conn = conn
                self.server = conn.server
                self.bind_user = bind_user
                return self
            except (LDAPInvalidCredentialsResult, LDAPBindError) as exc:
                last_error = exc
                exc_msg = str(exc)
                logger.error(
                    "LDAP bind RAW error | LdapSession | ip=%s bind_user=%s exc_type=%s message=%s",
                    self.ip, bind_user, type(exc).__name__, exc_msg, exc_info=True,
                )
                # Hard-stop: a definitive AD rejection (e.g. strongerAuthRequired,
                # accountLocked, passwordExpired). Retrying with another username
                # format won't help — surface the real reason immediately.
                if _is_hard_stop_bind_error(exc_msg):
                    subcode = extract_ad_bind_subcode(exc_msg)
                    detail = f"{subcode[0]} — {subcode[1]}" if subcode else exc_msg
                    raise LdapSessionError(
                        f"LDAP bind rejected by AD: {detail}", code=401
                    ) from exc
                if _is_ldap_bind_failure(exc_msg):
                    continue
                raise LdapSessionError(exc_msg, code=401) from exc
            except LdapSessionError:
                raise
            except Exception as exc:
                last_error = exc
                logger.error(
                    "LDAP connection RAW error | LdapSession | ip=%s bind_user=%s exc_type=%s message=%s",
                    self.ip, bind_user, type(exc).__name__, str(exc), exc_info=True,
                )
                raise LdapSessionError(str(exc), code=503) from exc

        # Exhausted all username formats — still no success.
        last_msg = str(last_error) if last_error else ""
        subcode = extract_ad_bind_subcode(last_msg)
        if subcode:
            detail = f"{subcode[0]} — {subcode[1]}"
            raise LdapSessionError(f"LDAP bind failed: {detail}", code=401) from last_error
        raise LdapSessionError(
            f"LDAP bind failed for {self.username}; tried UPN, NETBIOS, and raw "
            f"username formats. Verify the AD logon name (for example user@domain or DOMAIN\\user).",
            code=401,
        ) from last_error

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.unbind()
            except Exception:
                logger.warning("LDAP session unbind failed", exc_info=True)
            finally:
                self.conn = None
                self.server = None
        cleanup_temp_paths(self._ccache_path, self._cert_path, self._key_path)
        self._ccache_path = self._cert_path = self._key_path = None

    def __enter__(self) -> "LdapSession":
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False