import logging

from ldap3.core.exceptions import LDAPBindError, LDAPInvalidCredentialsResult

from connect.utils import build_ldap_bind_users, domain_to_dn, is_ntlm_hash
from connect.ldap_core import _is_ldap_bind_failure, _open_ldap_connection

logger = logging.getLogger("ad_api")


class LdapSessionError(Exception):
    def __init__(self, message: str, code: int = 500):
        super().__init__(message)
        self.message = message
        self.code = code


class LdapSession:
    def __init__(self, ip, domain, username, password, config, use_ssl: bool = False):
        self.ip = ip
        self.domain = domain
        self.username = username
        self.password = password
        self.config = config
        self.use_ssl = use_ssl

        self.conn = None
        self.server = None
        self.bind_user = None
        self.auth_type = "SIMPLE"
        self.base_dn = domain_to_dn(domain)

    def open(self) -> "LdapSession":
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
                logger.error(
                    "LDAP bind RAW error | LdapSession | ip=%s bind_user=%s exc_type=%s message=%s",
                    self.ip, bind_user, type(exc).__name__, str(exc), exc_info=True,
                )
                if _is_ldap_bind_failure(str(exc)):
                    continue
                raise LdapSessionError(str(exc), code=401) from exc
            except Exception as exc:
                last_error = exc
                logger.error(
                    "LDAP connection RAW error | LdapSession | ip=%s bind_user=%s exc_type=%s message=%s",
                    self.ip, bind_user, type(exc).__name__, str(exc), exc_info=True,
                )
                raise LdapSessionError(str(exc), code=503) from exc

        raise LdapSessionError(
            f"LDAP bind failed for {self.username}; tried UPN, NETBIOS, and raw "
            f"username formats.",
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

    def __enter__(self) -> "LdapSession":
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False