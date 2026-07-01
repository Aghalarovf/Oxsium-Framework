from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

@dataclass
class LdapConfig:
    connect_timeout: int = 10
    receive_timeout: int = 30
    page_size:       int = 1000

    @classmethod
    def from_app_config(cls, config) -> "LdapConfig":
        return cls(
            connect_timeout=getattr(config, "LDAP_CONNECT_TIMEOUT", 10),
            receive_timeout=getattr(config, "LDAP_RECEIVE_TIMEOUT", 30),
            page_size=getattr(config, "LDAP_PAGE_SIZE", 1000),
        )


@dataclass
class AclFilterConfig:
    exclude_inherited:          bool      = False
    exclude_default:            bool      = False
    interesting_only:           bool      = False
    exclude_inherited_defaults: bool      = False
    rights_filter:              list[str] = field(default_factory=list)
    principal_filter:           str       = ""
    target_filter:              str       = ""
    target_type_filter:         list[str] = field(default_factory=list)
    scope_filter:               list[str] = field(default_factory=list)
    self_acl_only:              bool      = False

@runtime_checkable
class LdapBackend(Protocol):
    def search(self, base: str, ldap_filter: str, **kwargs) -> None: ...
    @property
    def entries(self) -> list: ...
    @property
    def result(self) -> dict | None: ...
    def unbind(self) -> None: ...


@runtime_checkable
class SecurityDescriptorParser(Protocol):
    def parse(self, raw_sd: bytes) -> object: ...
    def is_object_ace(self, ace_data: object) -> bool: ...


class ObjectScope(str, Enum):
    SECURITY_PRINCIPALS = "security_principals"
    NAMED_CONTAINERS    = "named_containers"
    GPO                 = "gpo"
    SENSITIVE_TEMPLATES = "sensitive_templates"
    ALL_WITH_ACL        = "all_with_acl"
    CUSTOM_FILTER       = "custom_filter"
    DEEP_SCAN           = "deep_scan"