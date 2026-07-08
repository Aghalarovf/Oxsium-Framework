from __future__ import annotations

import os
import socket
import struct
from datetime import datetime, timezone

from ldap3 import ALL, BASE, NTLM, SIMPLE, SUBTREE, Connection, Server
from ldap3.core.exceptions import (
	LDAPAttributeError,
	LDAPException,
	LDAPInvalidCredentialsResult,
	LDAPSocketOpenError,
)

try:
	from connect.config import Config
except Exception:
	class Config:
		DOMAIN_LEVEL_MAP = {
			"0": "2000",
			"2": "2003",
			"3": "2008",
			"4": "2008 R2",
			"5": "2012",
			"6": "2012 R2",
			"7": "2016+",
		}
		LDAP_CONNECT_TIMEOUT = 15
		LDAP_RECEIVE_TIMEOUT = 120
		LDAP_PAGE_SIZE = 200
		SMB_PROBE_TIMEOUT = 5


def is_ntlm_hash(value: str) -> bool:
	return len(value or "") == 32 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def domain_to_dn(domain: str) -> str:
	return ",".join(f"DC={part}" for part in (domain or "").split(".") if part)


def get_bind_user(username: str, domain: str) -> str:
	if "@" in (username or "") or "\\" in (username or ""):
		return username
	netbios = (domain or "").split(".")[0].upper()
	return f"{netbios}\\{username}"


def normalize_value(value):
	if value is None:
		return None
	if hasattr(value, "value"):
		return value.value
	if isinstance(value, list):
		return value[0] if value else None
	return value


def normalize_values(value) -> list:
	if value is None:
		return []
	if hasattr(value, "values"):
		return [item for item in value.values if item is not None]
	if isinstance(value, list):
		return [item for item in value if item is not None]
	return [value]


def safe_int(value, default=0):
	value = normalize_value(value)
	if value is None or isinstance(value, bool):
		return default
	if isinstance(value, int):
		return value
	try:
		return int(str(value))
	except (TypeError, ValueError):
		return default


def ldap_timestamp_to_iso(value):
	normalized = normalize_value(value)
	if normalized is None:
		return None
	if isinstance(normalized, datetime):
		if normalized.tzinfo is None:
			normalized = normalized.replace(tzinfo=timezone.utc)
		return normalized.isoformat()
	if isinstance(normalized, str) and not normalized.isdigit():
		return normalized
	try:
		ticks = int(str(normalized))
	except (TypeError, ValueError):
		return str(normalized)
	if ticks in (0, 9223372036854775807):
		return None
	try:
		unix_seconds = (ticks - 116444736000000000) / 10000000
		return datetime.fromtimestamp(unix_seconds, tz=timezone.utc).isoformat()
	except (OSError, OverflowError, ValueError):
		return str(normalized)


def _domain_level_name(raw_level) -> str:
	level = str(safe_int(raw_level, -1))
	return getattr(Config, "DOMAIN_LEVEL_MAP", {}).get(level, level if level != "-1" else "Unknown")


def _connect(ip: str, domain: str, username: str, password: str, config) -> Connection:
	auth_type = SIMPLE
	if is_ntlm_hash(password):
		password = f"00000000000000000000000000000000:{password}"
		auth_type = NTLM

	bind_user = get_bind_user(username, domain)
	server = Server(ip, get_info=ALL, connect_timeout=getattr(config, "LDAP_CONNECT_TIMEOUT", 15))
	return Connection(
		server,
		user=bind_user,
		password=password,
		authentication=auth_type,
		auto_bind=True,
		receive_timeout=getattr(config, "LDAP_RECEIVE_TIMEOUT", 120),
	)


def _check_ntlm_supported(ip: str, domain: str, username: str, password: str, config, diagnostics: list[str] | None = None) -> bool | None:

	bind_password = password
	if is_ntlm_hash(password):
		bind_password = f"00000000000000000000000000000000:{password}"
	bind_user = get_bind_user(username, domain)

	test_conn = None
	try:
		server = Server(ip, connect_timeout=getattr(config, "LDAP_CONNECT_TIMEOUT", 15))
		test_conn = Connection(
			server,
			user=bind_user,
			password=bind_password,
			authentication=NTLM,
			auto_bind=True,
			receive_timeout=getattr(config, "LDAP_RECEIVE_TIMEOUT", 120),
		)
		return True
	except LDAPInvalidCredentialsResult as exc:
		if diagnostics is not None:
			diagnostics.append(f"ntlm_check: DC rejected NTLM bind with otherwise-valid credentials: {exc}")
		return False
	except (LDAPSocketOpenError, LDAPException, OSError, ValueError) as exc:
		if diagnostics is not None:
			diagnostics.append(f"ntlm_check: inconclusive ({exc})")
		return None
	finally:
		if test_conn is not None:
			try:
				test_conn.unbind()
			except Exception:
				pass

_SMB2_CLIENT_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)


def _build_smb2_negotiate_request() -> bytes:

	protocol_id = b"\xfeSMB"
	structure_size = struct.pack("<H", 64)
	credit_charge = struct.pack("<H", 0)
	status_or_channel_seq = struct.pack("<I", 0)
	command = struct.pack("<H", 0)          # 0 = SMB2 NEGOTIATE
	credit_request = struct.pack("<H", 1)
	flags = struct.pack("<I", 0)
	next_command = struct.pack("<I", 0)
	message_id = struct.pack("<Q", 0)
	reserved = struct.pack("<I", 0)
	tree_id = struct.pack("<I", 0)
	session_id = struct.pack("<Q", 0)
	signature = b"\x00" * 16

	header = (
		protocol_id + structure_size + credit_charge + status_or_channel_seq +
		command + credit_request + flags + next_command + message_id +
		reserved + tree_id + session_id + signature
	)

	dialects = _SMB2_CLIENT_DIALECTS
	body_structure_size = struct.pack("<H", 36)
	dialect_count = struct.pack("<H", len(dialects))
	client_security_mode = struct.pack("<H", 1)  
	body_reserved = struct.pack("<H", 0)
	capabilities = struct.pack("<I", 0)
	client_guid = os.urandom(16)
	client_start_time = struct.pack("<Q", 0)
	dialect_list = b"".join(struct.pack("<H", dialect) for dialect in dialects)

	body = (
		body_structure_size + dialect_count + client_security_mode + body_reserved +
		capabilities + client_guid + client_start_time + dialect_list
	)

	packet = header + body
	netbios_session_header = struct.pack(">I", len(packet))  
	return netbios_session_header + packet


def _recv_exact(sock: socket.socket, size: int) -> bytes:
	data = b""
	while len(data) < size:
		chunk = sock.recv(size - len(data))
		if not chunk:
			raise OSError("connection closed while reading SMB response")
		data += chunk
	return data


def _check_smb_signing(ip: str, timeout: float = 5.0, diagnostics: list[str] | None = None) -> dict:

	outcome = {"enabled": None, "required": None}
	try:
		with socket.create_connection((ip, 445), timeout=timeout) as sock:
			sock.settimeout(timeout)
			sock.sendall(_build_smb2_negotiate_request())
			netbios_header = _recv_exact(sock, 4)
			response_len = int.from_bytes(netbios_header[1:4], "big")
			response = _recv_exact(sock, response_len)
			if len(response) < 68 or response[0:4] != b"\xfeSMB":
				if diagnostics is not None:
					diagnostics.append("smb_signing_check: unexpected SMB2 negotiate response")
				return outcome
			structure_size = struct.unpack("<H", response[64:66])[0]
			if structure_size != 65:
				if diagnostics is not None:
					diagnostics.append(
						f"smb_signing_check: server returned non-NEGOTIATE response "
						f"(StructureSize={structure_size}, ehtimal ki STATUS xətası) — "
						f"SecurityMode etibarlı deyil, nəticə qeyri-müəyyən saxlanıldı"
					)
				return outcome
			security_mode = struct.unpack("<H", response[66:68])[0]
			outcome["enabled"] = bool(security_mode & 0x0001)
			outcome["required"] = bool(security_mode & 0x0002)
	except (OSError, socket.timeout) as exc:
		if diagnostics is not None:
			diagnostics.append(f"smb_signing_check: {exc}")
	return outcome


def _search_first_entry(conn: Connection, base_dn: str, ldap_filter: str, attributes: list[str], search_scope=SUBTREE):
	search_kwargs = dict(
		search_base=base_dn,
		search_filter=ldap_filter,
		search_scope=search_scope,
		attributes=attributes,
	)
	if search_scope != BASE:
		search_kwargs["paged_size"] = getattr(Config, "LDAP_PAGE_SIZE", 200)
	conn.search(**search_kwargs)
	return conn.entries[0] if conn.entries else None


def _search_base_entry(conn: Connection, base_dn: str, attributes: list[str], debug_label: str = "", diagnostics: list[str] | None = None):
	try:
		return _search_first_entry(conn, base_dn, "(objectClass=*)", attributes, search_scope=BASE)
	except LDAPAttributeError as exc:
		schema = getattr(conn.server, "schema", None)
		known_attributes = [attr for attr in attributes if schema is None or attr in schema.attribute_types]
		if not known_attributes or known_attributes == attributes:
			if diagnostics is not None:
				diagnostics.append(f"{debug_label or base_dn}: {exc}")
			return None
		try:
			return _search_first_entry(conn, base_dn, "(objectClass=*)", known_attributes, search_scope=BASE)
		except Exception as exc2:
			if diagnostics is not None:
				diagnostics.append(f"{debug_label or base_dn}: {exc2}")
			return None
	except Exception as exc:
		if diagnostics is not None:
			diagnostics.append(f"{debug_label or base_dn}: {exc}")
		return None


def _extract_server_cn_from_ntds_dn(dn: str) -> str:
	if not dn:
		return ""
	parts = [p.strip() for p in dn.split(",")]
	if len(parts) >= 2 and parts[1].upper().startswith("CN="):
		return parts[1][3:]
	return ""


def _get_fsmo_role_owner_cn(conn: Connection, container_dn: str, role_name: str = "", diagnostics: list[str] | None = None) -> str:
	if not container_dn:
		return ""
	entry = _search_base_entry(conn, container_dn, ["fSMORoleOwner"], debug_label=f"fsmo:{role_name}", diagnostics=diagnostics)
	if not entry:
		return ""
	owner_dn = str(normalize_value(getattr(entry, "fSMORoleOwner", None)) or "")
	return _extract_server_cn_from_ntds_dn(owner_dn)


def _collect_fsmo_roles(conn: Connection, base_dn: str, config_dn: str, schema_dn: str, diagnostics: list[str] | None = None) -> dict:

	locations = {
		"schema_master":   schema_dn,
		"naming_master":   f"CN=Partitions,{config_dn}" if config_dn else "",
		"rid_master":      f"CN=RID Manager$,CN=System,{base_dn}" if base_dn else "",
		"pdc_emulator":    base_dn,
		"infrastructure":  f"CN=Infrastructure,{base_dn}" if base_dn else "",
	}
	return {role: _get_fsmo_role_owner_cn(conn, dn, role_name=role, diagnostics=diagnostics) for role, dn in locations.items()}


def _collect_domain_controllers(conn: Connection, base_dn: str, domain: str, fsmo_roles: dict) -> list[dict]:
	attributes = [
		"cn",
		"dNSHostName",
		"distinguishedName",
		"objectSid",
		"operatingSystem",
		"operatingSystemVersion",
		"msDS-SupportedEncryptionTypes",
	]
	try:
		conn.search(
			base_dn,
			"(userAccountControl:1.2.840.113556.1.4.803:=8192)",
			search_scope=SUBTREE,
			attributes=attributes,
			paged_size=getattr(Config, "LDAP_PAGE_SIZE", 200),
		)
	except Exception:
		return []

	fsmo_roles = fsmo_roles or {}

	controllers: list[dict] = []
	for entry in conn.entries:
		cn = str(normalize_value(getattr(entry, "cn", None)) or "")
		dns_name = str(normalize_value(getattr(entry, "dNSHostName", None)) or "")
		cn_upper = cn.upper()
		fqdn = dns_name or (f"{cn}.{domain}" if cn and domain else cn)
		controllers.append(
			{
				"dn": str(normalize_value(getattr(entry, "distinguishedName", None)) or ""),
				"cn": cn,
				"dns_name": dns_name,
				"fqdn": fqdn,
				"os": str(normalize_value(getattr(entry, "operatingSystem", None)) or ""),
				"os_version": str(normalize_value(getattr(entry, "operatingSystemVersion", None)) or ""),
				"sid": str(normalize_value(getattr(entry, "objectSid", None)) or ""),
				"enc_types": safe_int(getattr(entry, "msDS-SupportedEncryptionTypes", None), 0),
				"is_schema_master":          bool(cn) and cn_upper == (fsmo_roles.get("schema_master") or "").upper(),
				"is_naming_master":          bool(cn) and cn_upper == (fsmo_roles.get("naming_master") or "").upper(),
				"is_rid_master":             bool(cn) and cn_upper == (fsmo_roles.get("rid_master") or "").upper(),
				"is_pdc_emulator":           bool(cn) and cn_upper == (fsmo_roles.get("pdc_emulator") or "").upper(),
				"is_infrastructure_master":  bool(cn) and cn_upper == (fsmo_roles.get("infrastructure") or "").upper(),
			}
		)
	return controllers


def _collect_certificate_services(conn: Connection, config_dn: str) -> list[dict]:
	if not config_dn:
		return []
	enrollment_services_dn = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}"
	try:
		conn.search(
			enrollment_services_dn,
			"(objectClass=pKIEnrollmentService)",
			search_scope=SUBTREE,
			attributes=["cn", "dNSHostName", "distinguishedName", "name"],
			paged_size=getattr(Config, "LDAP_PAGE_SIZE", 200),
		)
	except Exception:
		return []

	cas: list[dict] = []
	for entry in conn.entries:
		cas.append(
			{
				"cn": str(normalize_value(getattr(entry, "cn", None)) or normalize_value(getattr(entry, "name", None)) or ""),
				"dns_name": str(normalize_value(getattr(entry, "dNSHostName", None)) or ""),
				"dn": str(normalize_value(getattr(entry, "distinguishedName", None)) or ""),
			}
		)
	return cas


def _build_risk_findings(*, machine_account_quota: int, smart_card_required: bool, ntlm_supported: bool | None, smb_signing_required: bool | None) -> list[dict]:
	findings: list[dict] = []

	if machine_account_quota > 10:
		findings.append(
			{
				"severity": "medium",
				"code": "MAQ_HIGH",
				"title": "Machine account quota is elevated",
				"detail": f"ms-DS-MachineAccountQuota is set to {machine_account_quota}.",
			}
		)

	if not smart_card_required:
		findings.append(
			{
				"severity": "info",
				"code": "SMARTCARD_NOT_REQUIRED",
				"title": "Smart card logon not required",
				"detail": "The domain does not appear to enforce smart card requirement at the domain level.",
			}
		)

	if ntlm_supported is True:
		findings.append(
			{
				"severity": "medium",
				"code": "NTLM_ENABLED",
				"title": "NTLM authentication is allowed",
				"detail": "The domain controller accepted an NTLM bind, meaning NTLM authentication is not restricted at the domain level. This exposes the domain to NTLM relay and pass-the-hash style attacks.",
			}
		)

	if smb_signing_required is False:
		findings.append(
			{
				"severity": "high",
				"code": "SMB_SIGNING_NOT_REQUIRED",
				"title": "SMB signing is not required",
				"detail": "The domain controller does not require SMB signing. This makes the host vulnerable to SMB relay attacks (e.g. NTLM relay to LDAP/SMB).",
			}
		)

	return findings


def _highest_severity(findings: list[dict]) -> str:
	order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	if not findings:
		return "info"
	best = max(findings, key=lambda item: order.get(str(item.get("severity") or "info").lower(), 0))
	return str(best.get("severity") or "info").lower()


def get_domain_info(ip: str, domain: str, username: str, password: str, config) -> dict:
	generated_at = datetime.now(timezone.utc).isoformat()
	base_dn = domain_to_dn(domain)
	result = {
		"success": False,
		"count": 0,
		"error": None,
		"meta": {},
		"fqdn": domain,
		"netbios_name": (domain or "").split(".")[0].upper(),
		"domain_sid": "",
		"functional_level": None,
		"functional_level_name": "Unknown",
		"generated_at": generated_at,
		"smb_signing_policy_present": None,
		"smb_signing_enabled": None,
		"smb_signing_required": None,
		"ntlm_supported": None,
		"smart_card_required": False,
		"machine_account_quota": 0,
		"risk_score": 0,
		"highest_severity": "info",
		"fine_grained_policies": [],
		"has_enterprise_ca": False,
		"ca_list": [],
		"dns_zones": [],
		"domain_controllers": [],
		"risk_findings": [],
		"fsmo": {
			"schema_master": None,
			"naming_master": None,
			"rid_master": None,
			"pdc_emulator": None,
			"infrastructure": None,
		},
		"password_policy": {},
		"kerberos_policy": {},
	}

	diagnostics: list[str] = []

	try:
		conn = _connect(ip, domain, username, password, config)
	except (LDAPInvalidCredentialsResult, LDAPSocketOpenError, LDAPException, OSError, ValueError) as exc:
		result["error"] = str(exc)
		return result

	try:
		rootdse = _search_base_entry(
			conn,
			"",
			[
				"defaultNamingContext",
				"rootDomainNamingContext",
				"configurationNamingContext",
				"schemaNamingContext",
				"domainFunctionality",
				"forestFunctionality",
				"dnsHostName",
				"supportedCapabilities",
				"ldapServiceName",
			],
			debug_label="rootdse",
			diagnostics=diagnostics,
		)

		if rootdse:
			config_dn = str(normalize_value(getattr(rootdse, "configurationNamingContext", None)) or "")
			schema_dn = str(normalize_value(getattr(rootdse, "schemaNamingContext", None)) or "")
			functional_level = normalize_value(getattr(rootdse, "domainFunctionality", None))
			result["functional_level"] = safe_int(functional_level, None) if functional_level is not None else None
			result["functional_level_name"] = _domain_level_name(functional_level)
			result["meta"].update(
				{
					"configuration_naming_context": config_dn,
					"schema_naming_context": schema_dn,
					"root_domain_naming_context": str(normalize_value(getattr(rootdse, "rootDomainNamingContext", None)) or ""),
					"default_naming_context": str(normalize_value(getattr(rootdse, "defaultNamingContext", None)) or base_dn),
				}
			)
		else:
			config_dn = ""
			schema_dn = ""
			result["meta"]["default_naming_context"] = base_dn

		domain_entry = _search_base_entry(
			conn,
			base_dn,
			[
				"objectSid",
				"ms-DS-MachineAccountQuota",
				"msDS-Behavior-Version",
				"distinguishedName",
				"name",
				"description",
			],
			debug_label="domain_entry",
			diagnostics=diagnostics,
		)
		if domain_entry:
			result["domain_sid"] = str(normalize_value(getattr(domain_entry, "objectSid", None)) or "")
			if result["functional_level"] is None:
				behavior_version = getattr(domain_entry, "msDS-Behavior-Version", None)
				result["functional_level"] = safe_int(behavior_version, None)
				result["functional_level_name"] = _domain_level_name(behavior_version)
			result["machine_account_quota"] = safe_int(getattr(domain_entry, "ms-DS-MachineAccountQuota", None), 0)
			result["meta"]["domain_dn"] = str(normalize_value(getattr(domain_entry, "distinguishedName", None)) or base_dn)

		fsmo_roles = _collect_fsmo_roles(conn, base_dn, config_dn, schema_dn, diagnostics=diagnostics)
		result["fsmo"] = {
			"schema_master":  fsmo_roles.get("schema_master") or None,
			"naming_master":  fsmo_roles.get("naming_master") or None,
			"rid_master":     fsmo_roles.get("rid_master") or None,
			"pdc_emulator":   fsmo_roles.get("pdc_emulator") or None,
			"infrastructure": fsmo_roles.get("infrastructure") or None,
		}

		result["domain_controllers"] = _collect_domain_controllers(conn, base_dn, domain, fsmo_roles)
		result["ca_list"] = _collect_certificate_services(conn, config_dn)
		result["has_enterprise_ca"] = bool(result["ca_list"])
		result["dns_zones"] = []
		result["fine_grained_policies"] = []
		result["smart_card_required"] = False

		result["ntlm_supported"] = _check_ntlm_supported(ip, domain, username, password, config, diagnostics=diagnostics)

		smb_signing = _check_smb_signing(ip, timeout=getattr(config, "SMB_PROBE_TIMEOUT", 5), diagnostics=diagnostics)
		result["smb_signing_enabled"] = smb_signing.get("enabled")
		result["smb_signing_required"] = smb_signing.get("required")
		result["smb_signing_policy_present"] = smb_signing.get("required") is not None

		findings = _build_risk_findings(
			machine_account_quota=result["machine_account_quota"],
			smart_card_required=result["smart_card_required"],
			ntlm_supported=result["ntlm_supported"],
			smb_signing_required=result["smb_signing_required"],
		)
		result["risk_findings"] = findings
		result["highest_severity"] = _highest_severity(findings)
		result["risk_score"] = sum({"info": 1, "low": 3, "medium": 6, "high": 9, "critical": 12}.get(str(item.get("severity") or "info").lower(), 0) for item in findings)
		result["meta"]["domain_controller_count"] = len(result["domain_controllers"])
		result["meta"]["enterprise_ca_count"] = len(result["ca_list"])
		result["meta"]["risk_finding_count"] = len(findings)
		if diagnostics:
			result["meta"]["lookup_warnings"] = diagnostics
		result["success"] = True
		result["count"] = 1
		return result
	except Exception as exc:
		result["error"] = str(exc)
		return result


__all__ = ["get_domain_info"]