from __future__ import annotations

import os
import socket
import struct
from datetime import datetime, timezone

from ldap3 import ALL, ANONYMOUS, BASE, NTLM, SIMPLE, SUBTREE, Connection, Server
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

try:
	from connect.ldap_core import _open_ldap_connection
except Exception:
	_open_ldap_connection = None


def is_ntlm_hash(value: str) -> bool:
	return len(value or "") == 32 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def domain_to_dn(domain: str) -> str:
	return ",".join(f"DC={part}" for part in (domain or "").split(".") if part)


def get_bind_user(username: str, domain: str, netbios_name: str | None = None) -> str:
	if "@" in (username or "") or "\\" in (username or ""):
		return username
	netbios = (netbios_name or (domain or "").split(".")[0]).upper()
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


def _connect_anonymous(ip: str, config) -> Connection:
	server = Server(ip, get_info=ALL, connect_timeout=getattr(config, "LDAP_CONNECT_TIMEOUT", 15))
	return Connection(
		server,
		authentication=ANONYMOUS,
		auto_bind=True,
		receive_timeout=getattr(config, "LDAP_RECEIVE_TIMEOUT", 120),
	)


def _resolve_domain_netbios_name_via_ldap(ip: str, domain: str, config, diagnostics: list[str] | None = None) -> str:
	fallback = (domain or "").split(".")[0].upper()
	base_dn = domain_to_dn(domain)
	if not base_dn:
		return fallback

	conn = None
	try:
		conn = _connect_anonymous(ip, config)
		conn.search("", "(objectClass=*)", search_scope=BASE, attributes=["configurationNamingContext"])
		if not conn.entries:
			if diagnostics is not None:
				diagnostics.append("netbios_prebind: rootDSE lookup returned no entries")
			return fallback

		config_dn = str(normalize_value(getattr(conn.entries[0], "configurationNamingContext", None)) or "")
		if not config_dn:
			if diagnostics is not None:
				diagnostics.append("netbios_prebind: configurationNamingContext not found")
			return fallback

		partitions_dn = f"CN=Partitions,{config_dn}"
		ldap_filter = f"(&(objectClass=crossRef)(nCName={base_dn}))"
		conn.search(partitions_dn, ldap_filter, search_scope=SUBTREE, attributes=["nETBIOSName"])
		if not conn.entries:
			if diagnostics is not None:
				diagnostics.append("netbios_prebind: no matching crossRef entry")
			return fallback

		netbios_name = str(normalize_value(getattr(conn.entries[0], "nETBIOSName", None)) or "")
		return netbios_name.upper() if netbios_name else fallback

	except Exception as exc:
		if diagnostics is not None:
			diagnostics.append(f"netbios_prebind_ldap: {exc}")
		return fallback
	finally:
		if conn is not None:
			try:
				conn.unbind()
			except Exception:
				pass


def _resolve_domain_netbios_name_prebind(ip: str, domain: str, config, diagnostics: list[str] | None = None) -> str:
	fallback = (domain or "").split(".")[0].upper()

	try:
		smb_result = _resolve_host_netbios_name(ip, timeout=getattr(config, "SMB_PROBE_TIMEOUT", 5), diagnostics=diagnostics)
		if smb_result.get("domain_name"):
			return smb_result["domain_name"].upper()
	except Exception as exc:
		if diagnostics is not None:
			diagnostics.append(f"netbios_prebind_smb: {exc}")

	ldap_result = _resolve_domain_netbios_name_via_ldap(ip, domain, config, diagnostics=diagnostics)
	if ldap_result:
		return ldap_result

	if diagnostics is not None:
		diagnostics.append(
			f"netbios_prebind: both SMB/NTLM probe and anonymous LDAP failed, "
			f"falling back to guessed name '{fallback}' (may be wrong if it exceeds 15 chars)"
		)
	return fallback


def _connect(ip: str, domain: str, username: str, password: str, config, netbios_name: str | None = None) -> Connection:
	auth_type = SIMPLE
	if is_ntlm_hash(password):
		password = f"00000000000000000000000000000000:{password}"
		auth_type = NTLM

	bind_user = get_bind_user(username, domain, netbios_name)

	# Prefer the StartTLS-before-bind / LDAPS-fallback path used by
	# /api/connect. A plain Connection(auto_bind=True) here would fail with
	# "strongerAuthRequired" on any DC that enforces LDAP signing, even
	# though the same credentials succeed through the signing-safe path.
	if _open_ldap_connection is not None:
		return _open_ldap_connection(
			ldap_target=ip,
			bind_user=bind_user,
			bind_secret=password,
			auth_type=auth_type,
			use_ssl=False,
		)

	server = Server(ip, get_info=ALL, connect_timeout=getattr(config, "LDAP_CONNECT_TIMEOUT", 15))
	return Connection(
		server,
		user=bind_user,
		password=password,
		authentication=auth_type,
		auto_bind=True,
		receive_timeout=getattr(config, "LDAP_RECEIVE_TIMEOUT", 120),
	)


def _probe_ntlm_support(ip: str, domain: str, config, diagnostics: list[str] | None = None) -> bool | None:
	probe_user = get_bind_user(f"probe_{os.urandom(4).hex()}", domain)
	probe_password = os.urandom(16).hex()

	test_conn = None
	try:
		server = Server(ip, connect_timeout=getattr(config, "LDAP_CONNECT_TIMEOUT", 15))
		test_conn = Connection(
			server,
			user=probe_user,
			password=probe_password,
			authentication=NTLM,
			auto_bind=True,
			receive_timeout=getattr(config, "LDAP_RECEIVE_TIMEOUT", 120),
		)
		return True
	except LDAPInvalidCredentialsResult:
		if diagnostics is not None:
			diagnostics.append("ntlm_probe: DC processed the NTLM handshake and rejected the probe credentials (NTLM is supported)")
		return True
	except (LDAPSocketOpenError, LDAPException, OSError, ValueError) as exc:
		if diagnostics is not None:
			diagnostics.append(f"ntlm_probe: inconclusive ({exc})")
		return None
	finally:
		if test_conn is not None:
			try:
				test_conn.unbind()
			except Exception:
				pass


def _check_ntlm_supported(ip: str, domain: str, username: str, password: str, config, diagnostics: list[str] | None = None, netbios_name: str | None = None) -> bool | None:

	bind_password = password
	if is_ntlm_hash(password):
		bind_password = f"00000000000000000000000000000000:{password}"
	bind_user = get_bind_user(username, domain, netbios_name)

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
	command = struct.pack("<H", 0)
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
						f"(StructureSize={structure_size}, likely a STATUS error) — "
						f"SecurityMode is not valid, result kept as unknown"
					)
				return outcome
			security_mode = struct.unpack("<H", response[66:68])[0]
			outcome["enabled"] = bool(security_mode & 0x0001)
			outcome["required"] = bool(security_mode & 0x0002)
	except (OSError, socket.timeout) as exc:
		if diagnostics is not None:
			diagnostics.append(f"smb_signing_check: {exc}")
	return outcome


_NBT_NAME_SUFFIX_WORKSTATION = 0x00
_NBT_NAME_SUFFIX_DOMAIN = 0x1C
_NBT_GROUP_FLAG = 0x8000


def _encode_nbt_query_name(name: str = "*") -> bytes:
	padded = (name.upper() + " " * 16)[:16].encode("ascii", errors="replace")
	nibbles = bytearray()
	for byte_val in padded:
		nibbles.append(0x41 + ((byte_val >> 4) & 0x0F))
		nibbles.append(0x41 + (byte_val & 0x0F))
	return bytes([32]) + bytes(nibbles) + b"\x00"


def _build_nbstat_query() -> bytes:
	transaction_id = struct.pack(">H", os.urandom(2)[0] << 8 | os.urandom(1)[0])
	flags = struct.pack(">H", 0x0000)
	qdcount = struct.pack(">H", 1)
	ancount = struct.pack(">H", 0)
	nscount = struct.pack(">H", 0)
	arcount = struct.pack(">H", 0)
	header = transaction_id + flags + qdcount + ancount + nscount + arcount
	question_name = _encode_nbt_query_name("*")
	qtype = struct.pack(">H", 0x0021)
	qclass = struct.pack(">H", 0x0001)
	return header + question_name + qtype + qclass


def _get_host_netbios_info(ip: str, timeout: float = 5.0, diagnostics: list[str] | None = None) -> dict:
	outcome = {"computer_name": "", "domain_name": ""}
	sock = None
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(timeout)
		sock.sendto(_build_nbstat_query(), (ip, 137))
		response, _ = sock.recvfrom(2048)

		if len(response) < 12:
			if diagnostics is not None:
				diagnostics.append("nbt_query: response too short")
			return outcome

		ancount = struct.unpack(">H", response[6:8])[0]
		if ancount == 0:
			if diagnostics is not None:
				diagnostics.append("nbt_query: no names returned")
			return outcome

		offset = 12
		while offset < len(response) and response[offset] != 0x00:
			offset += 1
		offset += 1
		offset += 10

		num_names = response[offset]
		offset += 1

		for _ in range(num_names):
			if offset + 18 > len(response):
				break
			raw_name = response[offset:offset + 15]
			suffix = response[offset + 15]
			flags = struct.unpack(">H", response[offset + 16:offset + 18])[0]
			offset += 18

			decoded_name = raw_name.decode("ascii", errors="replace").strip()
			is_group = bool(flags & _NBT_GROUP_FLAG)

			if not is_group and suffix == _NBT_NAME_SUFFIX_WORKSTATION and not outcome["computer_name"]:
				outcome["computer_name"] = decoded_name
			elif is_group and suffix == _NBT_NAME_SUFFIX_DOMAIN and not outcome["domain_name"]:
				outcome["domain_name"] = decoded_name
			elif is_group and suffix == _NBT_NAME_SUFFIX_WORKSTATION and not outcome["domain_name"]:
				outcome["domain_name"] = decoded_name

	except (OSError, socket.timeout) as exc:
		if diagnostics is not None:
			diagnostics.append(f"nbt_query: {exc}")
	finally:
		if sock is not None:
			try:
				sock.close()
			except Exception:
				pass
	return outcome


_NTLMSSP_NEGOTIATE_UNICODE = 0x00000001
_NTLMSSP_NEGOTIATE_OEM = 0x00000002
_NTLMSSP_REQUEST_TARGET = 0x00000004
_NTLMSSP_NEGOTIATE_NTLM = 0x00000200
_NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000
_NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
_NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00400000
_NTLMSSP_NEGOTIATE_128 = 0x20000000

_MSV_AV_NB_COMPUTER_NAME = 0x0001
_MSV_AV_NB_DOMAIN_NAME = 0x0002
_MSV_AV_DNS_COMPUTER_NAME = 0x0003
_MSV_AV_DNS_DOMAIN_NAME = 0x0004


def _build_ntlm_negotiate_message() -> bytes:
	signature = b"NTLMSSP\x00"
	message_type = struct.pack("<I", 1)
	flags = (
		_NTLMSSP_NEGOTIATE_UNICODE | _NTLMSSP_NEGOTIATE_OEM | _NTLMSSP_REQUEST_TARGET |
		_NTLMSSP_NEGOTIATE_NTLM | _NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		_NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | _NTLMSSP_NEGOTIATE_TARGET_INFO |
		_NTLMSSP_NEGOTIATE_128
	)
	negotiate_flags = struct.pack("<I", flags)
	domain_name_fields = struct.pack("<HHI", 0, 0, 32)
	workstation_fields = struct.pack("<HHI", 0, 0, 32)
	return signature + message_type + negotiate_flags + domain_name_fields + workstation_fields


def _build_smb2_session_setup_request(security_blob: bytes) -> bytes:
	protocol_id = b"\xfeSMB"
	structure_size = struct.pack("<H", 64)
	credit_charge = struct.pack("<H", 1)
	channel_sequence_reserved = struct.pack("<I", 0)
	command = struct.pack("<H", 1)
	credit_request = struct.pack("<H", 1)
	flags = struct.pack("<I", 0)
	next_command = struct.pack("<I", 0)
	message_id = struct.pack("<Q", 1)
	reserved = struct.pack("<I", 0)
	tree_id = struct.pack("<I", 0)
	session_id = struct.pack("<Q", 0)
	signature = b"\x00" * 16

	header = (
		protocol_id + structure_size + credit_charge + channel_sequence_reserved +
		command + credit_request + flags + next_command + message_id +
		reserved + tree_id + session_id + signature
	)

	body_structure_size = struct.pack("<H", 25)
	session_setup_flags = struct.pack("<B", 0)
	security_mode = struct.pack("<B", 1)
	capabilities = struct.pack("<I", 0)
	channel = struct.pack("<I", 0)
	security_buffer_offset = struct.pack("<H", 64 + 24)
	security_buffer_length = struct.pack("<H", len(security_blob))
	previous_session_id = struct.pack("<Q", 0)

	body = (
		body_structure_size + session_setup_flags + security_mode + capabilities +
		channel + security_buffer_offset + security_buffer_length + previous_session_id
	)

	packet = header + body + security_blob
	netbios_header = struct.pack(">I", len(packet))
	return netbios_header + packet


def _parse_ntlm_target_info(challenge_message: bytes) -> dict:
	outcome = {"computer_name": "", "domain_name": "", "dns_computer_name": "", "dns_domain_name": ""}
	if len(challenge_message) < 48 or not challenge_message.startswith(b"NTLMSSP\x00"):
		return outcome

	target_info_len = struct.unpack("<H", challenge_message[40:42])[0]
	target_info_offset = struct.unpack("<I", challenge_message[44:48])[0]

	if target_info_len == 0 or target_info_offset + target_info_len > len(challenge_message):
		return outcome

	target_info = challenge_message[target_info_offset:target_info_offset + target_info_len]

	pos = 0
	while pos + 4 <= len(target_info):
		av_id, av_len = struct.unpack("<HH", target_info[pos:pos + 4])
		pos += 4
		if av_id == 0x0000:
			break
		av_value = target_info[pos:pos + av_len]
		pos += av_len
		if av_id == _MSV_AV_NB_COMPUTER_NAME:
			outcome["computer_name"] = av_value.decode("utf-16le", errors="replace")
		elif av_id == _MSV_AV_NB_DOMAIN_NAME:
			outcome["domain_name"] = av_value.decode("utf-16le", errors="replace")
		elif av_id == _MSV_AV_DNS_COMPUTER_NAME:
			outcome["dns_computer_name"] = av_value.decode("utf-16le", errors="replace")
		elif av_id == _MSV_AV_DNS_DOMAIN_NAME:
			outcome["dns_domain_name"] = av_value.decode("utf-16le", errors="replace")

	return outcome


def _probe_smb_ntlm_target_info(ip: str, timeout: float = 5.0, diagnostics: list[str] | None = None) -> dict:
	outcome = {"computer_name": "", "domain_name": "", "dns_computer_name": "", "dns_domain_name": ""}
	sock = None
	try:
		sock = socket.create_connection((ip, 445), timeout=timeout)
		sock.settimeout(timeout)

		sock.sendall(_build_smb2_negotiate_request())
		negotiate_nb_header = _recv_exact(sock, 4)
		negotiate_len = int.from_bytes(negotiate_nb_header[1:4], "big")
		_recv_exact(sock, negotiate_len)

		security_blob = _build_ntlm_negotiate_message()
		sock.sendall(_build_smb2_session_setup_request(security_blob))

		response_nb_header = _recv_exact(sock, 4)
		response_len = int.from_bytes(response_nb_header[1:4], "big")
		response = _recv_exact(sock, response_len)

		if len(response) < 72 or response[0:4] != b"\xfeSMB":
			if diagnostics is not None:
				diagnostics.append("smb_ntlm_probe: unexpected SMB2 session setup response")
			return outcome

		status = struct.unpack("<I", response[8:12])[0]
		if status not in (0xC0000016, 0x00000000):
			if diagnostics is not None:
				diagnostics.append(f"smb_ntlm_probe: unexpected NT status 0x{status:08x}")
			return outcome

		body = response[64:]
		if len(body) < 8:
			if diagnostics is not None:
				diagnostics.append("smb_ntlm_probe: session setup response body too short")
			return outcome

		sec_buf_offset = struct.unpack("<H", body[4:6])[0]
		sec_buf_len = struct.unpack("<H", body[6:8])[0]
		security_buffer = response[sec_buf_offset:sec_buf_offset + sec_buf_len]

		if not security_buffer.startswith(b"NTLMSSP\x00"):
			if diagnostics is not None:
				diagnostics.append("smb_ntlm_probe: security buffer is not an NTLMSSP challenge")
			return outcome

		outcome = _parse_ntlm_target_info(security_buffer)

	except (OSError, socket.timeout, struct.error) as exc:
		if diagnostics is not None:
			diagnostics.append(f"smb_ntlm_probe: {exc}")
	finally:
		if sock is not None:
			try:
				sock.close()
			except Exception:
				pass
	return outcome


def _resolve_host_netbios_name(ip: str, timeout: float = 5.0, diagnostics: list[str] | None = None) -> dict:
	smb_result = _probe_smb_ntlm_target_info(ip, timeout=timeout, diagnostics=diagnostics)
	if smb_result.get("computer_name") or smb_result.get("domain_name"):
		return {
			"computer_name": smb_result.get("computer_name") or "",
			"domain_name": smb_result.get("domain_name") or "",
			"dns_computer_name": smb_result.get("dns_computer_name") or "",
			"dns_domain_name": smb_result.get("dns_domain_name") or "",
		}

	nbt_result = _get_host_netbios_info(ip, timeout=timeout, diagnostics=diagnostics)
	return {
		"computer_name": nbt_result.get("computer_name") or "",
		"domain_name": nbt_result.get("domain_name") or "",
		"dns_computer_name": "",
		"dns_domain_name": "",
	}


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


def _get_netbios_name(conn: Connection, base_dn: str, config_dn: str, diagnostics: list[str] | None = None) -> str:
	if not base_dn or not config_dn:
		return ""
	partitions_dn = f"CN=Partitions,{config_dn}"
	ldap_filter = f"(&(objectClass=crossRef)(nCName={base_dn}))"
	try:
		entry = _search_first_entry(conn, partitions_dn, ldap_filter, ["nETBIOSName"], search_scope=SUBTREE)
	except Exception as exc:
		if diagnostics is not None:
			diagnostics.append(f"netbios_lookup: {exc}")
		return ""
	if not entry:
		return ""
	return str(normalize_value(getattr(entry, "nETBIOSName", None)) or "")


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


def get_domain_info_unauth(ip: str, domain: str, config) -> dict:
	generated_at = datetime.now(timezone.utc).isoformat()
	base_dn = domain_to_dn(domain)
	result = {
		"success": False,
		"auth_mode": "unauthenticated",
		"count": 0,
		"error": None,
		"meta": {},
		"fqdn": domain,
		"netbios_name": (domain or "").split(".")[0].upper(),
		"netbios_computer_name": "",
		"domain_sid": "",
		"functional_level": None,
		"functional_level_name": "Unknown",
		"generated_at": generated_at,
		"smb_signing_policy_present": None,
		"smb_signing_enabled": None,
		"smb_signing_required": None,
		"ntlm_supported": None,
		"smart_card_required": None,
		"machine_account_quota": None,
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

	smb_signing = _check_smb_signing(ip, timeout=getattr(config, "SMB_PROBE_TIMEOUT", 5), diagnostics=diagnostics)
	result["smb_signing_enabled"] = smb_signing.get("enabled")
	result["smb_signing_required"] = smb_signing.get("required")
	result["smb_signing_policy_present"] = smb_signing.get("required") is not None

	host_netbios = _resolve_host_netbios_name(ip, timeout=getattr(config, "SMB_PROBE_TIMEOUT", 5), diagnostics=diagnostics)
	result["netbios_computer_name"] = host_netbios.get("computer_name") or ""
	if host_netbios.get("domain_name"):
		result["netbios_name"] = host_netbios["domain_name"]

	result["ntlm_supported"] = _probe_ntlm_support(ip, domain, config, diagnostics=diagnostics)

	conn = None
	try:
		conn = _connect_anonymous(ip, config)
	except (LDAPInvalidCredentialsResult, LDAPSocketOpenError, LDAPException, OSError, ValueError) as exc:
		diagnostics.append(f"anonymous_bind: {exc}")

	config_dn = ""
	if conn is not None:
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
					"supportedSASLMechanisms",
					"ldapServiceName",
				],
				debug_label="rootdse_anon",
				diagnostics=diagnostics,
			)

			if rootdse:
				config_dn = str(normalize_value(getattr(rootdse, "configurationNamingContext", None)) or "")
				functional_level = normalize_value(getattr(rootdse, "domainFunctionality", None))
				result["functional_level"] = safe_int(functional_level, None) if functional_level is not None else None
				result["functional_level_name"] = _domain_level_name(functional_level)
				sasl_mechs = [str(m) for m in normalize_values(getattr(rootdse, "supportedSASLMechanisms", None))]
				if sasl_mechs:
					result["meta"]["supported_sasl_mechanisms"] = sasl_mechs
				result["meta"].update(
					{
						"configuration_naming_context": config_dn,
						"schema_naming_context": str(normalize_value(getattr(rootdse, "schemaNamingContext", None)) or ""),
						"root_domain_naming_context": str(normalize_value(getattr(rootdse, "rootDomainNamingContext", None)) or ""),
						"default_naming_context": str(normalize_value(getattr(rootdse, "defaultNamingContext", None)) or base_dn),
					}
				)

				netbios_name = _get_netbios_name(conn, base_dn, config_dn, diagnostics=diagnostics)
				if netbios_name:
					result["netbios_name"] = netbios_name
			else:
				result["meta"]["default_naming_context"] = base_dn

			try:
				result["domain_controllers"] = _collect_domain_controllers(conn, base_dn, domain, {})
			except Exception as exc:
				diagnostics.append(f"anon_dc_enum: {exc}")

			try:
				result["ca_list"] = _collect_certificate_services(conn, config_dn)
				result["has_enterprise_ca"] = bool(result["ca_list"])
			except Exception as exc:
				diagnostics.append(f"anon_ca_enum: {exc}")

			result["success"] = True
			result["count"] = 1
		except Exception as exc:
			diagnostics.append(f"anonymous_lookup: {exc}")
		finally:
			try:
				conn.unbind()
			except Exception:
				pass
	else:
		result["error"] = "Anonymous LDAP bind was not possible"

	if not result["success"] and result["smb_signing_policy_present"]:
		result["success"] = True
		result["count"] = 1
		result["error"] = None

	findings = _build_risk_findings(
		machine_account_quota=0,
		smart_card_required=True,
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

	return result


def get_domain_info(ip: str, domain: str, username: str, password: str, config, conn=None, base_dn=None) -> dict:
	generated_at = datetime.now(timezone.utc).isoformat()
	base_dn = base_dn or domain_to_dn(domain)
	owns_connection = conn is None
	result = {
		"success": False,
		"count": 0,
		"error": None,
		"meta": {},
		"fqdn": domain,
		"netbios_name": (domain or "").split(".")[0].upper(),
		"netbios_computer_name": "",
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

	username_has_explicit_bind_format = "@" in (username or "") or "\\" in (username or "")

	if username_has_explicit_bind_format:
		resolved_netbios_name = None
		diagnostics.append(
			"netbios_prebind: skipped — username already contains an explicit bind format "
			"(DOMAIN\\user or user@domain), using it as-is without any resolution/probing"
		)
	else:
		resolved_netbios_name = _resolve_domain_netbios_name_prebind(ip, domain, config, diagnostics=diagnostics)
		if resolved_netbios_name and resolved_netbios_name != (domain or "").split(".")[0].upper():
			diagnostics.append(
				f"netbios_prebind: guessed name would have been "
				f"'{(domain or '').split('.')[0].upper()}', using real LDAP-resolved name "
				f"'{resolved_netbios_name}' for bind instead"
			)

	try:
		if owns_connection:
			conn = _connect(ip, domain, username, password, config, netbios_name=resolved_netbios_name)
	except (LDAPInvalidCredentialsResult, LDAPSocketOpenError, LDAPException, OSError, ValueError) as exc:
		result["error"] = str(exc)
		if diagnostics:
			result["meta"]["lookup_warnings"] = diagnostics
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

		netbios_name = _get_netbios_name(conn, base_dn, config_dn, diagnostics=diagnostics)
		if netbios_name:
			result["netbios_name"] = netbios_name

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

		result["ntlm_supported"] = _check_ntlm_supported(ip, domain, username, password, config, diagnostics=diagnostics, netbios_name=resolved_netbios_name)

		smb_signing = _check_smb_signing(ip, timeout=getattr(config, "SMB_PROBE_TIMEOUT", 5), diagnostics=diagnostics)
		result["smb_signing_enabled"] = smb_signing.get("enabled")
		result["smb_signing_required"] = smb_signing.get("required")
		result["smb_signing_policy_present"] = smb_signing.get("required") is not None

		host_netbios = _resolve_host_netbios_name(ip, timeout=getattr(config, "SMB_PROBE_TIMEOUT", 5), diagnostics=diagnostics)
		result["netbios_computer_name"] = host_netbios.get("computer_name") or ""

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
	finally:
		if owns_connection and conn is not None:
			try:
				conn.unbind()
			except Exception:
				pass


__all__ = ["get_domain_info", "get_domain_info_unauth"]


import argparse
import json
import sys


class _C:
	RESET = "\033[0m"
	BOLD = "\033[1m"
	DIM = "\033[2m"
	RED = "\033[31m"
	GREEN = "\033[32m"
	YELLOW = "\033[33m"
	BLUE = "\033[34m"
	MAGENTA = "\033[35m"
	CYAN = "\033[36m"
	WHITE = "\033[97m"
	GRAY = "\033[90m"

	@staticmethod
	def enabled() -> bool:
		return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text, color, use_color=True):
	if not use_color:
		return str(text)
	return f"{color}{text}{_C.RESET}"


_SEVERITY_COLOR = {
	"critical": _C.MAGENTA,
	"high": _C.RED,
	"medium": _C.YELLOW,
	"low": _C.BLUE,
	"info": _C.GRAY,
}


def _bool_str(value, use_color=True):
	if value is None:
		return _c("Unknown", _C.GRAY, use_color)
	if value is True:
		return _c("Yes", _C.GREEN, use_color)
	return _c("No", _C.RED, use_color)


def _section(title, use_color=True):
	line = "─" * max(4, len(title) + 2)
	print()
	print(_c(f"┌{line}┐", _C.CYAN, use_color))
	print(_c(f"  {title}", _C.CYAN + _C.BOLD, use_color))
	print(_c(f"└{line}┘", _C.CYAN, use_color))


def _kv(key, value, use_color=True, key_width=28):
	key_str = _c(f"{key:<{key_width}}", _C.WHITE + _C.BOLD, use_color)
	print(f"  {key_str} {value}")


def print_domain_info(result: dict, use_color: bool | None = None) -> None:
	if use_color is None:
		use_color = _C.enabled()

	success = result.get("success")
	header_color = _C.GREEN if success else _C.RED
	status_text = "SUCCESS" if success else "FAILED"

	print()
	print(_c("=" * 60, header_color, use_color))
	print(_c(f"  DOMAIN INFORMATION — Status: {status_text}", header_color + _C.BOLD, use_color))
	print(_c("=" * 60, header_color, use_color))

	if not success:
		print()
		print(_c(f"  Error: {result.get('error')}", _C.RED, use_color))
		print()
		return

	_section("General information", use_color)
	_kv("FQDN", _c(result.get("fqdn") or "-", _C.CYAN, use_color), use_color)
	_kv("NetBIOS name", result.get("netbios_computer_name") or "-", use_color)
	_kv("NetBIOS domain name", result.get("netbios_name") or "-", use_color)
	_kv("Domain SID", result.get("domain_sid") or "-", use_color)
	_kv("Functional level", f"{result.get('functional_level_name')} ({result.get('functional_level')})", use_color)
	_kv("Generated at", result.get("generated_at") or "-", use_color)

	_section("Security indicators", use_color)
	_kv("NTLM supported", _bool_str(result.get("ntlm_supported"), use_color), use_color)
	_kv("SMB signing enabled", _bool_str(result.get("smb_signing_enabled"), use_color), use_color)
	_kv("SMB signing required", _bool_str(result.get("smb_signing_required"), use_color), use_color)
	_kv("Smart card required", _bool_str(result.get("smart_card_required"), use_color), use_color)
	maq = result.get("machine_account_quota")
	_kv("Machine Account Quota", maq if maq is not None else _c("Unknown", _C.GRAY, use_color), use_color)
	_kv("Enterprise CA present", _bool_str(result.get("has_enterprise_ca"), use_color), use_color)

	severity = str(result.get("highest_severity") or "info").lower()
	sev_color = _SEVERITY_COLOR.get(severity, _C.GRAY)
	_section("Risk assessment", use_color)
	_kv("Risk score", _c(result.get("risk_score"), sev_color + _C.BOLD, use_color), use_color)
	_kv("Highest severity", _c(severity.upper(), sev_color + _C.BOLD, use_color), use_color)

	findings = result.get("risk_findings") or []
	if findings:
		print()
		for f in findings:
			f_sev = str(f.get("severity") or "info").lower()
			f_color = _SEVERITY_COLOR.get(f_sev, _C.GRAY)
			badge = _c(f" {f_sev.upper():<8} ", _C.BOLD + f_color, use_color)
			print(f"  [{badge}] {_c(f.get('title') or '-', _C.WHITE + _C.BOLD, use_color)}")
			print(f"             {_c(f.get('detail') or '-', _C.GRAY, use_color)}")
	else:
		print(f"\n  {_c('No risks were detected.', _C.GREEN, use_color)}")

	fsmo = result.get("fsmo") or {}
	_section("FSMO Roles", use_color)
	for role, owner in fsmo.items():
		_kv(role, owner or _c("-", _C.GRAY, use_color), use_color)

	dcs = result.get("domain_controllers") or []
	_section(f"Domain Controllers ({len(dcs)})", use_color)
	if not dcs:
		print(f"  {_c('No domain controllers found.', _C.GRAY, use_color)}")
	for dc in dcs:
		roles = [
			label for label, flag in (
				("Schema", dc.get("is_schema_master")),
				("Naming", dc.get("is_naming_master")),
				("RID", dc.get("is_rid_master")),
				("PDC", dc.get("is_pdc_emulator")),
				("Infra", dc.get("is_infrastructure_master")),
			) if flag
		]
		roles_str = _c(f" [{', '.join(roles)}]", _C.YELLOW + _C.BOLD, use_color) if roles else ""
		print(f"  • {_c(dc.get('fqdn') or dc.get('cn') or '-', _C.CYAN, use_color)}{roles_str}")
		print(f"      OS: {dc.get('os') or '-'} {dc.get('os_version') or ''}")

	cas = result.get("ca_list") or []
	if cas:
		_section(f"Certificate Services / CA ({len(cas)})", use_color)
		for ca in cas:
			print(f"  • {_c(ca.get('cn') or '-', _C.CYAN, use_color)}  ({ca.get('dns_name') or '-'})")

	warnings = (result.get("meta") or {}).get("lookup_warnings") or []
	if warnings:
		_section("Diagnostic warnings", use_color)
		for w in warnings:
			print(f"  {_c('!', _C.YELLOW + _C.BOLD, use_color)} {_c(w, _C.GRAY, use_color)}")

	print()
	print(_c("=" * 60, header_color, use_color))
	print()


def save_domain_info_json(result: dict, path: str = "domain_info.jsonl") -> str:
	with open(path, "a", encoding="utf-8") as f:
		f.write(json.dumps(result, ensure_ascii=False, default=str))
		f.write("\n")
	return path


def main() -> int:
	parser = argparse.ArgumentParser(description="Domain (Active Directory) information gathering tool")
	parser.add_argument("-i", "--ip", required=True, help="Domain controller IP address")
	parser.add_argument("-d", "--domain", required=True, help="Domain FQDN (e.g. corp.local)")
	parser.add_argument("-u", "--username", required=False, default=None, help="Username (if omitted, runs in unauthenticated mode)")
	parser.add_argument("-p", "--password", required=False, default=None, help="Password or NTLM hash (if omitted, runs in unauthenticated mode)")
	parser.add_argument("-o", "--output", default="domain_info.jsonl", help="JSONL file to write the result to (default: domain_info.jsonl)")
	parser.add_argument("--no-color", action="store_true", help="Disable colored output")
	args = parser.parse_args()

	if bool(args.username) != bool(args.password):
		parser.error("-u/--username and -p/--password must be provided together (one alone is not enough).")

	use_color = not args.no_color

	if args.username and args.password:
		print(_c("[*] Authenticated mode: running all checks sequentially...", _C.CYAN + _C.BOLD, use_color))
		result = get_domain_info(args.ip, args.domain, args.username, args.password, Config)
	else:
		print(_c("[*] Unauthenticated mode: running only anonymous/protocol-level checks...", _C.CYAN + _C.BOLD, use_color))
		result = get_domain_info_unauth(args.ip, args.domain, Config)

	output_path = save_domain_info_json(result, args.output)
	print_domain_info(result, use_color=use_color)
	print(_c(f"Result appended to JSONL file: {output_path}", _C.GREEN + _C.BOLD, use_color))

	return 0 if result.get("success") else 1


if __name__ == "__main__":
	sys.exit(main())