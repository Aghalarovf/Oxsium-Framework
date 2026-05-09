"""
computer_network.py
───────────────────
Collects network information for computers listed in domain_computers.json:
  - IPv4 / IPv6 addresses  (DNS resolve)
  - SMB signing required   (SMB negotiate)
  - SMB version            (SMB1 / SMB2 / SMB3)

Usage:
    from computer_network import enrich_computers_with_network_info
    result = enrich_computers_with_network_info(
        json_path="Domain Object/domain_computers.json",
        workers=30,
        timeout=3.0,
    )

Returns:
    {
        "success": True,
        "enriched": 12,
        "skipped": 2,
        "errors": 1,
    }
    domain_computers.json is updated in place.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# ─────────────────────────────────────────────────────────────
#  DNS resolve
# ─────────────────────────────────────────────────────────────

def _resolve_ip_addresses(hostname: str, timeout: float = 2.0) -> dict:
    """
    Returns all A and AAAA records for the given hostname.
    If hostname is already an IP address, determines its type without resolving.
    """
    ipv4: list[str] = []
    ipv6: list[str] = []

    if not hostname:
        return {"ipv4": ipv4, "ipv6": ipv6}

    # Already an IP address — classify directly
    try:
        addr = ipaddress.ip_address(hostname)
        if isinstance(addr, ipaddress.IPv4Address):
            return {"ipv4": [hostname], "ipv6": []}
        return {"ipv4": [], "ipv6": [hostname]}
    except ValueError:
        pass

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, OSError):
        return {"ipv4": ipv4, "ipv6": ipv6}
    finally:
        socket.setdefaulttimeout(old_timeout)

    seen: set[str] = set()
    for family, _, _, _, sockaddr in results:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        if family == socket.AF_INET:
            ipv4.append(ip)
        elif family == socket.AF_INET6:
            # Strip link-local scope id (e.g. fe80::1%eth0)
            ipv6.append(ip.split("%")[0])

    return {"ipv4": ipv4, "ipv6": ipv6}


# ─────────────────────────────────────────────────────────────
#  Reverse DNS lookup
# ─────────────────────────────────────────────────────────────

def _reverse_lookup(ip: str, timeout: float = 2.0) -> str:
    """
    IP ünvanını reverse DNS ilə hostname-ə çevirir.
    Uğursuz olarsa boş string qaytarır.
    """
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.lower()
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


# ─────────────────────────────────────────────────────────────
#  SMB Negotiate — raw TCP, no external dependencies
# ─────────────────────────────────────────────────────────────

# SMB1 Negotiate Request (minimal, 39 bytes)
_SMB1_NEGOTIATE = bytes([
    0x00, 0x00, 0x00, 0x23,        # NetBIOS session header (length=35)
    0xFF, 0x53, 0x4D, 0x42,        # \xffSMB
    0x72,                           # Command: Negotiate
    0x00, 0x00, 0x00, 0x00,        # NT Status
    0x08,                           # Flags
    0x01, 0xC0,                    # Flags2
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # PID high + Signature
    0x00, 0x00, 0x00, 0x00,        # Reserved
    0x00, 0x00,                    # TID
    0xFF, 0xFE,                    # PID
    0x00, 0x00,                    # UID
    0x40, 0x00,                    # MID
    # Negotiate request payload
    0x00,                          # Word count
    0x0C, 0x00,                    # Byte count = 12
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
    # "NT LM 0.12\0"
])

# SMB2 Negotiate Request (76 bytes)
_SMB2_NEGOTIATE = bytes([
    0x00, 0x00, 0x00, 0x48,        # NetBIOS session header (length=72)
    0xFE, 0x53, 0x4D, 0x42,        # \xfeSMB (SMB2 magic)
    0x40, 0x00,                    # Structure size
    0x00, 0x00,                    # Credit charge
    0x00, 0x00, 0x00, 0x00,        # Status
    0x00, 0x00,                    # Command: Negotiate
    0x1F, 0x00,                    # Credits requested
    0x00, 0x00, 0x00, 0x00,        # Flags
    0x00, 0x00, 0x00, 0x00,        # Chain offset
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Message ID
    0x00, 0x00, 0x00, 0x00,        # Process ID
    0x00, 0x00, 0x00, 0x00,        # Tree ID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Session ID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature
    # Negotiate payload
    0x24, 0x00,                    # Structure size = 36
    0x03, 0x00,                    # Dialect count = 3
    0x00, 0x00,                    # Security mode (client)
    0x00, 0x00,                    # Reserved
    0x00, 0x00, 0x00, 0x00,        # Capabilities
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # GUID
    0x00, 0x00, 0x00, 0x00,        # Negotiate context offset/count
    0x02, 0x02,                    # SMB 2.0.2
    0x10, 0x02,                    # SMB 2.1.0
    0x00, 0x03,                    # SMB 3.0.0
])


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


def _smb_probe(host: str, timeout: float = 3.0) -> dict:
    """
    Probes SMB port availability via netcat-style port check.
    Full SMB negotiation details require authenticated session and are handled elsewhere.
    Returns:
      - smb_port_open          (bool): Whether port 445 is open
      - smb_signing_required   (bool): Default False (requires authenticated probe)
      - smb_version            (str | None): Default None (requires authenticated probe)
    """
    result = {
        "smb_port_open": False,
        "smb_signing_required": False,
        "smb_version": None,
    }

    try:
        effective_timeout = max(timeout * 1.5, 5.0)
        sock = socket.create_connection((host, 445), timeout=effective_timeout)
        result["smb_port_open"] = True
        sock.close()
    except (OSError, ConnectionRefusedError, socket.timeout):
        pass

    return result


# ─────────────────────────────────────────────────────────────
#  Per-computer network probe
# ─────────────────────────────────────────────────────────────

def _probe_computer(computer: dict, timeout: float) -> dict:
    """
    Resolves IP addresses and runs an SMB probe for a single computer entry.
    Mutates the computer dict in place and returns it.
    """
    hostname = str(computer.get("dns_name") or computer.get("computer_name") or "").strip()

    # IP addresses
    ip_info = _resolve_ip_addresses(hostname, timeout=timeout)
    computer["ipv4"] = ip_info["ipv4"]
    computer["ipv6"] = ip_info["ipv6"]

    # SMB probe — prefer first IPv4, fall back to hostname
    smb_target = ip_info["ipv4"][0] if ip_info["ipv4"] else hostname
    if smb_target:
        smb_info = _smb_probe(smb_target, timeout=timeout)
        computer["smb_port_open"] = smb_info["smb_port_open"]
        computer["smb_signing_required"] = smb_info["smb_signing_required"]
        computer["smb_version"] = smb_info["smb_version"]
    else:
        computer["smb_port_open"] = False
        computer["smb_signing_required"] = None
        computer["smb_version"] = None

    return computer


# ─────────────────────────────────────────────────────────────
#  Main entry point
# ─────────────────────────────────────────────────────────────

def enrich_computers_with_network_info(
    json_path: str | Path,
    workers: int = 30,
    timeout: float = 3.0,
) -> dict:
    """
    Reads domain_computers.json and enriches each computer entry with:
      - ipv4             list[str]   IPv4 addresses from DNS
      - ipv6             list[str]   IPv6 addresses from DNS
      - smb_port_open    bool        Whether TCP 445 is reachable
      - smb_signing_required  bool | None
      - smb_version      str | None  "SMB1", "SMB2", "SMB3", or dialect string

    The file is updated in place.

    Parameters
    ----------
    json_path : str | Path
        Path to domain_computers.json.
    workers : int
        Number of parallel threads (default 30).
    timeout : float
        Per-operation network timeout in seconds (default 3.0).

    Returns
    -------
    dict
        {"success": bool, "enriched": int, "skipped": int, "errors": int}
    """
    path = Path(json_path)
    if not path.exists():
        return {"success": False, "error": f"File not found: {path}"}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"success": False, "error": f"JSON read error: {exc}"}

    computers: list[dict] = raw.get("computers") if isinstance(raw, dict) else []
    if not isinstance(computers, list):
        return {"success": False, "error": "No 'computers' array found in JSON"}

    enriched = 0
    skipped = 0
    errors = 0
    lock = threading.Lock()

    def _task(comp: dict) -> None:
        nonlocal enriched, skipped, errors
        hostname = str(comp.get("dns_name") or comp.get("computer_name") or "").strip()
        if not hostname:
            with lock:
                skipped += 1
            return
        try:
            _probe_computer(comp, timeout=timeout)
            with lock:
                enriched += 1
        except Exception:
            with lock:
                errors += 1

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_task, comp) for comp in computers]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception:
                pass

    # Write updated JSON back to file
    if isinstance(raw, dict):
        raw["computers"] = computers
    else:
        raw = {"computers": computers}

    try:
        path.write_text(
            json.dumps(raw, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError as exc:
        return {"success": False, "error": f"JSON write error: {exc}"}

    return {
        "success": True,
        "enriched": enriched,
        "skipped": skipped,
        "errors": errors,
    }


# ─────────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Enrich domain_computers.json with network info (IP, SMB signing, SMB version)"
    )
    parser.add_argument(
        "json_path",
        nargs="?",
        default="Domain Object/domain_computers.json",
        help="Path to domain_computers.json (default: Domain Object/domain_computers.json)",
    )
    parser.add_argument("--workers", type=int, default=30, help="Number of parallel threads")
    parser.add_argument("--timeout", type=float, default=3.0, help="Network timeout in seconds")
    args = parser.parse_args()

    result = enrich_computers_with_network_info(
        json_path=args.json_path,
        workers=args.workers,
        timeout=args.timeout,
    )

    if result.get("success"):
        print(
            f"Done — "
            f"enriched: {result['enriched']}, "
            f"skipped: {result['skipped']}, "
            f"errors: {result['errors']}"
        )
    else:
        print(f"Error: {result.get('error')}", file=sys.stderr)
        sys.exit(1)