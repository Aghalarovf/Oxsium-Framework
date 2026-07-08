from __future__ import annotations

import ipaddress
import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def _resolve_ip_addresses(hostname: str, timeout: float = 2.0) -> dict:

    ipv4: list[str] = []
    ipv6: list[str] = []

    if not hostname:
        return {"ipv4": ipv4, "ipv6": ipv6}

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
            ipv6.append(ip.split("%")[0])

    return {"ipv4": ipv4, "ipv6": ipv6}


def _reverse_lookup(ip: str, timeout: float = 2.0) -> str:

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.lower()
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)

_SMB1_NEGOTIATE = bytes([
    0x00, 0x00, 0x00, 0x23,        
    0xFF, 0x53, 0x4D, 0x42,      
    0x72,                         
    0x00, 0x00, 0x00, 0x00,      
    0x08,                        
    0x01, 0xC0,                 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00,     
    0x00, 0x00,                
    0xFF, 0xFE,                 
    0x00, 0x00,                
    0x40, 0x00,                
    0x00,                      
    0x0C, 0x00,              
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
])

_SMB2_NEGOTIATE = bytes([
    0x00, 0x00, 0x00, 0x48,     
    0xFE, 0x53, 0x4D, 0x42,    
    0x40, 0x00,                
    0x00, 0x00,                  
    0x00, 0x00, 0x00, 0x00,     
    0x00, 0x00,                
    0x1F, 0x00,                
    0x00, 0x00, 0x00, 0x00,     
    0x00, 0x00, 0x00, 0x00,   
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00,       
    0x00, 0x00, 0x00, 0x00,        
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x24, 0x00,                  
    0x03, 0x00,                 
    0x00, 0x00,                  
    0x00, 0x00,                   
    0x00, 0x00, 0x00, 0x00,    
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
    0x00, 0x00, 0x00, 0x00,   
    0x02, 0x02,              
    0x10, 0x02,                
    0x00, 0x03,              
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


def _probe_computer(computer: dict, timeout: float) -> dict:

    hostname = str(computer.get("dns_name") or computer.get("computer_name") or "").strip()

    ip_info = _resolve_ip_addresses(hostname, timeout=timeout)
    computer["ipv4"] = ip_info["ipv4"]
    computer["ipv6"] = ip_info["ipv6"]

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


def enrich_computers_with_network_info(
    json_path: str | Path,
    workers: int = 30,
    timeout: float = 3.0,
) -> dict:

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