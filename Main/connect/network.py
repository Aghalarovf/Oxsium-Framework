import socket
import errno as _errno

from connect.config import Config


_HOST_PROBE_PORTS = [445, 135, 3389, 5985, 5986, 389, 636, 80, 443, 22, 8080, 8443, 53, 88, 464]


def _tcp_probe(ip: str, port: int, timeout: float) -> str:
    """Single TCP probe. Returns 'open', 'closed' (RST), or 'filtered' (timeout/error)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        err = sock.connect_ex((ip, port))
        if err == 0:
            return 'open'
        if err in (getattr(_errno, 'ECONNREFUSED', 111),):
            return 'closed'
        return 'filtered'
    except ConnectionRefusedError:
        return 'closed'
    except OSError:
        return 'filtered'
    finally:
        sock.close()


def host_up(ip: str, extra_ports: list = None, timeout: float = 3) -> tuple[bool, int]:
    probe_order = list(extra_ports or []) + _HOST_PROBE_PORTS
    seen: set = set()
    for port in probe_order:
        if port in seen:
            continue
        seen.add(port)
        result = _tcp_probe(ip, port, timeout)
        if result in ('open', 'closed'):
            return True, port
    return False, 0


def check_port(ip: str, port: int, timeout: int = Config.PORT_CHECK_TIMEOUT) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False