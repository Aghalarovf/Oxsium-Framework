import json


def _removed(name: str) -> dict:
    return {"success": False, "error": f"Checker '{name}' removed from repository", "code": 410}


def run_local_inventory_c_tool() -> dict:
    return _removed("local_inventory")


def run_smb_checker_tool(req: dict) -> dict:
    return _removed("smb_checker")


def run_ntlm_checker_tool(req: dict) -> dict:
    return _removed("ntlm_checker")


def run_kerberos_checker_tool(req: dict) -> dict:
    return _removed("kerberos_checker")


# Simple protocol probe stubs
SIMPLE_PROTOCOL_CHECKERS = {}


def run_simple_protocol_probe(protocol_key: str, ip: str, timeout: float = 5.0) -> dict:
    return {"success": False, "error": f"Protocol checkers removed (requested: {protocol_key})", "code": 410}