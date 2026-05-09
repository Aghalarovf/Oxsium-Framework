"""DCSync backend stubs.

The DCSync GUI is preserved, but backend execution and persistence were removed.
These helpers keep imports and API routes working without performing any action.
"""


def _read_dcsync_history() -> list[dict]:
    return []


def save_kerberos_key(req: dict) -> dict:
    return {"success": False, "error": "DCSync backend removed; saving keys disabled", "code": 410}


def run_dcsync_tool(req: dict) -> dict:
    return {"success": False, "error": "DCSync backend removed; execution disabled", "code": 410}