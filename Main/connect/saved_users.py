import json
import os

_PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OLD_USERS_FILE = os.path.join(_PROJECT_ROOT, "old_users.json")


def _read_old_users() -> list[dict]:
    if not os.path.exists(OLD_USERS_FILE):
        return []
    try:
        with open(OLD_USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_old_users(items: list[dict]) -> None:
    with open(OLD_USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)