"""
core/env_utils.py
─────────────────
Virtual environment mühit dəyişənlərini qurar.
"""

from __future__ import annotations

import os
from pathlib import Path

from .config import ROOT


def build_env(extra: dict | None = None) -> dict:
    """
    Proses üçün mühit dəyişənlərini hazırlayır.
    `extra` — subprocess-ə ötürüləcək əlavə dəyişənlər (məs. PORT, HOST).
    """
    env = os.environ.copy()
    venv_bin = ROOT / "oxsium" / ("Scripts" if os.name == "nt" else "bin")

    env["PATH"]                  = str(venv_bin) + os.pathsep + env.get("PATH", "")
    env["VIRTUAL_ENV"]           = str(ROOT / "oxsium")
    env["PYTHONUNBUFFERED"]      = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    if extra:
        env.update(extra)
    return env