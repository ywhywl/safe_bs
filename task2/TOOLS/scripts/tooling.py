#!/usr/bin/env python3

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


SEARCHSPLOIT_FALLBACK = Path("/Users/wenlongy/dev/src/exploitdb/searchsploit")


def resolve_tool(name: str) -> str | None:
    path = shutil.which(name)
    if path:
        return path
    if name == "searchsploit" and SEARCHSPLOIT_FALLBACK.exists():
        return str(SEARCHSPLOIT_FALLBACK)
    return None


def run_optional_command(command: list[str], cwd: Path | None = None) -> dict:
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError:
        return {
            "available": False,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "command not found",
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "available": True,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
        }
    return {
        "available": True,
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }
