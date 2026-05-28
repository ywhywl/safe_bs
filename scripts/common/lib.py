#!/usr/bin/env python3

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    ensure_dir(path.parent)
    path.write_text(content, encoding="utf-8")


def load_json(path: Path, default: Any | None = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, data: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def make_base_record(run_id: str, task_id: str, source_name: str, source_type: str = "script") -> dict[str, Any]:
    return {
        "run_id": run_id,
        "task_id": task_id,
        "created_at": utc_now(),
        "operator": os.environ.get("USER", "unknown"),
        "source_type": source_type,
        "source_name": source_name,
        "confidence": "medium",
        "evidence_refs": [],
        "manual_review_required": False,
        "notes": "",
    }


def render_markdown(title: str, sections: list[tuple[str, str]]) -> str:
    lines = [f"# {title}", ""]
    for heading, body in sections:
        lines.append(f"## {heading}")
        lines.append("")
        lines.append(body.strip() if body.strip() else "待补充。")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
