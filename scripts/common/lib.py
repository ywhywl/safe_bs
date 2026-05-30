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


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError:
        return default


def load_task2_runtime_config() -> dict[str, Any]:
    large_mode = env_flag("TASK2_LARGE_MODE", True)
    defaults = {
        "large_mode": large_mode,
        "baseline_max_paths_per_user": 200 if large_mode else 5000,
        "baseline_max_path_count_keys_per_user": 200 if large_mode else 5000,
        "baseline_max_daily_buckets_per_user": 120 if large_mode else 1000,
        "baseline_max_ip_profile_per_user": 100 if large_mode else 2000,
        "baseline_max_src_ips_per_user": 1000 if large_mode else 5000,
        "baseline_max_src_subnets_per_user": 500 if large_mode else 2000,
        "baseline_max_session_ids_per_user": 3000 if large_mode else 10000,
        "baseline_max_session_sequences_per_user": 500 if large_mode else 5000,
        "baseline_max_actions_per_session": 8 if large_mode else 16,
        "session_preview_limit": 100 if large_mode else 200,
        "score_supporting_scores_limit": 30 if large_mode else 100,
        "score_supporting_event_ids_limit": 30 if large_mode else 100,
        "correlation_max_paths_per_ip": 10 if large_mode else 50,
        "correlation_max_sessions_per_ip": 10 if large_mode else 50,
        "correlation_max_candidate_ips_per_user": 10 if large_mode else 500,
        "correlation_max_candidate_ips_per_subnet": 10 if large_mode else 500,
        "correlation_max_time_samples_per_user_ip": 50 if large_mode else 500,
        "sequence_max_sessions": 1000 if large_mode else 50000,
        "sequence_max_actions_per_session": 8 if large_mode else 200,
        "report_representative_cases_limit": 10,
        "report_representative_sessions_limit": 10 if large_mode else 20,
    }
    config = {}
    for key, default in defaults.items():
        if isinstance(default, bool):
            config[key] = env_flag(key.upper(), default)
        elif isinstance(default, int):
            config[key] = env_int(key.upper(), default)
        else:
            config[key] = default
    return config


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
