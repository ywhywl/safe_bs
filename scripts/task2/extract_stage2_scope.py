#!/usr/bin/env python3

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from event_io import iter_ndjson, write_ndjson_line
from lib import dump_json, load_json, make_base_record


def parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    source_path = json_dir / "task2_events.ndjson"
    scoped_path = json_dir / "task2_events_scoped.ndjson"
    candidates = load_json(json_dir / "task2_stage1_candidates.json", {})

    candidate_users = set(candidates.get("candidate_users", []))
    candidate_src_ips = set(candidates.get("candidate_src_ips", []))
    candidate_sessions = set(candidates.get("candidate_sessions", []))
    candidate_targets = set(candidates.get("candidate_target_servers", []))
    candidate_windows = []
    for item in candidates.get("multi_target_source_candidates", []):
        start = parse_ts(item.get("window_start", ""))
        end = parse_ts(item.get("window_end", ""))
        if start is None or end is None:
            continue
        candidate_windows.append(
            {
                "src_ip": item.get("src_ip", ""),
                "start": start,
                "end": end,
                "targets": set(item.get("targets", [])),
                "users": set(item.get("users", [])),
            }
        )

    if not (candidate_users or candidate_src_ips or candidate_sessions or candidate_targets or candidate_windows):
        record = make_base_record(run_dir.name, "task2", "extract_stage2_scope.py")
        record.update(
            {
                "source_events_path": str(source_path),
                "scoped_events_path": str(scoped_path),
                "scoped_event_count": 0,
                "scope_mode": "full_fallback",
                "candidate_user_count": 0,
                "candidate_src_ip_count": 0,
                "candidate_session_count": 0,
                "candidate_target_count": 0,
                "scoped_events_preview": [],
            }
        )
        dump_json(json_dir / "task2_stage2_scope.json", record)
        return

    scoped_path.unlink(missing_ok=True)
    scoped_count = 0
    preview = []
    with scoped_path.open("a", encoding="utf-8") as out:
        for event in iter_ndjson(source_path):
            src_ip = event.get("src_ip", "")
            session_id = event.get("session_id", "")
            target = event.get("system_name") or event.get("server_ip", "")
            ts = parse_ts(event.get("timestamp", ""))
            matched = False
            if ts is not None and src_ip and target:
                for window in candidate_windows:
                    if window["src_ip"] != src_ip:
                        continue
                    if ts < window["start"] or ts > window["end"]:
                        continue
                    if window["targets"] and target not in window["targets"]:
                        continue
                    matched = True
                    break
            if not matched:
                matched = (
                    session_id in candidate_sessions
                    or (
                        src_ip in candidate_src_ips
                        and target
                        and target in candidate_targets
                    )
                )
            if not matched:
                continue
            write_ndjson_line(scoped_path, event, handle=out)
            scoped_count += 1
            if len(preview) < 50:
                preview.append(event)

    record = make_base_record(run_dir.name, "task2", "extract_stage2_scope.py")
    record.update(
        {
            "source_events_path": str(source_path),
            "scoped_events_path": str(scoped_path),
            "scoped_event_count": scoped_count,
            "scope_mode": "scoped",
            "candidate_user_count": len(candidate_users),
            "candidate_src_ip_count": len(candidate_src_ips),
            "candidate_session_count": len(candidate_sessions),
            "candidate_target_count": len(candidate_targets),
            "candidate_window_count": len(candidate_windows),
            "scoped_events_preview": preview,
        }
    )
    dump_json(json_dir / "task2_stage2_scope.json", record)


if __name__ == "__main__":
    main()
