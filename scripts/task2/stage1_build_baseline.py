#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from event_io import iter_ndjson
from lib import dump_json, load_json, make_base_record


def parse_hour(value: str) -> int | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).hour
    except ValueError:
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    baseline_events_path = json_dir / "task2_baseline_events.ndjson"
    events_path = baseline_events_path if baseline_events_path.exists() else json_dir / "task2_events.ndjson"
    events_meta = load_json(json_dir / "task2_events.json", {})

    stats = defaultdict(
        lambda: {
            "src_ips": set(),
            "src_subnets": set(),
            "target_servers": set(),
            "actions": set(),
            "client_versions": set(),
            "active_hours": set(),
            "failure_count": 0,
            "success_count": 0,
            "bytes_out_sum": 0,
            "bytes_total_sum": 0,
            "sample_size": 0,
        }
    )

    skipped_unknown = 0

    for event in iter_ndjson(events_path):
        user = event.get("user", "unknown")

        # Skip unattributed events — "unknown" baselines have zero audit value
        # Also reject timestamp-like strings that leaked in via fallback parsing
        if user in {"unknown", "", "USER"} or re.match(r"^\d{2}:\d{2}:\d{2}", user):
            skipped_unknown += 1
            continue

        stat = stats[user]
        src_ip = event.get("src_ip", "")
        src_subnet = event.get("src_subnet", "")
        target = event.get("system_name") or event.get("server_ip", "")
        action = event.get("action", "")
        result = event.get("result", "")
        client_version = event.get("client_version", "")
        hour = parse_hour(event.get("timestamp", ""))
        total_bytes = event.get("bytes_in", 0) + event.get("bytes_out", 0)

        if src_ip:
            stat["src_ips"].add(src_ip)
        if src_subnet:
            stat["src_subnets"].add(src_subnet)
        if target:
            stat["target_servers"].add(target)
        if action:
            stat["actions"].add(action)
        if client_version:
            stat["client_versions"].add(client_version)
        if hour is not None:
            stat["active_hours"].add(hour)
        if result == "ok":
            stat["success_count"] += 1
        elif result:
            stat["failure_count"] += 1
        stat["bytes_out_sum"] += event.get("bytes_out", 0)
        stat["bytes_total_sum"] += total_bytes
        stat["sample_size"] += 1

    users = []
    for user, stat in sorted(stats.items()):
        sample_size = stat["sample_size"]
        users.append(
            {
                "user": user,
                "usual_src_ips": sorted(stat["src_ips"])[:200],
                "usual_src_subnets": sorted(stat["src_subnets"])[:100],
                "usual_target_servers": sorted(stat["target_servers"])[:100],
                "usual_actions": sorted(stat["actions"]),
                "usual_client_versions": sorted(stat["client_versions"])[:50],
                "active_time_profile": sorted(stat["active_hours"]),
                "usual_failure_rate": round(stat["failure_count"] / max(sample_size, 1), 4),
                "avg_bytes_out": round(stat["bytes_out_sum"] / max(sample_size, 1), 2),
                "avg_total_bytes": round(stat["bytes_total_sum"] / max(sample_size, 1), 2),
                "sample_size": sample_size,
            }
        )

    record = make_base_record(run_dir.name, "task2", "stage1_build_baseline.py")
    record["skipped_unknown_user_events"] = skipped_unknown
    record.update(
        {
            "baseline_mode": "historical_split" if baseline_events_path.exists() else "single_dataset",
            "baseline_event_count": events_meta.get("baseline_event_count", 0) if baseline_events_path.exists() else events_meta.get("event_count", 0),
            "current_event_count": events_meta.get("event_count", 0),
            "events_source_path": str(events_path),
            "users": users,
        }
    )
    dump_json(json_dir / "task2_stage1_baselines.json", record)


if __name__ == "__main__":
    main()
