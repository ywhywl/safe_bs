#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, make_base_record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    baselines = load_json(json_dir / "task2_user_baselines.json", {}).get("users", [])
    views = []
    for item in baselines:
        views.append(
            {
                "user": item.get("user"),
                "summary": f"user={item.get('user')} sample_size={item.get('sample_size')} failure_rate={item.get('usual_failure_rate')}",
                "typical_login_window": item.get("active_time_profile", []),
                "common_sources": item.get("usual_src_ips", []),
                "common_paths": item.get("usual_paths", []),
                "common_actions": item.get("usual_actions", []),
                "suspicious_patterns_to_watch": [
                    "new source ip",
                    "new action type",
                    "access outside known hours",
                ],
                "generated_at": "",
            }
        )
    record = make_base_record(run_dir.name, "task2", "build_baseline_views.py")
    record["views"] = views
    dump_json(json_dir / "task2_baseline_views.json", record)


if __name__ == "__main__":
    main()
