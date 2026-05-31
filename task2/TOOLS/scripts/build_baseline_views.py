#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, load_task2_runtime_config, make_base_record

VIEW_RENDER_LIMIT = 200  # max views stored in baseline_views.json for rendering


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    runtime_config = load_task2_runtime_config()
    render_limit = runtime_config.get("session_preview_limit", VIEW_RENDER_LIMIT)
    baselines = load_json(json_dir / "task2_user_baselines.json", {}).get("users", [])
    views = []
    for item in baselines[:render_limit]:
        # Convert sets back to sorted lists for display (baselines may have set fields after score_anomalies)
        src_ips = item.get("usual_src_ips", [])
        if isinstance(src_ips, set):
            src_ips = sorted(src_ips)
        paths = item.get("usual_paths", [])
        if isinstance(paths, set):
            paths = sorted(paths)
        actions = item.get("usual_actions", [])
        if isinstance(actions, set):
            actions = sorted(actions)
        clients = item.get("usual_client_versions", [])
        if isinstance(clients, set):
            clients = sorted(clients)
        kex = item.get("usual_kex_algorithms", [])
        if isinstance(kex, set):
            kex = sorted(kex)

        views.append(
            {
                "user": item.get("user"),
                "summary": f"user={item.get('user')} sample_size={item.get('sample_size')} failure_rate={item.get('usual_failure_rate')}",
                "typical_login_window": item.get("active_time_profile", [])[:10],
                "common_sources": src_ips[:10],
                "common_paths": paths[:10],
                "common_actions": actions[:10],
                "common_clients": clients[:5],
                "common_protocol_security": {
                    "kex": kex[:5],
                },
                "suspicious_patterns_to_watch": [
                    "new source ip",
                    "new action type",
                    "access outside known hours",
                    "weak ssh/sftp algorithm negotiation",
                    "legacy client fingerprint drift",
                ],
                "generated_at": "",
            }
        )
    record = make_base_record(run_dir.name, "task2", "build_baseline_views.py")
    record["total_user_count"] = len(baselines)
    record["rendered_view_count"] = len(views)
    record["views"] = views
    dump_json(json_dir / "task2_baseline_views.json", record)


if __name__ == "__main__":
    main()