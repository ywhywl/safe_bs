#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from event_io import iter_ndjson, write_ndjson_line
from lib import dump_json, make_base_record


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
    sessions = defaultdict(
        lambda: {
            "users": set(),
            "src_ips": set(),
            "start_time": "",
            "end_time": "",
            "action_sequence": [],
            "paths": set(),
            "results": set(),
            "event_count": 0,
            "open_count": 0,
            "close_count": 0,
            "login_success_count": 0,
            "login_failure_count": 0,
        }
    )
    auth_success_by_ip = defaultdict(list)
    for event in iter_ndjson(json_dir / "task2_events.ndjson"):
        session_id = event.get("session_id") or f"user:{event.get('user')}"
        item = sessions[session_id]
        item["event_count"] += 1
        if event.get("user"):
            item["users"].add(event["user"])
        if event.get("src_ip"):
            item["src_ips"].add(event["src_ip"])
        ts = event.get("timestamp", "")
        if not item["start_time"] or ts < item["start_time"]:
            item["start_time"] = ts
        if not item["end_time"] or ts > item["end_time"]:
            item["end_time"] = ts
        if event.get("action"):
            item["action_sequence"].append(event["action"])
        if event.get("path"):
            item["paths"].add(event["path"])
        if event.get("result"):
            item["results"].add(event["result"])
        if event.get("action") == "SESSION_OPEN":
            item["open_count"] += 1
        if event.get("action") == "SESSION_CLOSE":
            item["close_count"] += 1
        if event.get("action") in {"LOGIN", "AUTH"} and event.get("result") == "ok":
            item["login_success_count"] += 1
            if event.get("src_ip") and event.get("user") and event.get("user") != "unknown":
                ts = parse_ts(event.get("timestamp", ""))
                if ts is not None:
                    auth_success_by_ip[event["src_ip"]].append({"timestamp": ts, "user": event["user"]})
        if event.get("action") in {"LOGIN", "AUTH"} and event.get("result") == "fail":
            item["login_failure_count"] += 1

    ndjson_path = json_dir / "task2_session_views.ndjson"
    ndjson_path.unlink(missing_ok=True)
    preview = []
    sessions_output = []
    count = 0
    with ndjson_path.open("a", encoding="utf-8") as out:
        for session_id, item in sorted(sessions.items()):
            users = sorted(item["users"])
            inferred_user = ""
            if users == ["unknown"] and len(item["src_ips"]) == 1:
                src_ip = next(iter(item["src_ips"]))
                start = parse_ts(item["start_time"])
                if start is not None:
                    candidates = auth_success_by_ip.get(src_ip, [])
                    best = None
                    best_delta = None
                    for candidate in candidates:
                        delta = abs((candidate["timestamp"] - start).total_seconds())
                        if delta <= 300 and (best_delta is None or delta < best_delta):
                            best = candidate
                            best_delta = delta
                    if best is not None:
                        inferred_user = best["user"]
            record = {
                "session_id": session_id,
                "users": users,
                "src_ips": sorted(item["src_ips"]),
                "start_time": item["start_time"],
                "end_time": item["end_time"],
                "action_sequence": item["action_sequence"],
                "paths": sorted(item["paths"]),
                "results": sorted(item["results"]),
                "event_count": item["event_count"],
                "open_count": item["open_count"],
                "close_count": item["close_count"],
                "login_success_count": item["login_success_count"],
                "login_failure_count": item["login_failure_count"],
                "unbalanced_session": item["open_count"] > item["close_count"],
                "inferred_user": inferred_user,
                "summary": f"session={session_id} users={users} inferred_user={inferred_user or '-'} src_ips={sorted(item['src_ips'])} actions={item['action_sequence']}",
            }
            write_ndjson_line(ndjson_path, record, handle=out)
            sessions_output.append(record)
            count += 1
            if len(preview) < 200:
                preview.append(record)

    record = make_base_record(run_dir.name, "task2", "build_session_views.py")
    record["session_count"] = count
    record["sessions"] = sessions_output
    record["sessions_preview"] = preview
    dump_json(json_dir / "task2_session_views.json", record)


if __name__ == "__main__":
    main()
