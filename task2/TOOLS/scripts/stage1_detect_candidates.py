#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from event_io import iter_ndjson
from input_layout import load_noise_policy, resolve_input_layout
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
    parser.add_argument("--input-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    layout = resolve_input_layout(Path(args.input_dir))
    policy = load_noise_policy(layout.policy_path)

    fanout_window_seconds = int(policy.get("multi_target_source_window_seconds", 600))
    fanout_min_targets = int(policy.get("multi_target_source_min_targets", 2))
    data_exfil_bytes = int(policy.get("data_exfiltration_bytes_threshold", 1073741824))
    forbidden_kex = set(policy.get("expected_algorithms", {}).get("forbidden_kex", []))
    forbidden_hostkeys = set(policy.get("expected_algorithms", {}).get("forbidden_hostkeys", []))
    forbidden_ciphers = set(policy.get("expected_algorithms", {}).get("forbidden_ciphers", []))
    forbidden_macs = set(policy.get("expected_algorithms", {}).get("forbidden_macs", []))
    stage1_baselines = load_json(json_dir / "task2_stage1_baselines.json", {})
    baseline_map = {item["user"]: item for item in stage1_baselines.get("users", [])}

    per_source_events = defaultdict(list)
    candidate_users = set()
    candidate_src_ips = set()
    candidate_target_servers = set()
    candidate_sessions = set()
    multi_target_source_candidates = []

    for event in iter_ndjson(json_dir / "task2_events.ndjson"):
        src_ip = event.get("src_ip", "")
        server_ip = event.get("server_ip", "")
        system_name = event.get("system_name", "")
        ts = parse_ts(event.get("timestamp", ""))
        if not src_ip or src_ip == "unknown" or ts is None:
            continue
        target = system_name or server_ip
        if not target:
            continue
        user = event.get("user", "unknown")
        session_id = event.get("session_id", "")
        result = event.get("result", "")
        action = event.get("action", "")
        hour = ts.hour
        baseline = baseline_map.get(user, {})
        usual_src_ips = set(baseline.get("usual_src_ips", []))
        usual_src_subnets = set(baseline.get("usual_src_subnets", []))
        usual_targets = set(baseline.get("usual_target_servers", []))
        usual_clients = set(baseline.get("usual_client_versions", []))
        active_hours = set(baseline.get("active_time_profile", []))
        sample_size = baseline.get("sample_size", 0)
        if sample_size > 0:
            if src_ip and src_ip not in usual_src_ips:
                candidate_users.add(user)
                candidate_src_ips.add(src_ip)
                if session_id:
                    candidate_sessions.add(session_id)
                candidate_target_servers.add(target)
            if event.get("src_subnet") and event.get("src_subnet") not in usual_src_subnets:
                candidate_users.add(user)
                candidate_src_ips.add(src_ip)
                if session_id:
                    candidate_sessions.add(session_id)
                candidate_target_servers.add(target)
            if active_hours and hour not in active_hours:
                candidate_users.add(user)
                candidate_src_ips.add(src_ip)
                if session_id:
                    candidate_sessions.add(session_id)
                candidate_target_servers.add(target)
            if target and target not in usual_targets:
                candidate_users.add(user)
                candidate_src_ips.add(src_ip)
                if session_id:
                    candidate_sessions.add(session_id)
                candidate_target_servers.add(target)
            client_version = event.get("client_version", "")
            if client_version and usual_clients and client_version not in usual_clients:
                candidate_users.add(user)
                candidate_src_ips.add(src_ip)
                if session_id:
                    candidate_sessions.add(session_id)
                candidate_target_servers.add(target)
        if result == "fail":
            if user and user != "unknown":
                candidate_users.add(user)
            candidate_src_ips.add(src_ip)
            if session_id:
                candidate_sessions.add(session_id)
            candidate_target_servers.add(target)
        if event.get("bytes_out", 0) > data_exfil_bytes // 100:
            if user and user != "unknown":
                candidate_users.add(user)
            candidate_src_ips.add(src_ip)
            if session_id:
                candidate_sessions.add(session_id)
            candidate_target_servers.add(target)
        if (
            event.get("kex_algorithm") in forbidden_kex
            or event.get("hostkey_algorithm") in forbidden_hostkeys
            or event.get("cipher_c2s") in forbidden_ciphers
            or event.get("cipher_s2c") in forbidden_ciphers
            or event.get("mac_c2s") in forbidden_macs
            or event.get("mac_s2c") in forbidden_macs
        ):
            if user and user != "unknown":
                candidate_users.add(user)
            candidate_src_ips.add(src_ip)
            if session_id:
                candidate_sessions.add(session_id)
            candidate_target_servers.add(target)
        per_source_events[src_ip].append(
            {
                "timestamp": ts,
                "user": user,
                "session_id": session_id,
                "target": target,
                "server_ip": server_ip,
                "system_name": system_name,
                "result": result,
                "action": action,
            }
        )

    for src_ip, events in sorted(per_source_events.items()):
        events.sort(key=lambda item: item["timestamp"])
        left = 0
        for right in range(len(events)):
            while (events[right]["timestamp"] - events[left]["timestamp"]).total_seconds() > fanout_window_seconds:
                left += 1
            window = events[left:right + 1]
            targets = sorted({item["target"] for item in window if item.get("target")})
            if len(targets) < fanout_min_targets:
                continue
            users = sorted({item["user"] for item in window if item.get("user") and item.get("user") != "unknown"})
            session_ids = sorted({item["session_id"] for item in window if item.get("session_id")})
            candidate_users.update(users)
            candidate_src_ips.add(src_ip)
            candidate_target_servers.update(targets)
            candidate_sessions.update(session_ids)
            multi_target_source_candidates.append(
                {
                    "src_ip": src_ip,
                    "window_start": window[0]["timestamp"].isoformat(),
                    "window_end": window[-1]["timestamp"].isoformat(),
                    "target_count": len(targets),
                    "targets": targets,
                    "users": users,
                    "session_ids": session_ids[:50],
                    "results": sorted({item["result"] for item in window if item.get("result")}),
                    "actions": sorted({item["action"] for item in window if item.get("action")}),
                }
            )
            break

    record = make_base_record(run_dir.name, "task2", "stage1_detect_candidates.py")
    record.update(
        {
            "stage1_baseline_user_count": len(stage1_baselines.get("users", [])),
            "candidate_users": sorted(candidate_users),
            "candidate_src_ips": sorted(candidate_src_ips),
            "candidate_target_servers": sorted(candidate_target_servers),
            "candidate_sessions": sorted(candidate_sessions),
            "multi_target_source_candidates": multi_target_source_candidates,
        }
    )
    dump_json(json_dir / "task2_stage1_candidates.json", record)


if __name__ == "__main__":
    main()
