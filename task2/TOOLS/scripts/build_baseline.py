#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from event_io import iter_ndjson
from input_layout import load_noise_policy
from lib import dump_json, load_json, load_task2_runtime_config, make_base_record


def parse_hour(value: str) -> int | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).hour
    except ValueError:
        return None


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
    baseline_events_path = json_dir / "task2_baseline_events.ndjson"
    if baseline_events_path.exists():
        events_path = baseline_events_path
        baseline_mode = "historical_split"
    else:
        events_path = json_dir / "task2_events.ndjson"
        baseline_mode = "single_dataset"
    events_meta = load_json(json_dir / "task2_events.json", {})
    manifest = load_json(json_dir / "task2_log_ingest_manifest.json", {})
    policy = load_noise_policy(Path(manifest.get("policy_path"))) if manifest.get("policy_path") else load_noise_policy(None)
    runtime_config = load_task2_runtime_config()
    max_paths_per_user = runtime_config["baseline_max_paths_per_user"]
    max_path_count_keys_per_user = runtime_config["baseline_max_path_count_keys_per_user"]
    max_daily_buckets_per_user = runtime_config["baseline_max_daily_buckets_per_user"]
    max_ip_profile_per_user = runtime_config["baseline_max_ip_profile_per_user"]
    max_src_ips_per_user = runtime_config["baseline_max_src_ips_per_user"]
    max_src_subnets_per_user = runtime_config["baseline_max_src_subnets_per_user"]
    max_session_ids_per_user = runtime_config["baseline_max_session_ids_per_user"]
    max_session_sequences_per_user = runtime_config["baseline_max_session_sequences_per_user"]
    max_actions_per_session = runtime_config["baseline_max_actions_per_session"]

    # Per-user stats with much richer profiling
    stats = defaultdict(
        lambda: {
            "active_hours": set(),
            "src_ips": set(),
            "src_subnets": set(),
            "actions": set(),
            "paths": set(),
            "auth_methods": set(),
            "client_versions": set(),
            "kex_algorithms": set(),
            "hostkey_algorithms": set(),
            "cipher_c2s": set(),
            "cipher_s2c": set(),
            "mac_c2s": set(),
            "mac_s2c": set(),
            "publickey_fingerprints": set(),
            "results": set(),
            "min_total_bytes": None,
            "max_total_bytes": 0,
            "sum_total_bytes": 0,
            "sum_bytes_in": 0,
            "sum_bytes_out": 0,
            "successful_event_count": 0,
            "total_event_count": 0,
            "failed_event_count": 0,
            "login_success_count": 0,
            "login_failure_count": 0,
            "session_ids": set(),
            "session_actions": defaultdict(list),
            "ip_login_success": defaultdict(int),
            "ip_login_failure": defaultdict(int),
            "path_access_count": defaultdict(int),
            "daily_counts": defaultdict(int),
            "transfer_events": [],
            "privilege_path_accesses": [],
            "sensitive_file_accesses": [],
            "first_seen_timestamp": None,
            "last_seen_timestamp": None,
        }
    )

    PRIVILEGE_PATHS = ("/etc/", "/root/", "/var/log/", "/.ssh/", "/admin/", "/backup/", "/config/", "/secret/", "/credential/", "/key/")
    SENSITIVE_EXTENSIONS = (".conf", ".cfg", ".key", ".pem", ".crt", ".env", ".secret", ".password", ".credentials", ".ssh", ".bak", ".sql", ".db", ".xlsx", ".csv")
    CRAWL_PATHS = ("/", "/etc/", "/home/", "/var/", "/tmp/", "/opt/", "/usr/")

    for event in iter_ndjson(events_path):
        user = event.get("user", "unknown")
        user_stat = stats[user]
        user_stat["total_event_count"] += 1

        ts = parse_ts(event.get("timestamp", ""))
        if ts is not None:
            if user_stat["first_seen_timestamp"] is None or ts < user_stat["first_seen_timestamp"]:
                user_stat["first_seen_timestamp"] = ts
            if user_stat["last_seen_timestamp"] is None or ts > user_stat["last_seen_timestamp"]:
                user_stat["last_seen_timestamp"] = ts
            day_key = ts.strftime("%Y-%m-%d")
            if day_key in user_stat["daily_counts"] or len(user_stat["daily_counts"]) < max_daily_buckets_per_user:
                user_stat["daily_counts"][day_key] += 1

        if event.get("result") not in {"", "ok"}:
            user_stat["failed_event_count"] += 1

        total_bytes = event.get("bytes_in", 0) + event.get("bytes_out", 0)
        user_stat["sum_bytes_in"] += event.get("bytes_in", 0)
        user_stat["sum_bytes_out"] += event.get("bytes_out", 0)
        if user_stat["min_total_bytes"] is None:
            user_stat["min_total_bytes"] = total_bytes
        else:
            user_stat["min_total_bytes"] = min(user_stat["min_total_bytes"], total_bytes)
        user_stat["max_total_bytes"] = max(user_stat["max_total_bytes"], total_bytes)
        user_stat["sum_total_bytes"] += total_bytes

        # Track transfer events for exfiltration detection (keep top N by bytes)
        if total_bytes > 0:
            user_stat["transfer_events"].append({
                "bytes_in": event.get("bytes_in", 0),
                "bytes_out": event.get("bytes_out", 0),
                "total_bytes": total_bytes,
                "path": event.get("path", ""),
                "timestamp": event.get("timestamp", ""),
                "result": event.get("result", ""),
            })
            # Keep only top 50 by total_bytes to bound memory
            if len(user_stat["transfer_events"]) > 60:
                user_stat["transfer_events"].sort(key=lambda x: -x["total_bytes"])
                user_stat["transfer_events"] = user_stat["transfer_events"][:50]

        # Track privilege path accesses
        path = event.get("path", "")
        if path:
            for pp in PRIVILEGE_PATHS:
                if path.startswith(pp) or path.lower().startswith(pp):
                    user_stat["privilege_path_accesses"].append({
                        "path": path,
                        "action": event.get("action", ""),
                        "timestamp": event.get("timestamp", ""),
                        "src_ip": event.get("src_ip", ""),
                    })
                    # Keep max 50 privilege accesses per user
                    if len(user_stat["privilege_path_accesses"]) > 60:
                        user_stat["privilege_path_accesses"] = user_stat["privilege_path_accesses"][:50]
                    break

        # Track sensitive file accesses
        if path:
            for ext in SENSITIVE_EXTENSIONS:
                if path.lower().endswith(ext):
                    user_stat["sensitive_file_accesses"].append({
                        "path": path,
                        "action": event.get("action", ""),
                        "timestamp": event.get("timestamp", ""),
                        "src_ip": event.get("src_ip", ""),
                    })
                    # Keep max 50 sensitive accesses per user
                    if len(user_stat["sensitive_file_accesses"]) > 60:
                        user_stat["sensitive_file_accesses"] = user_stat["sensitive_file_accesses"][:50]
                    break

        # Only profile successful events for baseline
        if event.get("result") and event.get("result") != "ok":
            # Track login failures specifically
            if event.get("action") in {"LOGIN", "AUTH"}:
                user_stat["login_failure_count"] += 1
                if event.get("src_ip"):
                    if event["src_ip"] in user_stat["ip_login_failure"] or len(user_stat["ip_login_failure"]) < max_ip_profile_per_user:
                        user_stat["ip_login_failure"][event["src_ip"]] += 1
            continue

        user_stat["successful_event_count"] += 1
        user_stat["login_success_count"] += 1 if event.get("action") in {"LOGIN", "AUTH"} else 0

        if event.get("action") in {"LOGIN", "AUTH"} and event.get("src_ip"):
            if event["src_ip"] in user_stat["ip_login_success"] or len(user_stat["ip_login_success"]) < max_ip_profile_per_user:
                user_stat["ip_login_success"][event["src_ip"]] += 1

        hour = parse_hour(event.get("timestamp", ""))
        if hour is not None:
            user_stat["active_hours"].add(hour)
        if event.get("src_ip"):
            if event["src_ip"] in user_stat["src_ips"] or len(user_stat["src_ips"]) < max_src_ips_per_user:
                user_stat["src_ips"].add(event["src_ip"])
        if event.get("src_subnet"):
            if event["src_subnet"] in user_stat["src_subnets"] or len(user_stat["src_subnets"]) < max_src_subnets_per_user:
                user_stat["src_subnets"].add(event["src_subnet"])
        if event.get("action"):
            user_stat["actions"].add(event["action"])
        if path:
            if path in user_stat["paths"] or len(user_stat["paths"]) < max_paths_per_user:
                user_stat["paths"].add(path)
            if path in user_stat["path_access_count"] or len(user_stat["path_access_count"]) < max_path_count_keys_per_user:
                user_stat["path_access_count"][path] += 1
        if event.get("auth_method"):
            user_stat["auth_methods"].add(event["auth_method"])
        if event.get("client_version"):
            user_stat["client_versions"].add(event["client_version"])
        if event.get("kex_algorithm"):
            user_stat["kex_algorithms"].add(event["kex_algorithm"])
        if event.get("hostkey_algorithm"):
            user_stat["hostkey_algorithms"].add(event["hostkey_algorithm"])
        if event.get("cipher_c2s"):
            user_stat["cipher_c2s"].add(event["cipher_c2s"])
        if event.get("cipher_s2c"):
            user_stat["cipher_s2c"].add(event["cipher_s2c"])
        if event.get("mac_c2s"):
            user_stat["mac_c2s"].add(event["mac_c2s"])
        if event.get("mac_s2c"):
            user_stat["mac_s2c"].add(event["mac_s2c"])
        if event.get("publickey_fingerprint_md5"):
            user_stat["publickey_fingerprints"].add(event["publickey_fingerprint_md5"])
        if event.get("result"):
            user_stat["results"].add(event["result"])
        if event.get("session_id"):
            session_id = event["session_id"]
            if session_id in user_stat["session_ids"] or len(user_stat["session_ids"]) < max_session_ids_per_user:
                user_stat["session_ids"].add(session_id)
            if event.get("action"):
                if session_id in user_stat["session_actions"] or len(user_stat["session_actions"]) < max_session_sequences_per_user:
                    actions = user_stat["session_actions"][session_id]
                    if len(actions) < max_actions_per_session:
                        actions.append(event["action"])

    # Build baseline profiles
    users = []
    for user, user_stat in sorted(stats.items()):
        sequences = []
        for actions in user_stat["session_actions"].values():
            if len(actions) >= 2:
                sequences.append(" -> ".join(actions[:4]))

        avg_total_bytes = 0
        avg_bytes_out = 0
        if user_stat["total_event_count"]:
            avg_total_bytes = user_stat["sum_total_bytes"] / user_stat["total_event_count"]
            avg_bytes_out = user_stat["sum_bytes_out"] / user_stat["total_event_count"]

        # Compute active days count
        active_days = len(user_stat["daily_counts"])

        # Compute top paths
        top_paths = sorted(user_stat["path_access_count"].items(), key=lambda x: -x[1])[:10]

        # Login success/failure per IP
        ip_success_profile = dict(user_stat["ip_login_success"])
        ip_failure_profile = dict(user_stat["ip_login_failure"])

        # Compute in/out ratio
        in_out_ratio = user_stat["sum_bytes_out"] / max(user_stat["sum_bytes_in"], 1)

        users.append(
            {
                "user": user,
                "active_time_profile": sorted(user_stat["active_hours"]),
                "active_days": active_days,
                "usual_src_ips": sorted(user_stat["src_ips"]),
                "usual_src_subnets": sorted(user_stat["src_subnets"]),
                "usual_actions": sorted(user_stat["actions"]),
                "usual_action_sequences": sorted(set(sequences))[:5],
                "usual_paths": sorted(user_stat["paths"]),
                "top_paths": [{"path": p, "count": c} for p, c in top_paths],
                "usual_auth_methods": sorted(user_stat["auth_methods"]),
                "usual_client_versions": sorted(user_stat["client_versions"]),
                "usual_kex_algorithms": sorted(user_stat["kex_algorithms"]),
                "usual_hostkey_algorithms": sorted(user_stat["hostkey_algorithms"]),
                "usual_cipher_c2s": sorted(user_stat["cipher_c2s"]),
                "usual_cipher_s2c": sorted(user_stat["cipher_s2c"]),
                "usual_mac_c2s": sorted(user_stat["mac_c2s"]),
                "usual_mac_s2c": sorted(user_stat["mac_s2c"]),
                "usual_publickey_fingerprints": sorted(user_stat["publickey_fingerprints"]),
                "usual_results": sorted(user_stat["results"]),
                "usual_transfer_ranges": {
                    "min_total_bytes": user_stat["min_total_bytes"] or 0,
                    "max_total_bytes": user_stat["max_total_bytes"],
                    "avg_total_bytes": avg_total_bytes,
                    "avg_bytes_out": avg_bytes_out,
                },
                "in_out_ratio": round(in_out_ratio, 4),
                "usual_failure_rate": round(user_stat["failed_event_count"] / user_stat["total_event_count"], 4)
                if user_stat["total_event_count"]
                else 0,
                "login_success_count": user_stat["login_success_count"],
                "login_failure_count": user_stat["login_failure_count"],
                "login_failure_rate": round(user_stat["login_failure_count"] / max(user_stat["login_success_count"] + user_stat["login_failure_count"], 1), 4),
                "ip_success_profile": ip_success_profile,
                "ip_failure_profile": ip_failure_profile,
                "session_frequency_profile": {
                    "successful_event_count": user_stat["successful_event_count"],
                    "session_count": len(user_stat["session_ids"]),
                    "avg_events_per_session": round(user_stat["successful_event_count"] / len(user_stat["session_ids"]), 2)
                    if user_stat["session_ids"]
                    else user_stat["successful_event_count"],
                    "avg_session_duration_minutes": 0,
                },
                "privilege_path_accesses": user_stat["privilege_path_accesses"][:20],
                "sensitive_file_accesses": user_stat["sensitive_file_accesses"][:20],
                "transfer_events_summary": {
                    "count": len(user_stat["transfer_events"]),
                    "top_by_bytes": sorted(user_stat["transfer_events"], key=lambda x: -x["total_bytes"])[:10],
                },
                "daily_counts": dict(user_stat["daily_counts"]),
                "first_seen": user_stat["first_seen_timestamp"].isoformat() if user_stat["first_seen_timestamp"] else "",
                "last_seen": user_stat["last_seen_timestamp"].isoformat() if user_stat["last_seen_timestamp"] else "",
                "seasonality_notes": "",
                "baseline_confidence": "low" if user_stat["successful_event_count"] < 5 else "medium",
                "sample_size": user_stat["successful_event_count"],
                "last_updated": "",
                "trusted_user": user in set(policy.get("trusted_users", [])),
            }
        )

    # Cross-user analysis: IP shared across multiple users
    ip_user_map = defaultdict(set)
    for user, user_stat in stats.items():
        for ip in user_stat["src_ips"]:
            ip_user_map[ip].add(user)

    cross_user_shared_ips = {ip: sorted(users_set) for ip, users_set in ip_user_map.items() if len(users_set) >= 3}

    record = make_base_record(run_dir.name, "task2", "build_baseline.py")
    record["baseline_mode"] = baseline_mode
    record["baseline_event_count"] = events_meta.get("baseline_event_count", 0) if baseline_events_path.exists() else events_meta.get("event_count", 0)
    record["current_event_count"] = events_meta.get("event_count", 0)
    record["events_source_path"] = str(events_path)
    record["stage2_scope_available"] = (json_dir / "task2_events_scoped.ndjson").exists()
    record["large_mode"] = runtime_config["large_mode"]
    record["baseline_limits"] = {
        "max_paths_per_user": max_paths_per_user,
        "max_path_count_keys_per_user": max_path_count_keys_per_user,
        "max_daily_buckets_per_user": max_daily_buckets_per_user,
        "max_ip_profile_per_user": max_ip_profile_per_user,
        "max_src_ips_per_user": max_src_ips_per_user,
        "max_src_subnets_per_user": max_src_subnets_per_user,
        "max_session_ids_per_user": max_session_ids_per_user,
        "max_session_sequences_per_user": max_session_sequences_per_user,
        "max_actions_per_session": max_actions_per_session,
    }
    record["users"] = users
    record["cross_user_shared_ips"] = cross_user_shared_ips
    dump_json(json_dir / "task2_user_baselines.json", record)


if __name__ == "__main__":
    main()
