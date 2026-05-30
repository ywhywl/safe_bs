#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from event_io import iter_ndjson, write_ndjson_line
from input_layout import load_noise_policy, resolve_input_layout
from lib import dump_json, load_json, make_base_record


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


def make_session_aggregate() -> dict:
    return {
        "user": "unknown",
        "event_count": 0,
        "max_event_score": 0,
        "start_ts": None,
        "end_ts": None,
        "distinct_ips": set(),
        "unique_paths": set(),
        "total_session_bytes": 0,
        "has_open": False,
        "has_close": False,
        "protocol_security_score": 0,
        "has_weak_kex": False,
        "has_weak_hostkey": False,
        "has_weak_cipher": False,
        "has_weak_mac": False,
        "has_protocol_deviation": False,
        "baseline_avg_total_bytes": 0,
    }


PRIVILEGE_PATHS = ("/etc/", "/root/", "/var/log/", "/.ssh/", "/admin/", "/backup/", "/config/", "/secret/", "/credential/", "/key/")
SENSITIVE_EXTENSIONS = (".conf", ".cfg", ".key", ".pem", ".crt", ".env", ".secret", ".password", ".credentials", ".ssh", ".bak", ".sql", ".db", ".xlsx", ".csv")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--input-dir", default="task2/TOOLS/samples")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    layout = resolve_input_layout(Path(args.input_dir))
    policy = load_noise_policy(layout.policy_path)
    events = iter_ndjson(json_dir / "task2_events.ndjson")
    baselines_data = load_json(json_dir / "task2_user_baselines.json", {})
    baselines = baselines_data.get("users", [])
    baseline_map = {item["user"]: item for item in baselines}
    # Convert baseline list fields to sets for O(1) membership checks in the hot loop
    _list_keys = [
        "usual_src_ips", "usual_src_subnets", "usual_actions", "usual_paths",
        "usual_auth_methods", "usual_client_versions",
        "usual_kex_algorithms", "usual_hostkey_algorithms",
        "usual_cipher_c2s", "usual_cipher_s2c",
        "usual_mac_c2s", "usual_mac_s2c",
    ]
    for item in baselines:
        for key in _list_keys:
            if key in item and isinstance(item[key], list):
                item[key] = set(item[key])

    # Load anomaly policy for thresholds
    brute_force_threshold = policy.get("brute_force_threshold", 5)
    brute_force_window = policy.get("brute_force_window_seconds", 300)
    concurrent_threshold = policy.get("concurrent_session_threshold", 3)
    concurrent_window = policy.get("concurrent_session_window_seconds", 60)
    data_exfil_bytes = policy.get("data_exfiltration_bytes_threshold", 1073741824)
    data_exfil_ratio = policy.get("data_exfiltration_ratio_threshold", 10)
    long_session_min = policy.get("long_session_threshold_minutes", 480)
    dormant_days = policy.get("dormant_account_days", 30)
    abnormal_ratio = policy.get("abnormal_transfer_ratio", 3)
    forbidden_kex = set(policy.get("expected_algorithms", {}).get("forbidden_kex", []))
    forbidden_hostkeys = set(policy.get("expected_algorithms", {}).get("forbidden_hostkeys", []))
    forbidden_ciphers = set(policy.get("expected_algorithms", {}).get("forbidden_ciphers", []))
    forbidden_macs = set(policy.get("expected_algorithms", {}).get("forbidden_macs", []))
    trusted_users = set(policy.get("trusted_users", []))
    trusted_client_versions = set(policy.get("trusted_client_versions", []))
    account_risk_strategy = policy.get("account_risk_strategy", "account")

    # Track login failures for brute force detection
    login_fail_by_user_ip = {}  # {(user, src_ip): [(timestamp, event_id)]}

    scored_preview = []
    scored_count = 0
    hit_count = 0
    ndjson_path = json_dir / "task2_anomaly_scores.ndjson"
    ndjson_path.unlink(missing_ok=True)

    session_aggregates = defaultdict(make_session_aggregate)

    with ndjson_path.open("a", encoding="utf-8") as out:
        for event in events:
            baseline = baseline_map.get(event.get("user"), {})
            sample_size = baseline.get("sample_size", 0)
            active_hours = baseline.get("active_time_profile", set())
            hour = parse_hour(event.get("timestamp", ""))
            src_ip = event.get("src_ip")
            src_subnet = event.get("src_subnet")
            src_ips = baseline.get("usual_src_ips", set())
            src_subnets = baseline.get("usual_src_subnets", set())
            actions = baseline.get("usual_actions", set())
            paths = baseline.get("usual_paths", set())
            auth_methods = baseline.get("usual_auth_methods", set())
            client_versions = baseline.get("usual_client_versions", set())
            kex_algorithms = baseline.get("usual_kex_algorithms", set())
            hostkey_algorithms = baseline.get("usual_hostkey_algorithms", set())
            cipher_c2s_baseline = baseline.get("usual_cipher_c2s", set())
            cipher_s2c_baseline = baseline.get("usual_cipher_s2c", set())
            mac_c2s_baseline = baseline.get("usual_mac_c2s", set())
            mac_s2c_baseline = baseline.get("usual_mac_s2c", set())
            transfer_range = baseline.get("usual_transfer_ranges", {})
            avg_total_bytes = transfer_range.get("avg_total_bytes", 0)
            avg_bytes_out = transfer_range.get("avg_bytes_out", 0)
            in_out_ratio = baseline.get("in_out_ratio", 0)
            total_bytes = event.get("bytes_in", 0) + event.get("bytes_out", 0)
            bytes_out = event.get("bytes_out", 0)
            bytes_in = event.get("bytes_in", 0)
            event_class = event.get("event_class", "generic")
            path = event.get("path", "")
            action = event.get("action", "")
            result = event.get("result", "")
            user = event.get("user", "unknown")
            kex_algorithm = event.get("kex_algorithm", "")
            hostkey_algorithm = event.get("hostkey_algorithm", "")
            cipher_c2s = event.get("cipher_c2s", "")
            cipher_s2c = event.get("cipher_s2c", "")
            mac_c2s = event.get("mac_c2s", "")
            mac_s2c = event.get("mac_s2c", "")
            client_version = event.get("client_version", "")

            # --- Original 8 dimensions ---
            src_score = 0
            if src_ip and src_ip not in src_ips:
                src_score = 20 if src_subnet and src_subnet in src_subnets else 40
            action_score = 0 if action in actions else 25
            path_score = 0
            if event_class not in {"auth", "session", "protocol"}:
                path_score = 0 if path in paths else 25
            auth_score = 0 if not event.get("auth_method") or event.get("auth_method") in auth_methods else 15
            client_score = 0 if not client_version or client_version in client_versions or client_version in trusted_client_versions else 15
            time_score = 0
            if active_hours and hour is not None and hour not in active_hours:
                time_score = 20
            failure_score = 0
            if result not in {"", "ok"}:
                failure_score = 25 if baseline.get("usual_failure_rate", 0) <= 0.1 else 10
            volume_score = 0
            max_bytes = transfer_range.get("max_total_bytes", 0)
            if max_bytes and total_bytes > max_bytes * 2:
                volume_score = 15

            # --- NEW expert-level dimensions ---
            reasons = []

            # 1. First-time IP (only when source deviation is NOT already triggered)
            # Avoids double-counting: source deviation already covers "IP not in baseline"
            # first-time IP now means: IP is new but within a known subnet (milder deviation)
            first_time_ip_score = 0
            if src_ip and src_ip not in src_ips and src_ips and src_score == 0:
                first_time_ip_score = policy.get("new_ip_first_time_score", 30)

            # 2. Privilege path access (accessing system/sensitive directories)
            privilege_score = 0
            if path:
                for pp in PRIVILEGE_PATHS:
                    if path.startswith(pp) or path.lower().startswith(pp):
                        privilege_score = 20
                        break

            # 3. Sensitive file access (downloading/uploading sensitive file extensions)
            sensitive_file_score = 0
            if path:
                for ext in SENSITIVE_EXTENSIONS:
                    if path.lower().endswith(ext):
                        sensitive_file_score = 25
                        break

            # 4. Data exfiltration indicator (outbound >> inbound or abnormal volume)
            exfil_score = 0
            if total_bytes > 0 and avg_total_bytes > 0:
                transfer_ratio = total_bytes / max(avg_total_bytes, 1)
                if transfer_ratio >= data_exfil_ratio:
                    exfil_score = 30
                elif bytes_out > bytes_in * abnormal_ratio and bytes_out > avg_bytes_out * 2:
                    exfil_score = 20

            # 5. Bulk data download (single transfer > threshold)
            bulk_download_score = 0
            if bytes_out > data_exfil_bytes / 100:  # 1% of threshold as "large" flag
                bulk_download_score = 15

            # 6. Abnormal in/out ratio deviation from baseline
            in_out_deviation_score = 0
            if bytes_in > 0 and bytes_out > 0:
                current_ratio = bytes_out / bytes_in
                if in_out_ratio > 0 and abs(current_ratio - in_out_ratio) > in_out_ratio * 2:
                    in_out_deviation_score = 10

            # 7. Login brute force tracking
            brute_force_score = 0
            if action in {"LOGIN", "AUTH"} and result == "fail":
                key = (user, src_ip)
                ts = parse_ts(event.get("timestamp", ""))
                if key not in login_fail_by_user_ip:
                    login_fail_by_user_ip[key] = []
                if ts is not None:
                    login_fail_by_user_ip[key].append((ts, event.get("event_id")))
                    # Prune entries outside 2x the brute force window to keep list bounded
                    cutoff = ts - timedelta(seconds=brute_force_window * 2)
                    login_fail_by_user_ip[key] = [
                        (t, e) for t, e in login_fail_by_user_ip[key] if t >= cutoff
                    ]
                    # Check if failures within window exceed threshold
                    recent_failures = [t for t, _ in login_fail_by_user_ip[key] if (ts - t).total_seconds() <= brute_force_window]
                    if len(recent_failures) >= brute_force_threshold:
                        brute_force_score = 40

            # 8. Dormant account reactivation
            dormant_score = 0
            baseline_last_seen = parse_ts(baseline.get("last_seen", ""))
            current_ts = parse_ts(event.get("timestamp", ""))
            if baseline_last_seen is not None and current_ts is not None and current_ts > baseline_last_seen:
                dormant_gap_days = (current_ts - baseline_last_seen).total_seconds() / 86400
                if baseline.get("sample_size", 0) > 0 and dormant_gap_days >= dormant_days:
                    dormant_score = 30 if dormant_gap_days >= dormant_days * 3 else 20

            # 9. Unusual result type (never seen result for this user)
            unusual_result_score = 0
            usual_results = baseline.get("usual_results", [])
            if result and result not in {"", "ok"} and result not in usual_results and usual_results:
                unusual_result_score = 10

            # 10. Protocol/security posture deviations
            weak_kex_score = 25 if kex_algorithm and kex_algorithm in forbidden_kex else 0
            weak_hostkey_score = 20 if hostkey_algorithm and hostkey_algorithm in forbidden_hostkeys else 0
            weak_cipher_score = 15 if any(v and v in forbidden_ciphers for v in [cipher_c2s, cipher_s2c]) else 0
            weak_mac_score = 15 if any(v and v in forbidden_macs for v in [mac_c2s, mac_s2c]) else 0
            protocol_deviation_score = 0
            if kex_algorithm and kex_algorithms and kex_algorithm not in kex_algorithms:
                protocol_deviation_score += 10
            if hostkey_algorithm and hostkey_algorithms and hostkey_algorithm not in hostkey_algorithms:
                protocol_deviation_score += 10
            if cipher_c2s and cipher_c2s_baseline and cipher_c2s not in cipher_c2s_baseline:
                protocol_deviation_score += 10
            if cipher_s2c and cipher_s2c_baseline and cipher_s2c not in cipher_s2c_baseline:
                protocol_deviation_score += 10
            if mac_c2s and mac_c2s_baseline and mac_c2s not in mac_c2s_baseline:
                protocol_deviation_score += 10
            if mac_s2c and mac_s2c_baseline and mac_s2c not in mac_s2c_baseline:
                protocol_deviation_score += 10

            # Small sample size adjustment
            if sample_size <= 1:
                action_score = min(action_score, 10)
                path_score = min(path_score, 10)
                auth_score = min(auth_score, 5)
                client_score = min(client_score, 5)

            # Compute total score
            score = src_score + action_score + path_score + auth_score + client_score + time_score + failure_score + volume_score + first_time_ip_score + privilege_score + sensitive_file_score + exfil_score + bulk_download_score + in_out_deviation_score + brute_force_score + dormant_score + unusual_result_score + weak_kex_score + weak_hostkey_score + weak_cipher_score + weak_mac_score + protocol_deviation_score

            # Collect all reasons
            if src_score:
                reasons.append("source deviation")
            if action_score:
                reasons.append("action deviation")
            if path_score:
                reasons.append("path deviation")
            if auth_score:
                reasons.append("auth deviation")
            if client_score:
                reasons.append("client deviation")
            if time_score:
                reasons.append("time deviation")
            if failure_score:
                reasons.append("failure deviation")
            if volume_score:
                reasons.append("volume deviation")
            if first_time_ip_score:
                reasons.append("first-time source IP")
            if privilege_score:
                reasons.append("privilege path access")
            if sensitive_file_score:
                reasons.append("sensitive file access")
            if exfil_score:
                reasons.append("data exfiltration indicator")
            if bulk_download_score:
                reasons.append("bulk data download")
            if in_out_deviation_score:
                reasons.append("in/out ratio deviation")
            if brute_force_score:
                reasons.append("brute force attempt")
            if dormant_score:
                reasons.append("dormant account activation")
            if unusual_result_score:
                reasons.append("unusual result type")
            if weak_kex_score:
                reasons.append("weak kex algorithm")
            if weak_hostkey_score:
                reasons.append("weak hostkey algorithm")
            if weak_cipher_score:
                reasons.append("weak cipher algorithm")
            if weak_mac_score:
                reasons.append("weak mac algorithm")
            if protocol_deviation_score:
                reasons.append("protocol negotiation deviation")

            scored_record = {
                "item_id": event.get("event_id"),
                "item_type": "event",
                "user": user,
                "session_id": event.get("session_id") or f"user:{user}",
                "timestamp": event.get("timestamp", ""),
                "src_ip": src_ip,
                "src_subnet": src_subnet,
                "score_total": score,
                "score_time_deviation": time_score,
                "score_source_deviation": src_score,
                "score_action_deviation": action_score,
                "score_path_deviation": path_score,
                "score_auth_deviation": auth_score,
                "score_client_deviation": client_score,
                "score_volume_deviation": volume_score,
                "score_failure_deviation": failure_score,
                "score_first_time_ip": first_time_ip_score,
                "score_privilege_path": privilege_score,
                "score_sensitive_file": sensitive_file_score,
                "score_exfiltration": exfil_score,
                "score_bulk_download": bulk_download_score,
                "score_in_out_deviation": in_out_deviation_score,
                "score_brute_force": brute_force_score,
                "score_dormant_activation": dormant_score,
                "score_unusual_result": unusual_result_score,
                "score_weak_kex": weak_kex_score,
                "score_weak_hostkey": weak_hostkey_score,
                "score_weak_cipher": weak_cipher_score,
                "score_weak_mac": weak_mac_score,
                "score_protocol_deviation": protocol_deviation_score,
                "threshold_hit": score >= 60,
                "rule_hits": reasons,
                "manual_review_required": score >= 60,
            }
            # Only write anomalous events to NDJSON (threshold_hit=True)
            # Normal events (score < 60) are still tracked in session_aggregates and the .json summary
            if scored_record["threshold_hit"]:
                write_ndjson_line(ndjson_path, scored_record, handle=out)
            scored_count += 1
            if scored_record["threshold_hit"]:
                hit_count += 1
            if scored_record["threshold_hit"] and len(scored_preview) < 200:
                scored_preview.append(scored_record)

            sid = event.get("session_id") or f"user:{user}"
            session_stat = session_aggregates[sid]
            session_stat["event_count"] += 1
            if session_stat["user"] in {"", "unknown"} and user not in {"", "unknown"}:
                session_stat["user"] = user
            if current_ts is not None:
                if session_stat["start_ts"] is None or current_ts < session_stat["start_ts"]:
                    session_stat["start_ts"] = current_ts
                if session_stat["end_ts"] is None or current_ts > session_stat["end_ts"]:
                    session_stat["end_ts"] = current_ts
            if src_ip:
                session_stat["distinct_ips"].add(src_ip)
            if path:
                session_stat["unique_paths"].add(path)
            session_stat["total_session_bytes"] += total_bytes
            if action == "SESSION_OPEN":
                session_stat["has_open"] = True
            if action == "SESSION_CLOSE":
                session_stat["has_close"] = True
            session_stat["max_event_score"] = max(session_stat["max_event_score"], score)
            session_stat["protocol_security_score"] = min(
                session_stat["protocol_security_score"]
                + weak_kex_score
                + weak_hostkey_score
                + weak_cipher_score
                + weak_mac_score
                + protocol_deviation_score,
                60,
            )
            session_stat["has_weak_kex"] = session_stat["has_weak_kex"] or weak_kex_score > 0
            session_stat["has_weak_hostkey"] = session_stat["has_weak_hostkey"] or weak_hostkey_score > 0
            session_stat["has_weak_cipher"] = session_stat["has_weak_cipher"] or weak_cipher_score > 0
            session_stat["has_weak_mac"] = session_stat["has_weak_mac"] or weak_mac_score > 0
            session_stat["has_protocol_deviation"] = session_stat["has_protocol_deviation"] or protocol_deviation_score > 0
            if user not in {"", "unknown"}:
                session_stat["baseline_avg_total_bytes"] = baseline.get("usual_transfer_ranges", {}).get(
                    "avg_total_bytes",
                    session_stat["baseline_avg_total_bytes"],
                )

    # --- Session-level anomaly detection ---
    session_ndjson_path = json_dir / "task2_session_anomaly_scores.ndjson"
    session_ndjson_path.unlink(missing_ok=True)

    session_scored_count = 0
    session_hit_count = 0
    session_scored_preview = []

    with session_ndjson_path.open("a", encoding="utf-8") as sout:
        for session_id, session_stat in sorted(session_aggregates.items()):
            if session_stat["event_count"] < 2:
                continue

            start_ts = session_stat["start_ts"]
            end_ts = session_stat["end_ts"]
            if start_ts is None or end_ts is None:
                continue

            session_duration = (end_ts - start_ts).total_seconds()
            session_duration_min = session_duration / 60

            # 1. Long session (超过阈值)
            long_session_score = 0
            if session_duration_min >= long_session_min:
                long_session_score = 30

            # 2. Session with many distinct IPs
            distinct_ips = session_stat["distinct_ips"]
            multi_ip_session_score = 0
            if len(distinct_ips) >= 3:
                multi_ip_session_score = 20

            # 3. Crawl behavior: accessing many diverse paths in short time
            unique_paths = session_stat["unique_paths"]
            crawl_score = 0
            if len(unique_paths) >= 5 and session_duration <= 60:
                crawl_score = 25

            # 4. Abnormal session data volume
            total_session_bytes = session_stat["total_session_bytes"]
            session_exfil_score = 0
            baseline_avg_total_bytes = session_stat["baseline_avg_total_bytes"]
            session_avg_bytes = baseline_avg_total_bytes * session_stat["event_count"] if baseline_avg_total_bytes > 0 else 0
            if session_avg_bytes > 0 and total_session_bytes >= session_avg_bytes * data_exfil_ratio:
                session_exfil_score = 20

            # 5. Open-no-close session pattern
            has_open = session_stat["has_open"]
            has_close = session_stat["has_close"]
            orphan_session_score = 0
            if has_open and not has_close:
                orphan_session_score = 15

            # 6. Aggregate protocol-security risk across negotiation events
            protocol_session_score = session_stat["protocol_security_score"]

            session_total_score = session_stat["max_event_score"] + long_session_score + multi_ip_session_score + crawl_score + session_exfil_score + orphan_session_score + protocol_session_score

            session_reasons = []
            if long_session_score:
                session_reasons.append("long session")
            if multi_ip_session_score:
                session_reasons.append("multi-IP session")
            if crawl_score:
                session_reasons.append("crawl behavior")
            if session_exfil_score:
                session_reasons.append("session data exfiltration")
            if orphan_session_score:
                session_reasons.append("orphan session (open without close)")
            if protocol_session_score:
                if session_stat["has_weak_kex"]:
                    session_reasons.append("weak kex algorithm")
                if session_stat["has_weak_hostkey"]:
                    session_reasons.append("weak hostkey algorithm")
                if session_stat["has_weak_cipher"]:
                    session_reasons.append("weak cipher algorithm")
                if session_stat["has_weak_mac"]:
                    session_reasons.append("weak mac algorithm")
                if session_stat["has_protocol_deviation"]:
                    session_reasons.append("protocol negotiation deviation")

            session_scored_record = {
                "item_id": session_id,
                "item_type": "session",
                "user": session_stat["user"],
                "session_id": session_id,
                "score_total": session_total_score,
                "max_event_score": session_stat["max_event_score"],
                "score_long_session": long_session_score,
                "score_multi_ip": multi_ip_session_score,
                "score_crawl": crawl_score,
                "score_session_exfil": session_exfil_score,
                "score_orphan_session": orphan_session_score,
                "score_protocol_security": protocol_session_score,
                "session_duration_minutes": round(session_duration_min, 2),
                "distinct_ip_count": len(distinct_ips),
                "unique_path_count": len(unique_paths),
                "total_session_bytes": total_session_bytes,
                "threshold_hit": session_total_score >= 60 and bool(session_reasons),
                "rule_hits": session_reasons,
                "manual_review_required": session_total_score >= 60 and bool(session_reasons),
            }

            write_ndjson_line(session_ndjson_path, session_scored_record, handle=sout)
            session_scored_count += 1
            if session_scored_record["threshold_hit"]:
                session_hit_count += 1
            if len(session_scored_preview) < 50:
                session_scored_preview.append(session_scored_record)

    # --- Brute force alert generation ---
    brute_force_alerts = []
    bf_idx = 0
    for (user, src_ip), failures in login_fail_by_user_ip.items():
        if len(failures) >= brute_force_threshold:
            # Find clusters within the window
            sorted_failures = sorted(failures, key=lambda x: x[0])
            cluster_start = sorted_failures[0]
            cluster_end = sorted_failures[-1]
            window_seconds = (cluster_end[0] - cluster_start[0]).total_seconds()
            if window_seconds <= brute_force_window or len(failures) >= brute_force_threshold * 2:
                bf_idx += 1
                brute_force_alerts.append({
                    "bf_id": f"bf-{bf_idx}",
                    "user": user,
                    "src_ip": src_ip,
                    "failure_count": len(failures),
                    "time_window_seconds": round(window_seconds, 1),
                    "first_failure": cluster_start[0].isoformat(),
                    "last_failure": cluster_end[0].isoformat(),
                    "event_ids": [eid for _, eid in failures],
                })

    # --- Cross-user shared IP detection ---
    cross_user_ips = baselines_data.get("cross_user_shared_ips", {})
    shared_ip_alerts = []
    for ip, user_list in cross_user_ips.items():
        if len(user_list) >= 3:
            shared_ip_alerts.append({
                "shared_ip": ip,
                "user_count": len(user_list),
                "users": user_list,
            })

    record = make_base_record(run_dir.name, "task2", "score_anomalies.py")
    record["scored_item_count"] = scored_count
    record["threshold_hit_count"] = hit_count
    record["scored_items_preview"] = scored_preview
    record["session_scored_count"] = session_scored_count
    record["session_hit_count"] = session_hit_count
    record["session_scores_preview"] = session_scored_preview
    record["brute_force_clusters"] = brute_force_alerts
    record["cross_user_shared_ip_alerts"] = shared_ip_alerts
    record["score_dimensions"] = [
        "source deviation", "action deviation", "path deviation", "auth deviation",
        "client deviation", "time deviation", "failure deviation", "volume deviation",
        "first-time source IP", "privilege path access", "sensitive file access",
        "data exfiltration indicator", "bulk data download", "in/out ratio deviation",
        "brute force attempt", "dormant account activation", "unusual result type",
        "long session", "multi-IP session", "crawl behavior", "session data exfiltration",
                "orphan session",
                "weak kex algorithm", "weak hostkey algorithm",
                "weak cipher algorithm", "weak mac algorithm",
                "protocol negotiation deviation",
            ]
    dump_json(json_dir / "task2_anomaly_scores.json", record)


if __name__ == "__main__":
    main()
