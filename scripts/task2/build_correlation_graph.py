#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

from event_io import iter_ndjson
from lib import dump_json, load_json, load_task2_runtime_config, make_base_record


TIME_PROXIMITY_WINDOW = 300  # seconds, same as brute_force_window_seconds


class UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        if x not in self.parent:
            self.parent[x] = x
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb

    def clusters(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = defaultdict(list)
        for x in self.parent:
            groups[self.find(x)].append(x)
        return groups


def parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def compute_subnet(ip_str: str) -> str:
    try:
        addr = ip_address(ip_str)
    except ValueError:
        return ""
    if addr.version == 4:
        parts = ip_str.split(".")
        return ".".join(parts[:3]) + ".0/24"
    groups = ip_str.split(":")
    return ":".join(groups[:4]) + "::/64"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    runtime_config = load_task2_runtime_config()
    max_candidate_ips_per_user = runtime_config["correlation_max_candidate_ips_per_user"]
    max_candidate_ips_per_subnet = runtime_config["correlation_max_candidate_ips_per_subnet"]
    max_paths_per_ip = runtime_config["correlation_max_paths_per_ip"]
    max_sessions_per_ip = runtime_config["correlation_max_sessions_per_ip"]
    max_time_samples_per_user_ip = runtime_config["correlation_max_time_samples_per_user_ip"]

    # --- Stream events to build IP node map (no full list) ---
    ip_data: dict[str, dict] = defaultdict(lambda: {
        "users": set(), "sessions": set(), "paths": set(),
        "actions": set(), "results": set(),
        "first_ts": None, "last_ts": None, "event_count": 0,
        "result_counts": defaultdict(int),
        "is_anomalous": False, "anomalous_event_ids": [],
    })

    # Build anomalous event ID set first (from scores only, small dataset)
    anomalous_event_ids: set[str] = set()
    anomalous_session_ids: set[str] = set()
    for item in iter_ndjson(json_dir / "task2_anomaly_scores.ndjson"):
        if item.get("threshold_hit"):
            anomalous_event_ids.add(item.get("item_id", ""))
            anomalous_session_ids.add(item.get("session_id", ""))
    for item in iter_ndjson(json_dir / "task2_session_anomaly_scores.ndjson"):
        if item.get("threshold_hit"):
            anomalous_session_ids.add(item.get("session_id", ""))

    # Build event_id -> rule_hits lookup from scores (only anomalous ones)
    anomalous_rule_map: dict[str, list[str]] = {}
    for item in iter_ndjson(json_dir / "task2_anomaly_scores.ndjson"):
        if item.get("threshold_hit"):
            anomalous_rule_map[item.get("item_id", "")] = item.get("rule_hits", [])

    # Stream events into ip_data (no list storage)
    for event in iter_ndjson(json_dir / "task2_events.ndjson"):
        src_ip = event.get("src_ip", "")
        if not src_ip or src_ip == "unknown":
            continue
        d = ip_data[src_ip]
        user = event.get("user", "")
        if user:
            d["users"].add(user)
        sid = event.get("session_id", "")
        if sid:
            d["sessions"].add(sid)
        path = event.get("path", "")
        if path and (path in d["paths"] or len(d["paths"]) < max_paths_per_ip):
            d["paths"].add(path)
        action = event.get("action", "")
        if action:
            d["actions"].add(action)
        result = event.get("result", "")
        if result:
            d["results"].add(result)
            d["result_counts"][result] += 1
        ts = parse_ts(event.get("timestamp", ""))
        if ts:
            if d["first_ts"] is None or ts < d["first_ts"]:
                d["first_ts"] = ts
            if d["last_ts"] is None or ts > d["last_ts"]:
                d["last_ts"] = ts
        eid = event.get("event_id", "")
        d["event_count"] += 1
        if eid in anomalous_event_ids:
            d["is_anomalous"] = True
            if len(d["anomalous_event_ids"]) < 50:
                d["anomalous_event_ids"].append(eid)

    # --- Enrich IP nodes from session views ---
    for session in iter_ndjson(json_dir / "task2_session_views.ndjson"):
        src_ips = session.get("src_ips", [])
        session_id = session.get("session_id", "")
        users = session.get("users", [])
        for ip in src_ips:
            if ip in ip_data:
                ip_data[ip]["sessions"].add(session_id)
                for u in users:
                    ip_data[ip]["users"].add(u)

    # --- Step C: Compute IP edges (group-by-user, not O(|IPs|²)) ---
    # Group IPs by user to only check pairs with at least one shared dimension
    user_ips: dict[str, set[str]] = defaultdict(set)
    subnet_ips: dict[str, set[str]] = defaultdict(set)
    for ip, d in ip_data.items():
        for user in d["users"]:
            user_ips[user].add(ip)
        subnet = compute_subnet(ip)
        if subnet:
            subnet_ips[subnet].add(ip)

    # Collect candidate pairs: IPs that share at least one user or one subnet
    candidate_pairs: set[tuple[str, str]] = set()
    for ips in user_ips.values():
        ips_list = sorted(ips)[:max_candidate_ips_per_user]
        for ip_a in ips_list:
            for ip_b in ips_list:
                if ip_a < ip_b:
                    candidate_pairs.add((ip_a, ip_b))
    # Also add subnet pairs (but only as candidates, shared_subnet alone won't union)
    for ips in subnet_ips.values():
        ips_list = sorted(ips)[:max_candidate_ips_per_subnet]
        for i in range(len(ips_list)):
            for j in range(i + 1, len(ips_list)):
                candidate_pairs.add((ips_list[i], ips_list[j]))

    # Build per-user per-IP sorted timestamps for time proximity (binary scan)
    user_ip_sorted_times: dict[str, dict[str, list[datetime]]] = defaultdict(dict)
    for ip, d in ip_data.items():
        for user in d["users"]:
            # Collect timestamps of events from this IP by this user
            user_ip_sorted_times[user][ip] = []

    # Stream events once more to populate user_ip_sorted_times (cheap, just timestamp extraction)
    for event in iter_ndjson(json_dir / "task2_events.ndjson"):
        user = event.get("user", "")
        src_ip = event.get("src_ip", "")
        if not user or not src_ip or src_ip == "unknown":
            continue
        ts = parse_ts(event.get("timestamp", ""))
        if ts and src_ip in user_ip_sorted_times.get(user, {}):
            times = user_ip_sorted_times[user][src_ip]
            if len(times) < max_time_samples_per_user_ip:
                times.append(ts)

    for user, ip_map in user_ip_sorted_times.items():
        for ip, times in ip_map.items():
            times.sort()

    # Compute edges only for candidate pairs
    ip_edges = []
    for ip_a, ip_b in sorted(candidate_pairs):
        d_a, d_b = ip_data[ip_a], ip_data[ip_b]
        edge_types = []
        shared_users = sorted(d_a["users"] & d_b["users"])
        shared_sessions = sorted(d_a["sessions"] & d_b["sessions"])
        subnet_a = compute_subnet(ip_a)
        subnet_b = compute_subnet(ip_b)

        if shared_users:
            edge_types.append("shared_user")
        if shared_sessions:
            edge_types.append("shared_session")
        if subnet_a and subnet_b and subnet_a == subnet_b:
            edge_types.append("shared_subnet")

        # Time proximity: sorted scan instead of nested loop
        max_gap = None
        for user in shared_users:
            times_a = user_ip_sorted_times.get(user, {}).get(ip_a, [])
            times_b = user_ip_sorted_times.get(user, {}).get(ip_b, [])
            if not times_a or not times_b:
                continue
            i = 0
            j = 0
            found = False
            while i < len(times_a) and j < len(times_b):
                gap = (times_a[i] - times_b[j]).total_seconds()
                abs_gap = abs(gap)
                if abs_gap <= TIME_PROXIMITY_WINDOW:
                    found = True
                    if max_gap is None or abs_gap > max_gap:
                        max_gap = abs_gap
                    if times_a[i] <= times_b[j]:
                        i += 1
                    else:
                        j += 1
                elif gap < 0:
                    i += 1
                else:
                    j += 1
            if found:
                edge_types.append("time_proximity")

        if edge_types:
            ip_edges.append({
                "ip_a": ip_a, "ip_b": ip_b,
                "edge_types": edge_types,
                "shared_users": shared_users,
                "shared_sessions": shared_sessions,
                "max_time_gap_seconds": round(max_gap, 1) if max_gap else None,
            })

    # --- Step D: Find IP clusters via Union-Find ---
    uf = UnionFind()
    # Ensure all IPs are registered in UnionFind
    for ip in ip_data:
        uf.find(ip)
    for edge in ip_edges:
        types = set(edge["edge_types"])
        stronger = types - {"shared_subnet"}
        if stronger:
            uf.union(edge["ip_a"], edge["ip_b"])

    clusters = uf.clusters()
    ip_clusters = []
    cluster_idx = 0
    for root, members in sorted(clusters.items()):
        if len(members) < 2:
            continue
        cluster_idx += 1
        cluster_users: set[str] = set()
        cluster_sessions: set[str] = set()
        cluster_anomalous = False
        total_events = 0
        for ip in members:
            cluster_users |= ip_data[ip]["users"]
            cluster_sessions |= ip_data[ip]["sessions"]
            if ip_data[ip]["is_anomalous"]:
                cluster_anomalous = True
            total_events += ip_data[ip]["event_count"]

        ip_clusters.append({
            "cluster_id": f"ip-cluster-{cluster_idx:03d}",
            "ips": sorted(members),
            "shared_users": sorted(cluster_users - {"unknown", ""}),
            "total_events": total_events,
            "session_count": len(cluster_sessions),
            "is_anomalous_cluster": cluster_anomalous,
            "alert_session_ids": sorted(
                s for s in cluster_sessions if s in anomalous_session_ids
            ),
        })

    # --- Step E: Detect cross-user IP patterns ---
    cross_user_ip_patterns = []
    for ip, d in sorted(ip_data.items()):
        users = sorted(d["users"] - {"unknown", ""})
        if len(users) < 2:
            continue
        pattern_type = "multi_user_auth"
        if len(users) >= 3:
            pattern_type = "suspicious_multi_user"
        results = d["results"]
        has_ok = "ok" in results
        has_fail = any(r in results for r in ("fail", "denied", "error"))
        if has_ok and has_fail and len(users) >= 2:
            pattern_type = "credential_probing"

        cross_user_ip_patterns.append({
            "ip": ip,
            "pattern_type": pattern_type,
            "users": users,
            "sessions": sorted(d["sessions"])[:max_sessions_per_ip],
            "details": f"IP {ip} accessed by {len(users)} users with actions {sorted(d['actions'])}",
        })

    # --- Step F: Build anomalous IP nodes summary ---
    anomalous_ip_nodes = []
    for ip, d in sorted(ip_data.items()):
        if not d["is_anomalous"]:
            continue
        reasons = set()
        for eid in d["anomalous_event_ids"][:50]:
            if eid in anomalous_rule_map:
                reasons.update(anomalous_rule_map[eid])
        anomalous_ip_nodes.append({
            "ip": ip,
            "subnet": compute_subnet(ip),
            "users": sorted(d["users"] - {"unknown", ""}),
            "anomalous_event_count": len(d["anomalous_event_ids"]),
            "reasons": sorted(reasons),
        })

    # --- Serialize IP node data for output ---
    ip_nodes_output = []
    for ip, d in sorted(ip_data.items()):
        ip_nodes_output.append({
            "ip": ip,
            "subnet": compute_subnet(ip),
            "users": sorted(d["users"]),
            "sessions": sorted(d["sessions"])[:max_sessions_per_ip],
            "paths": sorted(d["paths"])[:max_paths_per_ip],
            "action_types": sorted(d["actions"]),
            "result_distribution": dict(d["result_counts"]),
            "time_range": {
                "start": d["first_ts"].isoformat() if d["first_ts"] else "",
                "end": d["last_ts"].isoformat() if d["last_ts"] else "",
            },
            "event_count": d["event_count"],
            "is_anomalous": d["is_anomalous"],
            "anomalous_event_ids": d["anomalous_event_ids"][:20],
        })

    # --- Build output ---
    record = make_base_record(run_dir.name, "task2", "build_correlation_graph.py")
    record.update({
        "large_mode": runtime_config["large_mode"],
        "correlation_limits": {
            "max_candidate_ips_per_user": max_candidate_ips_per_user,
            "max_candidate_ips_per_subnet": max_candidate_ips_per_subnet,
            "max_paths_per_ip": max_paths_per_ip,
            "max_sessions_per_ip": max_sessions_per_ip,
            "max_time_samples_per_user_ip": max_time_samples_per_user_ip,
        },
        "total_ip_nodes": len(ip_nodes_output),
        "anomalous_ip_count": len(anomalous_ip_nodes),
        "total_ip_edges": len(ip_edges),
        "ip_cluster_count": len(ip_clusters),
        "ip_nodes": ip_nodes_output,
        "ip_edges": ip_edges,
        "ip_clusters": ip_clusters,
        "cross_user_ip_patterns": cross_user_ip_patterns,
        "anomalous_ip_nodes": anomalous_ip_nodes,
    })
    dump_json(json_dir / "task2_ip_correlation.json", record)


if __name__ == "__main__":
    main()
