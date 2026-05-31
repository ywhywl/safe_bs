#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from event_io import iter_ndjson
from lib import dump_json, load_json, load_task2_runtime_config, make_base_record


SIMILARITY_THRESHOLD = 0.6

ACTION_CATEGORY_MAP = {
    "LOGIN": "AUTH", "AUTH": "AUTH",
    "SESSION_OPEN": "SESSION_CTRL", "SESSION_CLOSE": "SESSION_CTRL",
    "GET": "DATA_IN", "DOWNLOAD": "DATA_IN",
    "PUT": "DATA_OUT", "UPLOAD": "DATA_OUT",
    "LIST": "LIST", "LS": "LIST", "DIR": "LIST",
    "DELETE": "DELETE", "DEL": "DELETE", "RM": "DELETE",
    "RENAME": "SESSION_CTRL", "MKDIR": "SESSION_CTRL", "CHMOD": "SESSION_CTRL",
    "PROGRAM": "PROGRAM",
}


def normalize_action(action: str) -> str:
    return ACTION_CATEGORY_MAP.get(action, action)


def normalize_sequence(actions: list[str]) -> list[str]:
    return [normalize_action(a) for a in actions]


def lcs_ratio(seq_a: list[str], seq_b: list[str]) -> float:
    m, n = len(seq_a), len(seq_b)
    if m == 0 or n == 0:
        return 0.0
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if seq_a[i - 1] == seq_b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    return dp[m][n] / max(m, n)


def sequences_are_similar(seq_a: list[str], seq_b: list[str]) -> bool:
    if len(seq_a) <= 3 and len(seq_b) <= 3:
        # Short sequences: require exact match of first/last + same length
        if len(seq_a) != len(seq_b):
            return False
        if not seq_a or not seq_b:
            return False
        return seq_a[0] == seq_b[0] and seq_a[-1] == seq_b[-1]
    return lcs_ratio(seq_a, seq_b) >= SIMILARITY_THRESHOLD


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    runtime_config = load_task2_runtime_config()
    max_sessions = runtime_config["sequence_max_sessions"]
    max_actions_per_session = runtime_config["sequence_max_actions_per_session"]

    # Build score lookup by streaming (no list storage needed)
    # Note: anomaly_scores.json was previously loaded here but never used (dead code removed)
    session_score_map: dict[str, dict] = {}
    for item in iter_ndjson(json_dir / "task2_anomaly_scores.ndjson"):
        sid = item.get("session_id", "")
        if not sid:
            continue
        existing = session_score_map.get(sid, {"score_total": 0, "threshold_hit": False, "rule_hits": set(), "user": ""})
        if item.get("score_total", 0) > existing["score_total"]:
            existing["score_total"] = item.get("score_total", 0)
        if item.get("threshold_hit"):
            existing["threshold_hit"] = True
        existing["rule_hits"] = existing.get("rule_hits", set()) | set(item.get("rule_hits", []))
        existing["user"] = item.get("user", existing.get("user", ""))
        session_score_map[sid] = existing

    # Session-level scores (streaming)
    for item in iter_ndjson(json_dir / "task2_session_anomaly_scores.ndjson"):
        sid = item.get("session_id", "")
        if not sid:
            continue
        existing = session_score_map.get(sid, {"score_total": 0, "threshold_hit": False, "rule_hits": set(), "user": ""})
        if item.get("score_total", 0) > existing["score_total"]:
            existing["score_total"] = item.get("score_total", 0)
        if item.get("threshold_hit"):
            existing["threshold_hit"] = True
        existing["rule_hits"] = existing.get("rule_hits", set()) | set(item.get("rule_hits", []))
        session_score_map[sid] = existing

    # --- Step A: Extract and normalize action sequences ---
    session_sequences: dict[str, dict] = {}
    for session in iter_ndjson(json_dir / "task2_session_views.ndjson"):
        if len(session_sequences) >= max_sessions:
            break
        sid = session.get("session_id", "")
        raw_actions = session.get("action_sequence", [])[:max_actions_per_session]
        normalized = normalize_sequence(raw_actions)
        users = session.get("users", [])
        session_sequences[sid] = {
            "normalized_sequence": normalized,
            "raw_actions": raw_actions,
            "users": users,
            "session_data": session,
        }

    # --- Step B: Build sequence pattern inventory ---
    # Canonical form: normalized sequence as tuple
    pattern_inventory: dict[tuple[str, ...], dict] = defaultdict(lambda: {
        "session_ids": [], "users": set(), "is_anomalous": False, "max_score": 0, "rule_hits": set(),
    })
    for sid, info in sorted(session_sequences.items()):
        canonical = tuple(info["normalized_sequence"])
        if not canonical:
            continue
        inv = pattern_inventory[canonical]
        inv["session_ids"].append(sid)
        for u in info["users"]:
            inv["users"].add(u)
        score_info = session_score_map.get(sid, {})
        if score_info.get("threshold_hit"):
            inv["is_anomalous"] = True
        inv["max_score"] = max(inv["max_score"], score_info.get("score_total", 0))
        inv["rule_hits"].update(score_info.get("rule_hits", []))

    # Serialize pattern inventory
    pattern_idx = 0
    sequence_patterns = []
    for canonical, inv in sorted(pattern_inventory.items()):
        pattern_idx += 1
        sequence_patterns.append({
            "pattern_id": f"pattern-{pattern_idx:03d}",
            "canonical_sequence": list(canonical),
            "session_count": len(inv["session_ids"]),
            "session_ids": inv["session_ids"],
            "users": sorted(inv["users"]),
            "is_anomalous": inv["is_anomalous"],
            "max_score": inv["max_score"],
            "avg_score": round(inv["max_score"] / max(len(inv["session_ids"]), 1), 1),
            "rule_hits": sorted(inv["rule_hits"]),
        })

    # --- Step C: Cluster anomalous sessions by sequence similarity ---
    anomalous_sessions = []
    for sid, info in sorted(session_sequences.items()):
        score_info = session_score_map.get(sid, {})
        if score_info.get("threshold_hit") and info["normalized_sequence"]:
            anomalous_sessions.append({
                "session_id": sid,
                "sequence": info["normalized_sequence"],
                "user": info["users"][0] if info["users"] else "unknown",
                "score": score_info.get("score_total", 0),
                "rule_hits": sorted(score_info.get("rule_hits", set())),
            })

    # Sort by score descending for greedy clustering
    anomalous_sessions.sort(key=lambda x: x["score"], reverse=True)

    assigned: dict[str, str] = {}  # session_id -> cluster_id
    clusters: dict[str, list[dict]] = {}  # cluster_id -> list of session info
    cluster_idx = 0

    for session in anomalous_sessions:
        sid = session["session_id"]
        if sid in assigned:
            continue
        cluster_idx += 1
        cluster_id = f"seq-cluster-{cluster_idx:03d}"
        clusters[cluster_id] = [session]
        assigned[sid] = cluster_id

        # Add similar unassigned sessions
        for other in anomalous_sessions:
            other_sid = other["session_id"]
            if other_sid in assigned:
                continue
            if sequences_are_similar(session["sequence"], other["sequence"]):
                clusters[cluster_id].append(other)
                assigned[other_sid] = cluster_id

    # --- Step D: Build pattern clusters output ---
    pattern_clusters = []
    for cluster_id, members in sorted(clusters.items()):
        cluster_users = set()
        cluster_rule_hits = set()
        max_score = 0
        avg_lcs = 0.0
        representative = members[0]["sequence"]
        lcs_count = 0

        for m in members:
            cluster_users.add(m["user"])
            cluster_rule_hits.update(m["rule_hits"])
            max_score = max(max_score, m["score"])

        # Compute pairwise LCS within cluster
        if len(members) > 1:
            total_lcs = 0
            pairs = 0
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    total_lcs += lcs_ratio(members[i]["sequence"], members[j]["sequence"])
                    pairs += 1
            avg_lcs = round(total_lcs / max(pairs, 1), 2)

        is_cross_user = len(cluster_users) >= 2
        pattern_clusters.append({
            "cluster_id": cluster_id,
            "representative_sequence": representative,
            "session_ids": [m["session_id"] for m in members],
            "users": sorted(cluster_users),
            "max_score": max_score,
            "avg_lcs_ratio": avg_lcs,
            "is_cross_user": is_cross_user,
            "rule_hits_overlap": sorted(cluster_rule_hits),
        })

    # --- Step E: Detect cross-user patterns ---
    cross_user_patterns = []
    for cluster in pattern_clusters:
        if not cluster["is_cross_user"]:
            continue
        interpretation = ""
        seq = cluster["representative_sequence"]
        if "DELETE" in seq:
            interpretation = f"{len(cluster['users'])} 个不同用户执行了包含删除操作的异常序列"
        elif "DATA_IN" in seq and "DATA_OUT" in seq:
            interpretation = f"{len(cluster['users'])} 个不同用户执行了包含数据上传下载的异常序列"
        elif "AUTH" in seq:
            interpretation = f"{len(cluster['users'])} 个不同用户执行了相同的异常认证序列"
        else:
            interpretation = f"{len(cluster['users'])} 个不同用户执行了相同的异常行为序列"

        cross_user_patterns.append({
            "cluster_id": cluster["cluster_id"],
            "pattern_type": "shared_anomalous_sequence",
            "users": cluster["users"],
            "session_ids": cluster["session_ids"],
            "sequence": cluster["representative_sequence"],
            "interpretation_hint": interpretation,
        })

    # --- Step F: Build anomalous sequence patterns summary ---
    anomalous_sequence_patterns = []
    for pattern in sequence_patterns:
        if not pattern["is_anomalous"]:
            continue
        anomalous_sequence_patterns.append({
            "pattern_id": pattern["pattern_id"],
            "canonical_sequence": pattern["canonical_sequence"],
            "affected_sessions": pattern["session_ids"],
            "affected_users": pattern["users"],
            "max_score": pattern["max_score"],
            "common_rule_hits": pattern["rule_hits"],
        })

    # --- Build output ---
    record = make_base_record(run_dir.name, "task2", "build_sequence_clusters.py")
    record.update({
        "events_scope_mode": "scoped" if (json_dir / "task2_events_scoped.ndjson").exists() else "full",
        "total_sessions_analyzed": len(session_sequences),
        "large_mode": runtime_config["large_mode"],
        "sequence_limits": {
            "max_sessions": max_sessions,
            "max_actions_per_session": max_actions_per_session,
        },
        "anomalous_sessions": len(anomalous_sessions),
        "pattern_count": len(sequence_patterns),
        "cross_user_pattern_count": len(cross_user_patterns),
        "sequence_patterns": sequence_patterns,
        "pattern_clusters": pattern_clusters,
        "cross_user_patterns": cross_user_patterns,
        "anomalous_sequence_patterns": anomalous_sequence_patterns,
    })
    dump_json(json_dir / "task2_sequence_clusters.json", record)


if __name__ == "__main__":
    main()
