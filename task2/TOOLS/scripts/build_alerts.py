#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from event_io import iter_ndjson
from input_layout import load_noise_policy, resolve_input_layout
from lib import dump_json, load_json, make_base_record


REASON_LABELS = {
    "source deviation": "来源地址偏离历史基线",
    "action deviation": "操作类型偏离历史基线",
    "path deviation": "访问路径偏离历史基线",
    "auth deviation": "认证方式偏离历史基线",
    "client deviation": "客户端版本偏离历史基线",
    "time deviation": "访问时段偏离历史基线",
    "failure deviation": "失败行为与历史失败率不一致",
    "volume deviation": "传输体量显著偏离历史范围",
    "first-time source IP": "首次出现的新来源IP地址",
    "privilege path access": "访问特权/系统目录路径",
    "sensitive file access": "访问/传输敏感文件类型",
    "data exfiltration indicator": "数据外泄指标（出流量异常偏大）",
    "bulk data download": "批量数据下载（单次传输量偏大）",
    "in/out ratio deviation": "进出流量比率偏离基线",
    "brute force attempt": "暴力破解尝试（短时间内多次登录失败）",
    "dormant account activation": "休眠账户突然激活",
    "unusual result type": "异常结果类型",
    "session imbalance": "会话出现打开未关闭或开闭不平衡现象",
    "multi-source burst": "同一用户在短时间内出现多个不同来源地址",
    "long session": "会话持续时间异常偏长",
    "multi-IP session": "同一会话中出现多个不同来源IP",
    "crawl behavior": "短时间大量路径扫描（爬取行为）",
    "session data exfiltration": "会话级数据外泄（会话总传输量异常偏大）",
    "orphan session": "孤立会话（会话打开但未正常关闭）",
    "login brute force": "登录暴力破解（同一IP对同一用户短时间多次失败）",
    "cross-user shared IP": "跨用户共享IP（同一IP被多个不同用户使用）",
    "weak kex algorithm": "使用了不安全的密钥交换算法",
    "weak hostkey algorithm": "使用了不安全的主机密钥算法",
    "weak cipher algorithm": "使用了不安全的加密算法",
    "weak mac algorithm": "使用了不安全的MAC算法",
    "protocol negotiation deviation": "协议协商参数偏离历史基线",
    "same source multi-target fanout": "同一来源在短时间内访问多个 SFTP 目标，存在横向探测或批量尝试访问风险",
    "correlated action sequence": "多个用户执行相同的异常操作序列，可能存在共享攻击工具或凭证泄露",
    "account risk aggregation": "同一账户在同一时间窗口内聚合出多类异常，账户整体风险升高",
}


def explain_reasons(reasons: list[str]) -> str:
    return "；".join(REASON_LABELS.get(reason, reason) for reason in reasons)


def parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def severity_from_score(score: int, src_subnets: list[str], trusted_subnets: set, deprioritize_types: set, trigger_type: str) -> str:
    base = "high" if score >= 80 else "medium" if score >= 60 else "low"
    if src_subnets and all(s in trusted_subnets for s in src_subnets):
        base = "low" if base == "medium" else "medium"
    if trigger_type in deprioritize_types:
        base = "low" if base == "medium" else base
    return base


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--input-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    layout = resolve_input_layout(Path(args.input_dir))
    noise_policy = load_noise_policy(layout.policy_path)
    suppress_users = set(noise_policy.get("suppress_users", []))
    trusted_src_subnets = set(noise_policy.get("trusted_src_subnets", []))
    deprioritize_types = set(noise_policy.get("deprioritize_trigger_types", []))
    multi_source_window = int(noise_policy.get("concurrent_session_window_seconds", 60))
    account_risk_strategy = noise_policy.get("account_risk_strategy", "account")

    grouped = defaultdict(
        lambda: {
            "user": "unknown",
            "start": "",
            "end": "",
            "reasons": set(),
            "event_ids": [],
            "supporting_scores": [],
            "max_score": 0,
            "src_ips": set(),
            "src_subnets": set(),
            "event_count": 0,
        }
    )
    for item in iter_ndjson(json_dir / "task2_anomaly_scores.ndjson"):
        if not item.get("threshold_hit"):
            continue
        session_id = item.get("session_id", "") or f"user:{item.get('user')}"
        group = grouped[session_id]
        user = item.get("user", "unknown")
        if group["user"] in {"", "unknown"} and user not in {"", "unknown"}:
            group["user"] = user
        ts = item.get("timestamp", "")
        if ts and (not group["start"] or ts < group["start"]):
            group["start"] = ts
        if ts and (not group["end"] or ts > group["end"]):
            group["end"] = ts
        group["reasons"].update(item.get("rule_hits", []))
        if len(group["event_ids"]) < 10:
            group["event_ids"].append(item.get("item_id"))
        if len(group["supporting_scores"]) < 10:
            group["supporting_scores"].append(
                {
                    "item_id": item.get("item_id"),
                    "score_total": item.get("score_total"),
                    "rule_hits": item.get("rule_hits"),
                    "threshold_hit": item.get("threshold_hit"),
                }
            )
        group["max_score"] = max(group["max_score"], item.get("score_total", 0))
        if item.get("src_ip"):
            group["src_ips"].add(item.get("src_ip"))
        if item.get("src_subnet"):
            group["src_subnets"].add(item.get("src_subnet"))
        group["event_count"] += 1

    session_scores = list(iter_ndjson(json_dir / "task2_session_anomaly_scores.ndjson"))
    session_views = {}
    for session in iter_ndjson(json_dir / "task2_session_views.ndjson"):
        sid = session.get("session_id")
        if sid:
            session_views[sid] = {
                "session_id": sid,
                "users": session.get("users", []),
                "inferred_user": session.get("inferred_user", ""),
                "start_time": session.get("start_time", ""),
                "end_time": session.get("end_time", ""),
                "src_ips": session.get("src_ips", []),
                "server_ips": session.get("server_ips", []),
                "system_names": session.get("system_names", []),
                "action_sequence": session.get("action_sequence", [])[:50],
                "paths": session.get("paths", [])[:50],
                "event_count": session.get("event_count", 0),
                "open_count": session.get("open_count", 0),
                "close_count": session.get("close_count", 0),
                "unbalanced_session": session.get("unbalanced_session", False),
            }
    scores_meta = load_json(json_dir / "task2_anomaly_scores.json", {})
    stage1_candidates = load_json(json_dir / "task2_stage1_candidates.json", {})
    sequence_clusters = load_json(json_dir / "task2_sequence_clusters.json", {})

    alerts = []
    alert_idx = 0

    # --- Event-level alerts (grouped by session, using score fields only) ---
    for session_id, group in sorted(grouped.items()):
        user = group["user"]
        if user in suppress_users:
            continue
        alert_idx += 1
        reasons = sorted(group["reasons"])
        explanation = explain_reasons(reasons)
        event_ids = group["event_ids"]
        max_score = group["max_score"]
        src_ips = sorted(group["src_ips"])
        src_subnets = sorted(group["src_subnets"])

        # Determine trigger_type based on reasons
        trigger_type = "session_behavioral_deviation"
        if "brute force attempt" in reasons:
            trigger_type = "login_brute_force"
        elif any(r in reasons for r in ["data exfiltration indicator", "bulk data download", "session data exfiltration"]):
            trigger_type = "data_exfiltration"
        elif any(r in reasons for r in ["privilege path access", "sensitive file access"]):
            trigger_type = "sensitive_access"
        elif any(r in reasons for r in ["weak kex algorithm", "weak hostkey algorithm", "weak cipher algorithm", "weak mac algorithm", "protocol negotiation deviation"]):
            trigger_type = "protocol_security_risk"
        elif any(r in reasons for r in ["first-time source IP"]):
            trigger_type = "anomalous_source"
        elif any(r in reasons for r in ["dormant account activation"]):
            trigger_type = "dormant_activation"

        sev = severity_from_score(max_score, src_subnets, trusted_src_subnets, deprioritize_types, trigger_type)

        alerts.append(
            {
                "alert_id": f"alert-{alert_idx}",
                "severity": sev,
                "user": user,
                "session_id": session_id,
                "time_window": {
                    "start": group["start"],
                    "end": group["end"],
                },
                "trigger_type": trigger_type,
                "trigger_reasons": reasons,
                "supporting_event_ids": event_ids,
                "supporting_scores": group["supporting_scores"],
                "session_summary": {
                    "src_ips": src_ips,
                    "src_subnets": src_subnets,
                    "event_count": group["event_count"],
                },
                "recommended_action": {
                    "login_brute_force": "Block source IP, force password reset for affected user, review login policies.",
                    "data_exfiltration": "Review outbound data, inspect accessed paths, verify authorization for large transfers.",
                    "sensitive_access": "Review access authorization for privileged paths, check file integrity.",
                    "protocol_security_risk": "Review negotiated SSH/SFTP algorithms and client software version. Consider disabling weak KEX/cipher/MAC and updating legacy clients.",
                    "anomalous_source": "Verify source IP legitimacy, check VPN/proxy logs, confirm user location.",
                    "dormant_activation": "Review account status, verify authorization, check if legitimate return to work.",
                    "session_behavioral_deviation": "Review account activity, validate source context, and inspect the full session sequence.",
                }.get(trigger_type, "Review account activity, validate source context, and inspect the full session sequence."),
                "status": "open",
                "llm_explanation": explanation or "该告警由脚本打分触发，需要进一步人工复核。",
                "llm_confidence": "medium",
            }
        )

    # --- Session-level alerts ---
    for item in session_scores:
        if not item.get("threshold_hit"):
            continue
        user = item.get("user", "unknown")
        if user in suppress_users:
            continue
        alert_idx += 1
        reasons = item.get("rule_hits", [])
        trigger_type = "session_anomaly"
        if any(r in reasons for r in ["weak kex algorithm", "weak hostkey algorithm", "weak cipher algorithm", "weak mac algorithm", "protocol negotiation deviation"]):
            trigger_type = "protocol_security_risk"
        elif "crawl behavior" in reasons:
            trigger_type = "crawl_behavior"
        elif "session data exfiltration" in reasons:
            trigger_type = "session_data_exfiltration"
        elif "long session" in reasons:
            trigger_type = "long_session"
        elif any(reason.startswith("orphan session") for reason in reasons):
            trigger_type = "orphan_session"
        elif "multi-IP session" in reasons:
            trigger_type = "multi_ip_session"

        sev = severity_from_score(item.get("score_total", 0), [], trusted_src_subnets, deprioritize_types, trigger_type)

        alerts.append(
            {
                "alert_id": f"alert-{alert_idx}",
                "severity": sev,
                "user": user,
                "session_id": item.get("session_id", ""),
                "time_window": {
                    "start": "",
                    "end": "",
                },
                "trigger_type": trigger_type,
                "trigger_reasons": reasons,
                "supporting_event_ids": [],
                "supporting_scores": [],
                "session_summary": {
                    "duration_minutes": item.get("session_duration_minutes", 0),
                    "distinct_ip_count": item.get("distinct_ip_count", 0),
                    "unique_path_count": item.get("unique_path_count", 0),
                    "total_bytes": item.get("total_session_bytes", 0),
                },
                "recommended_action": {
                    "crawl_behavior": "Check if user is performing authorized directory scanning. Block or rate-limit if unauthorized.",
                    "protocol_security_risk": "Review negotiated SSH/SFTP algorithms and client software version for this session. Disable weak KEX/hostkey/cipher/MAC and verify whether the client is an outdated automation component.",
                    "session_data_exfiltration": "Review session data volume, inspect all transferred files, verify authorization.",
                    "long_session": "Check session legitimacy, verify if user was actually active throughout. Investigate persistent connections.",
                    "orphan_session": "Review session logs, check if session was abnormally terminated. Investigate potential session hijacking.",
                    "multi_ip_session": "Check if IPs belong to same geographic region or proxy. Investigate potential credential sharing or hijacking.",
                    "session_anomaly": "Full session review required.",
                }.get(trigger_type, "Full session review required."),
                "status": "open",
                "llm_explanation": explain_reasons(reasons),
                "llm_confidence": "medium",
            }
        )

    # --- Unbalanced session alerts ---
    existing_sessions = {alert.get("session_id") for alert in alerts}
    for session_id, session in sorted(session_views.items()):
        if not session.get("unbalanced_session") or session_id in existing_sessions:
            continue
        user = session.get("users", ["unknown"])[0] if session.get("users") else "unknown"
        inferred_user = session.get("inferred_user", "")
        display_user = inferred_user or user
        if user in suppress_users:
            continue
        alert_idx += 1
        reasons = ["session imbalance"]
        alerts.append(
            {
                "alert_id": f"alert-{alert_idx}",
                "severity": "medium",
                "user": display_user,
                "raw_user": user,
                "inferred_user": inferred_user,
                "session_id": session_id,
                "time_window": {"start": session.get("start_time", ""), "end": session.get("end_time", "")},
                "trigger_type": "session_state_anomaly",
                "trigger_reasons": reasons,
                "supporting_event_ids": [],
                "supporting_scores": [],
                "session_summary": {
                    "src_ips": session.get("src_ips", []),
                    "action_sequence": session.get("action_sequence", []),
                    "paths": session.get("paths", []),
                    "event_count": session.get("event_count", 0),
                    "open_count": session.get("open_count", 0),
                    "close_count": session.get("close_count", 0),
                },
                "recommended_action": "Review whether the session ended normally and inspect the associated client source.",
                "status": "open",
                "llm_explanation": explain_reasons(reasons),
                "llm_confidence": "medium",
            }
        )

    # --- Multi-source burst alerts ---
    by_user = defaultdict(list)
    for session in session_views.values():
        users = session.get("users", [])
        if len(users) != 1:
            continue
        user = users[0]
        start = parse_ts(session.get("start_time", ""))
        if start is None:
            continue
        by_user[user].append({"session_id": session.get("session_id"), "start": start, "src_ips": session.get("src_ips", []), "action_sequence": session.get("action_sequence", [])})

    for user, sessions in sorted(by_user.items()):
        if user in suppress_users:
            continue
        sessions.sort(key=lambda item: item["start"])
        for i in range(len(sessions)):
            current = sessions[i]
            current_ips = set(current["src_ips"])
            if not current_ips:
                continue
            burst = [current]
            for j in range(i + 1, len(sessions)):
                other = sessions[j]
                delta = (other["start"] - current["start"]).total_seconds()
                if delta > multi_source_window:
                    break
                if set(other["src_ips"]) != current_ips:
                    burst.append(other)
            distinct_ips = sorted({ip for session in burst for ip in session["src_ips"]})
            if len(burst) >= 2 and len(distinct_ips) >= 2:
                alert_idx += 1
                reasons = ["multi-source burst"]
                alerts.append(
                    {
                        "alert_id": f"alert-{alert_idx}",
                        "severity": "low" if "multi_source_burst" in deprioritize_types else "medium",
                        "user": user,
                        "session_id": f"multi-source:{user}:{current['start'].isoformat()}",
                        "time_window": {"start": current["start"].isoformat(), "end": burst[-1]["start"].isoformat()},
                        "trigger_type": "multi_source_burst",
                        "trigger_reasons": reasons,
                        "supporting_event_ids": [],
                        "supporting_scores": [],
                        "session_summary": {"src_ips": distinct_ips, "related_sessions": [item["session_id"] for item in burst], "event_count": len(burst)},
                        "recommended_action": "Check whether the same account is legitimately used from multiple networks in a short window.",
                        "status": "open",
                        "llm_explanation": explain_reasons(reasons),
                        "llm_confidence": "medium",
                    }
                )
                break

    # --- Brute force alerts ---
    for bf in scores_meta.get("brute_force_clusters", []):
        alert_idx += 1
        alerts.append(
            {
                "alert_id": f"alert-{alert_idx}",
                "severity": "high",
                "user": bf.get("user", "unknown"),
                "session_id": f"bruteforce:{bf.get('user')}:{bf.get('src_ip')}",
                "time_window": {"start": bf.get("first_failure", ""), "end": bf.get("last_failure", "")},
                "trigger_type": "login_brute_force",
                "trigger_reasons": ["login brute force"],
                "supporting_event_ids": bf.get("event_ids", []),
                "supporting_scores": [],
                "session_summary": {"src_ips": [bf.get("src_ip")], "failure_count": bf.get("failure_count"), "time_window_seconds": bf.get("time_window_seconds")},
                "recommended_action": "Block source IP, force password reset, review login policies.",
                "status": "open",
                "llm_explanation": explain_reasons(["login brute force"]),
                "llm_confidence": "high",
            }
        )

    # --- Cross-user shared IP alerts ---
    for shared in scores_meta.get("cross_user_shared_ip_alerts", []):
        alert_idx += 1
        alerts.append(
            {
                "alert_id": f"alert-{alert_idx}",
                "severity": "medium",
                "user": "multiple",
                "session_id": f"shared-ip:{shared.get('shared_ip')}",
                "time_window": {"start": "", "end": ""},
                "trigger_type": "cross_user_shared_ip",
                "trigger_reasons": ["cross-user shared IP"],
                "supporting_event_ids": [],
                "supporting_scores": [],
                "session_summary": {"shared_ip": shared.get("shared_ip"), "user_count": shared.get("user_count"), "users": shared.get("users")},
                "recommended_action": "Investigate whether users share credentials or if IP is a shared proxy/VPN. Check for credential theft.",
                "status": "open",
                "llm_explanation": explain_reasons(["cross-user shared IP"]),
                "llm_confidence": "medium",
            }
        )

    # --- Same source visiting multiple SFTP targets ---
    for candidate in stage1_candidates.get("multi_target_source_candidates", []):
        alert_idx += 1
        targets = candidate.get("targets", [])
        users = candidate.get("users", [])
        src_ip = candidate.get("src_ip", "")
        alerts.append(
            {
                "alert_id": f"alert-{alert_idx}",
                "severity": "high" if len(targets) >= 3 else "medium",
                "user": "multiple" if len(users) != 1 else users[0],
                "session_id": f"multi-target:{src_ip}:{candidate.get('window_start', '')}",
                "time_window": {
                    "start": candidate.get("window_start", ""),
                    "end": candidate.get("window_end", ""),
                },
                "trigger_type": "same_source_multi_sftp_fanout",
                "trigger_reasons": ["same source multi-target fanout"],
                "supporting_event_ids": [],
                "supporting_scores": [],
                "session_summary": {
                    "src_ips": [src_ip],
                    "target_servers": targets,
                    "users": users,
                    "related_sessions": candidate.get("session_ids", []),
                    "event_count": len(candidate.get("session_ids", [])),
                },
                "recommended_action": "Review whether the same source is probing or attempting access across multiple SFTP servers in a short time window. Check source legitimacy, target spread, and correlated failures.",
                "status": "open",
                "llm_explanation": f"来源 {src_ip} 在短时间内访问了多个 SFTP 目标 {targets}，涉及用户 {users}，存在横向探测或批量尝试访问的风险。",
                "llm_confidence": "medium",
            }
        )

    # --- Account risk aggregation (default output strategy) ---
    if account_risk_strategy == "account":
        by_user_alerts: dict[str, list[dict]] = defaultdict(list)
        for alert in alerts:
            user = alert.get("user", "")
            if not user or user in {"unknown", "multiple"}:
                continue
            by_user_alerts[user].append(alert)
        for user, user_alerts in sorted(by_user_alerts.items()):
            high_count = sum(1 for a in user_alerts if a.get("severity") == "high")
            if len(user_alerts) < 2:
                continue
            trigger_reasons = sorted({reason for a in user_alerts for reason in a.get("trigger_reasons", [])})
            alert_idx += 1
            alerts.append(
                {
                    "alert_id": f"alert-{alert_idx}",
                    "severity": "high" if high_count >= 1 or len(user_alerts) >= 3 else "medium",
                    "user": user,
                    "session_id": f"account-risk:{user}",
                    "time_window": {"start": "", "end": ""},
                    "trigger_type": "account_risk_aggregation",
                    "trigger_reasons": ["account risk aggregation"] + trigger_reasons[:8],
                    "supporting_event_ids": [],
                    "supporting_scores": [],
                    "session_summary": {
                        "related_alert_ids": [a.get("alert_id") for a in user_alerts],
                        "alert_count": len(user_alerts),
                        "high_count": high_count,
                    },
                    "recommended_action": "Review the account as a whole across all related sessions, source IPs, authentication attempts, and negotiated protocol parameters.",
                    "status": "open",
                    "llm_explanation": explain_reasons(["account risk aggregation"]) + f"；该账户在当前窗口内关联 {len(user_alerts)} 条异常告警。",
                    "llm_confidence": "medium",
                }
            )

    # --- Cross-user sequence pattern alerts ---
    for pattern in sequence_clusters.get("cross_user_patterns", []):
        alert_idx += 1
        related_alert_ids = []
        pattern_sessions = set(pattern.get("session_ids", []))
        for existing_alert in alerts:
            if existing_alert.get("session_id") in pattern_sessions:
                related_alert_ids.append(existing_alert["alert_id"])

        alerts.append({
            "alert_id": f"alert-{alert_idx}",
            "severity": "high" if len(pattern.get("users", [])) >= 3 else "medium",
            "user": "multiple",
            "session_id": f"correlated-seq:{pattern.get('cluster_id')}",
            "time_window": {"start": "", "end": ""},
            "trigger_type": "correlated_attack_cluster",
            "trigger_reasons": ["correlated action sequence"],
            "supporting_event_ids": [],
            "supporting_scores": [],
            "correlation_data": {
                "cluster_id": pattern.get("cluster_id"),
                "pattern_type": pattern.get("pattern_type"),
                "shared_users": pattern.get("users", []),
                "sequence": pattern.get("sequence", []),
                "related_alert_ids": related_alert_ids,
            },
            "session_summary": {
                "cluster_id": pattern.get("cluster_id"),
                "users": pattern.get("users", []),
                "session_ids": pattern.get("session_ids", []),
                "sequence": pattern.get("sequence", []),
            },
            "recommended_action": "Multiple users performed the same anomalous action sequence. Investigate for shared attacker tooling, credential theft, or coordinated activity.",
            "status": "open",
            "llm_explanation": f"跨用户序列模式: {len(pattern.get('users', []))} 个用户执行序列 {pattern.get('sequence', [])}。{pattern.get('interpretation_hint', '')}",
            "llm_confidence": "medium",
        })

    record = make_base_record(run_dir.name, "task2", "build_alerts.py")
    record["events_scope_mode"] = "scoped" if (json_dir / "task2_events_scoped.ndjson").exists() else "full"
    record["alerts"] = alerts
    record["alert_type_summary"] = defaultdict(int, {a.get("trigger_type"): 0 for a in alerts})
    for a in alerts:
        record["alert_type_summary"][a.get("trigger_type")] += 1
    record["alert_type_summary"] = dict(record["alert_type_summary"])
    dump_json(json_dir / "task2_alerts.json", record)


if __name__ == "__main__":
    main()
