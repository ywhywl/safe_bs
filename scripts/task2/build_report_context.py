#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from event_io import iter_ndjson
from lib import dump_json, load_json, load_task2_runtime_config, make_base_record


def _build_correlation_insights(ip_corr: dict, seq_clusters: dict) -> list[dict]:
    insights = []
    for cluster in ip_corr.get("ip_clusters", []):
        if cluster.get("is_anomalous_cluster") and len(cluster.get("ips", [])) >= 2:
            insights.append({
                "type": "ip_cluster",
                "cluster_id": cluster["cluster_id"],
                "summary": f"IP集群 {cluster['cluster_id']}: {len(cluster['ips'])}个IP共享用户{cluster.get('shared_users', [])}",
                "severity": "high" if len(cluster.get("ips", [])) >= 3 else "medium",
            })
    for pattern in seq_clusters.get("cross_user_patterns", []):
        insights.append({
            "type": "cross_user_sequence",
            "cluster_id": pattern.get("cluster_id", ""),
            "summary": f"跨用户序列模式: 用户{pattern.get('users', [])}执行相同序列{pattern.get('sequence', [])}",
            "severity": "high" if len(pattern.get("users", [])) >= 3 else "medium",
        })
    return insights


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    manifest = load_json(json_dir / "task2_log_ingest_manifest.json", {})
    alerts = load_json(json_dir / "task2_alerts.json", {})
    sessions = load_json(json_dir / "task2_session_views.json", {})
    baselines = load_json(json_dir / "task2_user_baselines.json", {})
    ip_correlation = load_json(json_dir / "task2_ip_correlation.json", {})
    sequence_clusters = load_json(json_dir / "task2_sequence_clusters.json", {})
    runtime_config = load_task2_runtime_config()
    record = make_base_record(run_dir.name, "task2", "build_report_context.py")
    formats = sorted({source.get("format_guess", "unknown") for source in manifest.get("log_sources", [])})
    record.update(
        {
            "dataset_summary": {
                "mode": manifest.get("dataset_mode", "single_dataset"),
                "large_mode": runtime_config["large_mode"],
                "sources": manifest.get("log_sources", []),
                "current_sources": manifest.get("current_log_sources", []),
                "baseline_sources": manifest.get("baseline_log_sources", []),
            },
            "baseline_method_summary": "基于成功事件构建用户画像，覆盖来源 IP/网段、常见动作/路径、活跃时段、认证方式、客户端版本、传输体量范围、进出比率、历史失败率、特权路径访问、敏感文件访问、登录成败按IP统计、跨用户共享IP。若输入目录包含 baseline/ 与 current/，则优先使用 baseline/ 构建历史基线，仅对 current/ 打分。",
            "detection_logic_summary": "采用四层确定性架构：(1) 历史基线对比：若输入目录包含 baseline/ 与 current/，则只用 baseline/ 建立历史用户画像，对 current/ 逐条评分，满足“以某一天/某几天基准日志对比新日志”的要求。(2) 事件级多维打分：来源偏离、动作偏离、路径偏离、认证偏离、客户端偏离、时段偏离、失败偏离、体量偏离、首次来源IP、特权路径、敏感文件、数据外泄指标、批量下载、进出比偏离、暴力破解、休眠账户激活、异常结果类型；并新增 SSH/SFTP 协议安全维度：弱 KEX、弱 hostkey、弱 cipher、弱 MAC、协议协商偏离、老旧客户端指纹偏离。(3) 会话与关联分析：会话级 5 维度、IP关联图、跨用户IP模式、LCS 行为序列聚类。(4) 风险输出：默认按账户风险聚合，并保留会话级和关联级明细。LLM 仅负责将脚本产出的告警、IP集群和序列模式串联为攻击叙事。",
            "alert_summary": {"count": len(alerts.get("alerts", [])), "types": alerts.get("alert_type_summary", {})},
            "representative_cases": [
                {
                    "alert_id": a["alert_id"],
                    "severity": a["severity"],
                    "user": a["user"],
                    "session_id": a["session_id"],
                    "trigger_type": a.get("trigger_type", ""),
                    "trigger_reasons": a.get("trigger_reasons", []),
                    "llm_explanation": a.get("llm_explanation", ""),
                    "recommended_action": a.get("recommended_action", ""),
                    "correlation_data": a.get("correlation_data"),
                    "session_summary": a.get("session_summary", {}),
                }
                for a in alerts.get("alerts", [])[:10]
            ],
            "session_summary": {
                "count": sessions.get("session_count", 0),
                "representative_sessions": [
                    {
                        "session_id": s.get("session_id"),
                        "users": s.get("users", []),
                        "src_ips": s.get("src_ips", []),
                        "action_sequence": s.get("action_sequence", [])[:10],
                        "start_time": s.get("start_time", ""),
                        "end_time": s.get("end_time", ""),
                        "summary": s.get("summary", ""),
                    }
                    for s in sessions.get("sessions_preview", [])[:10]
                ],
            },
            "baseline_summary": {
                "mode": baselines.get("baseline_mode", "single_dataset"),
                "baseline_event_count": baselines.get("baseline_event_count", 0),
                "current_event_count": baselines.get("current_event_count", 0),
            },
            "strengths": ["确定性多维评分，覆盖来源/行为/数据/会话/协议安全五层", "支持 baseline/current 分离，满足以基准日志对比新日志的要求", "第三类 mod_sftp 协议日志纳入统一画像，可识别弱算法、协商漂移、老旧客户端指纹", "默认按账户风险聚合输出，更贴近实际安全运营视角，同时保留会话级证据", "IP关联图和序列聚类提供跨实体关联发现，突破单用户基线局限", "可解释且可追溯：每条告警附带触发原因和打分明细，关联发现可追溯到IP集群和序列模式", "本地 JSON 管线，内网 LLM 双模式", "噪声策略和白名单可调：可信网段、可信用户、可信客户端、算法策略均可配置", "LLM 语义化串联脚本产出的孤立告警为攻击叙事，限制幻觉"],
            "limitations": [
                "阈值仍采用启发式设置，尚未针对更大规模历史样本做调优",
                "会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检",
                "暴力破解检测基于滑动窗口，密集慢速攻击可能不触发",
                "开启 TASK2_LARGE_MODE=1 时，会对路径画像、序列聚类样本和关联图候选规模做截断，以换取 16G 机器上的稳定运行",
            ],
            "supported_formats": formats,
            "manual_usage_summary": "人工复核时应结合 baseline_views、session_views 和 alert_output.log 查看完整上下文。",
            "ai_usage_summary": "LLM 用于告警解释、关联推理和攻击叙事生成。异常判定和关联发现由脚本确定性产出，LLM 仅负责语义化解释和叙事串联，所有结论必须可追溯到脚本输出字段。",
            "ip_correlation_summary": {
                "total_ip_nodes": ip_correlation.get("total_ip_nodes", 0),
                "anomalous_ip_count": ip_correlation.get("anomalous_ip_count", 0),
                "ip_cluster_count": ip_correlation.get("ip_cluster_count", 0),
                "key_findings": [
                    f"检测到 {ip_correlation.get('ip_cluster_count', 0)} 个IP关联集群"
                ] if ip_correlation.get("ip_cluster_count", 0) > 0 else ["未发现显著IP关联模式"],
                "anomalous_clusters": [
                    {
                        "cluster_id": c["cluster_id"],
                        "ip_count": len(c.get("ips", [])),
                        "ips": c.get("ips", []),
                        "shared_users": c.get("shared_users", []),
                    }
                    for c in ip_correlation.get("ip_clusters", [])
                    if c.get("is_anomalous_cluster")
                ][:5],
                "cross_user_patterns": ip_correlation.get("cross_user_ip_patterns", [])[:5],
            },
            "sequence_cluster_summary": {
                "total_sessions_analyzed": sequence_clusters.get("total_sessions_analyzed", 0),
                "anomalous_sessions": sequence_clusters.get("anomalous_sessions", 0),
                "cross_user_pattern_count": sequence_clusters.get("cross_user_pattern_count", 0),
                "key_findings": [
                    f"检测到 {sequence_clusters.get('cross_user_pattern_count', 0)} 个跨用户行为序列模式"
                ] if sequence_clusters.get("cross_user_pattern_count", 0) > 0 else ["未发现显著跨用户序列模式"],
                "cross_user_patterns": [
                    {
                        "cluster_id": p.get("cluster_id", ""),
                        "users": p.get("users", []),
                        "sequence": p.get("sequence", []),
                    }
                    for p in sequence_clusters.get("cross_user_patterns", [])
                ][:5],
                "anomalous_patterns": [
                    {
                        "pattern_id": p.get("pattern_id", ""),
                        "sequence": p.get("canonical_sequence", []),
                        "affected_users": p.get("affected_users", []),
                        "max_score": p.get("max_score", 0),
                    }
                    for p in sequence_clusters.get("anomalous_sequence_patterns", [])
                ][:5],
            },
            "correlation_insights": _build_correlation_insights(ip_correlation, sequence_clusters),
        }
    )
    dump_json(json_dir / "task2_report_context.json", record)


if __name__ == "__main__":
    main()
