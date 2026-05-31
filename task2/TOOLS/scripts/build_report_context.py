#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, load_task2_runtime_config, make_base_record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    manifest = load_json(json_dir / "task2_log_ingest_manifest.json", {})
    # Only load alert summary and top-10 alerts (full load can be multi-GB)
    alerts_data = load_json(json_dir / "task2_alerts.json", {})
    alert_count = len(alerts_data.get("alerts", []))
    alert_types = alerts_data.get("alert_type_summary", {})
    representative_alerts = alerts_data.get("alerts", [])[:10]
    sessions = load_json(json_dir / "task2_session_views.json", {})
    stage1_baselines = load_json(json_dir / "task2_stage1_baselines.json", {})
    stage2_scope = load_json(json_dir / "task2_stage2_scope.json", {})
    baselines = load_json(json_dir / "task2_user_baselines.json", {})
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
            "baseline_method_summary": "当前采用两阶段方式处理数据。Stage 1 先基于全量归一化事件构建轻基线，只保留来源 IP/网段、目标 SFTP、访问时段、动作、客户端版本、失败率和体量均值等粗粒度画像，用于宽进候选筛选。Stage 2 再基于候选作用域抽出的 scoped 事件做精细基线和异常打分。若输入目录包含 baseline/ 与 current/，则仍优先使用 baseline/ 构建历史基线，仅对 current/ 打分。",
            "detection_logic_summary": "采用两阶段确定性架构：(1) Stage 1 宽进粗筛：全量归一化事件 -> 轻基线 -> 候选发现，覆盖失败登录、弱协议算法、异常大流量、同一来源访问多个 SFTP 服务器，以及基于粗基线的新来源/新网段/非常规时段/新目标/异常客户端等粗筛信号。(2) Stage 2 严出精跑：从候选账户、来源、目标和时间窗抽取 scoped 事件，随后在 scoped 子集上进行精细基线、事件级多维打分、会话级分析、序列聚类和账户风险聚合。当前关联分析以行为序列聚类和同源多目标 SFTP 扇出为主，LLM 仅负责将脚本产出的告警与模式串联为攻击叙事。",
            "alert_summary": {"count": alert_count, "types": alert_types},
            "representative_cases": [
                {
                    "alert_id": a.get("alert_id", ""),
                    "severity": a.get("severity", ""),
                    "user": a.get("user", ""),
                    "session_id": a.get("session_id", ""),
                    "trigger_type": a.get("trigger_type", ""),
                    "trigger_reasons": a.get("trigger_reasons", [])[:5],
                    "llm_explanation": a.get("llm_explanation", "")[:200],
                    "recommended_action": a.get("recommended_action", "")[:200] if isinstance(a.get("recommended_action"), str) else "",
                    "correlation_data": a.get("correlation_data"),
                    "session_summary": a.get("session_summary", {}),
                }
                for a in representative_alerts
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
            "stage1_summary": {
                "baseline_mode": stage1_baselines.get("baseline_mode", ""),
                "baseline_event_count": stage1_baselines.get("baseline_event_count", 0),
                "coarse_user_count": len(stage1_baselines.get("users", [])),
                "scope_mode": stage2_scope.get("scope_mode", ""),
                "scoped_event_count": stage2_scope.get("scoped_event_count", 0),
                "candidate_user_count": stage2_scope.get("candidate_user_count", 0),
                "candidate_src_ip_count": stage2_scope.get("candidate_src_ip_count", 0),
                "candidate_session_count": stage2_scope.get("candidate_session_count", 0),
                "candidate_target_count": stage2_scope.get("candidate_target_count", 0),
                "candidate_window_count": stage2_scope.get("candidate_window_count", 0),
            },
            "strengths": ["采用两阶段架构：Stage 1 轻基线粗筛，Stage 2 scoped 精跑，更适合大数据集", "确定性多维评分，覆盖来源/行为/数据/会话/协议安全五层", "支持 baseline/current 分离，满足以基准日志对比新日志的要求", "第三类 mod_sftp 协议日志纳入统一画像，可识别弱算法、协商漂移、老旧客户端指纹", "支持检测同一来源在短时间内访问多个 SFTP 服务器的横向探测行为", "默认按账户风险聚合输出，更贴近实际安全运营视角，同时保留会话级证据", "序列聚类提供跨用户关联发现，突破单用户基线局限", "可解释且可追溯：每条告警附带触发原因和打分明细，关联发现可追溯到序列模式", "本地 JSON 管线，内网 LLM 双模式", "噪声策略和白名单可调：可信网段、可信用户、可信客户端、算法策略均可配置", "LLM 语义化串联脚本产出的孤立告警为攻击叙事，限制幻觉"],
            "limitations": [
                "阈值仍采用启发式设置，尚未针对更大规模历史样本做调优",
                "会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检",
                "暴力破解检测基于滑动窗口，密集慢速攻击可能不触发",
                "开启 TASK2_LARGE_MODE=1 时，会对路径画像和序列聚类样本做截断，以换取 16G 机器上的稳定运行",
                "当前 scoped 抽取仍以候选时间窗、session、来源和目标命中为主，真实大数据上的压缩率仍需进一步验证和调优",
            ],
            "supported_formats": formats,
            "manual_usage_summary": "人工复核时应结合 baseline_views、session_views 和 alert_output.log 查看完整上下文。",
            "ai_usage_summary": "LLM 用于告警解释、关联推理和攻击叙事生成。异常判定和关联发现由脚本确定性产出，LLM 仅负责语义化解释和叙事串联，所有结论必须可追溯到脚本输出字段。",
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
            }
    )
    dump_json(json_dir / "task2_report_context.json", record)


if __name__ == "__main__":
    main()
