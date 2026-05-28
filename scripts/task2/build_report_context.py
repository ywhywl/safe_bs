#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from event_io import iter_ndjson
from lib import dump_json, load_json, make_base_record


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
    record = make_base_record(run_dir.name, "task2", "build_report_context.py")
    formats = sorted({source.get("format_guess", "unknown") for source in manifest.get("log_sources", [])})
    record.update(
        {
            "dataset_summary": {
                "mode": manifest.get("dataset_mode", "single_dataset"),
                "sources": manifest.get("log_sources", []),
                "current_sources": manifest.get("current_log_sources", []),
                "baseline_sources": manifest.get("baseline_log_sources", []),
            },
            "baseline_method_summary": "基于成功事件构建用户画像，覆盖来源 IP/网段、常见动作/路径、活跃时段、认证方式、客户端版本、传输体量范围、进出比率、历史失败率、特权路径访问、敏感文件访问、登录成败按IP统计、跨用户共享IP。若输入目录包含 baseline/ 与 current/，则优先使用 baseline/ 构建历史基线，仅对 current/ 打分。",
            "detection_logic_summary": "采用确定性多维打分，事件级 17 维度（来源偏离、动作偏离、路径偏离、认证偏离、客户端偏离、时段偏离、失败偏离、体量偏离、首次来源IP、特权路径、敏感文件、数据外泄指标、批量下载、进出比偏离、暴力破解、休眠账户激活、异常结果类型），会话级 5 维度（长会话、多IP会话、爬取行为、会话数据外泄、孤立会话），外加暴力破解集群和跨用户共享IP检测。总分 ≥ 60 触发告警，并结合可信网段和降优先级策略调整严重等级。休眠账户按当前事件与历史 last_seen 间隔天数判定。",
            "alert_summary": {"count": len(alerts.get("alerts", [])), "types": alerts.get("alert_type_summary", {})},
            "representative_cases": alerts.get("alerts", [])[:5],
            "session_summary": {
                "count": sessions.get("session_count", 0),
                "representative_sessions": sessions.get("sessions_preview", [])[:5],
            },
            "baseline_summary": {
                "mode": baselines.get("baseline_mode", "single_dataset"),
                "baseline_event_count": baselines.get("baseline_event_count", 0),
                "current_event_count": baselines.get("current_event_count", 0),
            },
            "strengths": ["确定性多维评分，22维覆盖来源/行为/数据/会话四层", "支持 baseline/current 分离，避免当前窗口污染历史基线", "可解释且可追溯：每条告警附带触发原因和打分明细", "本地 JSON 管线，内网 LLM 双模式", "噪声策略可调：可信网段降级、降优先级类型、抑制用户"],
            "limitations": [
                "阈值仍采用启发式设置，尚未针对更大规模历史样本做调优",
                "会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检",
                "暴力破解检测基于滑动窗口，密集慢速攻击可能不触发",
            ],
            "supported_formats": formats,
            "manual_usage_summary": "人工复核时应结合 baseline_views、session_views 和 alert_output.log 查看完整上下文。",
            "ai_usage_summary": "LLM 仅用于解释和文档生成，不参与最终告警判定。",
        }
    )
    dump_json(json_dir / "task2_report_context.json", record)


if __name__ == "__main__":
    main()
