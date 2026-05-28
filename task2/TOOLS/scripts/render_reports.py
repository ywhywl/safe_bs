#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path

from event_io import iter_ndjson
from lib import load_json, render_markdown, write_text
from llm_client import create_client, InternalLLMClient


def summarize_sources(dataset_summary: dict) -> str:
    current_sources = dataset_summary.get("current_sources", [])
    baseline_sources = dataset_summary.get("baseline_sources", [])
    sources = dataset_summary.get("sources", [])
    if current_sources or baseline_sources:
        lines = []
        if baseline_sources:
            lines.append("历史基线数据：")
            for source in baseline_sources:
                lines.append(
                    f"- 文件: {source.get('path')}，格式猜测: {source.get('format_guess')}，行数: {source.get('line_count')}"
                )
        if current_sources:
            lines.append("当前检测数据：")
            for source in current_sources:
                lines.append(
                    f"- 文件: {source.get('path')}，格式猜测: {source.get('format_guess')}，行数: {source.get('line_count')}"
                )
        return "\n".join(lines)
    if not sources:
        return "未检测到输入日志。"
    lines = []
    for source in sources:
        lines.append(
            f"- 文件: {source.get('path')}，格式猜测: {source.get('format_guess')}，行数: {source.get('line_count')}"
        )
    return "\n".join(lines)


def summarize_views(views: list[dict]) -> str:
    if not views:
        return "未生成用户基线。"
    lines = []
    for view in views:
        lines.append(
            f"- 用户 {view.get('user')}: 常见来源 {view.get('common_sources')}, 常见动作 {view.get('common_actions')}, 常见路径 {view.get('common_paths')}, 常见时段 {view.get('typical_login_window')}"
        )
    return "\n".join(lines)


def summarize_alerts(alerts: list[dict]) -> str:
    if not alerts:
        return "当前样本未触发告警。"
    lines = []
    for alert in alerts:
        inferred = alert.get("inferred_user", "")
        inferred_text = f"，推断用户 {inferred}" if inferred else ""
        lines.append(
            f"- 告警 {alert.get('alert_id')}: 用户 {alert.get('user')}{inferred_text}，会话 {alert.get('session_id')}，级别 {alert.get('severity')}，原因 {alert.get('trigger_reasons')}，说明 {alert.get('llm_explanation')}"
        )
    return "\n".join(lines)


def summarize_list(values: list[str]) -> str:
    if not values:
        return "无"
    return "；".join(values)


def summarize_sessions(sessions: list[dict]) -> str:
    if not sessions:
        return "未生成会话视图。"
    lines = []
    for session in sessions:
        inferred = session.get("inferred_user", "")
        inferred_text = f"，推断用户 {inferred}" if inferred else ""
        lines.append(
            f"- 会话 {session.get('session_id')}: 用户 {session.get('users')}{inferred_text}，来源 {session.get('src_ips')}，动作序列 {session.get('action_sequence')}，时间范围 {session.get('start_time')} -> {session.get('end_time')}"
        )
    return "\n".join(lines)


def load_report_prompt(project_root: Path, prompt_type: str) -> str:
    prompt_path = project_root / "task2" / "TOOLS" / "prompts" / f"task2_{prompt_type}_prompt.md"
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8")
    prompt_path2 = project_root / "common" / "prompts" / f"task2_{prompt_type}_prompt.md"
    if prompt_path2.exists():
        return prompt_path2.read_text(encoding="utf-8")
    if prompt_type == "report":
        return "根据 task2_report_context.json 生成 REPORT.md 和 MANUAL.md。要求异常结论只能来自脚本打分，LLM 只负责解释和文档。"
    return "根据 task2_report_context.json 和告警数据生成 AI_REPORT.md。"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--llm-config", default="")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    project_root = Path(args.project_root)
    json_dir = run_dir / "task2" / "json"
    task_out = project_root / "task2"

    # LLM config
    if args.llm_config:
        llm_config_path = Path(args.llm_config)
    else:
        llm_config_path = task_out / "TOOLS" / "llm_config.json"
    client = create_client(llm_config_path)

    is_internal = isinstance(client, InternalLLMClient)
    llm_mode_desc = "内网私有化 LLM (glm-5.1)" if is_internal else "外网 LLM (Claude Code skill)"

    views = load_json(json_dir / "task2_baseline_views.json", {}).get("views", [])
    alerts = load_json(json_dir / "task2_alerts.json", {}).get("alerts", [])
    context = load_json(json_dir / "task2_report_context.json", {})
    sessions = list(iter_ndjson(json_dir / "task2_session_views.ndjson"))[:50]
    alert_count = context.get("alert_summary", {}).get("count", 0)

    context_json_str = json.dumps(context, ensure_ascii=False, indent=2)
    llm_output_dir = json_dir
    llm_output_dir.mkdir(parents=True, exist_ok=True)

    # Generate REPORT via LLM
    report_prompt = load_report_prompt(project_root, "report")
    report_content = client.generate(report_prompt, context_json_str, llm_output_dir)

    if report_content.startswith("EXTERNAL_LLM_PENDING"):
        # External mode: template-based placeholder
        manual = render_markdown(
            "MANUAL",
            [
                ("工具目标", "从 SFTP 日志中提取基线并识别异常。"),
                ("输入说明", summarize_sources(context.get("dataset_summary", {}))),
                ("输出说明", "输出 JSON、告警日志和报告草稿。"),
                ("核心流程", "日志解析 -> 事件归一化 -> 用户基线生成 -> 多维异常评分 -> 告警输出 -> 解释与文档生成。"),
                ("用户基线查看方式", summarize_views(views)),
                ("会话查看方式", summarize_sessions(sessions)),
                ("告警解释方式", summarize_alerts(alerts)),
                ("参数与阈值说明", "事件级 17 维度 + 会话级 5 维度 + 暴力破解 + 跨用户共享IP，总分 ≥ 60 触发。可信网段降级、降优先级类型、抑制用户可在 noise_policy.json 调整。"),
                ("适用范围与局限", summarize_list(context.get("limitations", []))),
                ("告警文件说明", "查看 task2/TOOLS/alerts/alert_output.log 或 runs 下对应输出。"),
            ],
        )
        report = render_markdown(
            "REPORT",
            [
                ("需求定义", "自动分析 SFTP 日志并识别异常行为。"),
                ("数据与假设", summarize_sources(context.get("dataset_summary", {}))),
                ("系统设计", "日志解析 -> 基线生成 -> 异常评分 -> 告警输出 -> LLM 解释。"),
                ("数据结构设计", "使用 events、baselines、alerts 三层 JSON。"),
                ("基线建模方法", summarize_views(views)),
                ("会话行为建模", summarize_sessions(sessions)),
                ("异常识别逻辑", str(context.get("detection_logic_summary", ""))),
                ("结果展示方式", f"本次运行共触发 {alert_count} 条告警。\n\n{summarize_alerts(alerts)}"),
                ("准确性与可复用性分析", "第一版强调可解释性与结构化过程，异常由脚本打分决定，LLM 不参与最终判定。"),
                ("局限与改进方向", summarize_list(context.get("limitations", []))),
                ("总结", "脚本决定异常，LLM 负责解释和报告。"),
            ],
        )
        write_text(llm_output_dir / "llm_prompt_input.md", report_prompt)
        write_text(llm_output_dir / "llm_context_input.json", context_json_str)
    else:
        # Internal mode: LLM API returned report content
        # Split into MANUAL and REPORT based on LLM output structure
        # If LLM returns a single doc, use it as REPORT and generate MANUAL from template
        report = report_content
        manual = render_markdown(
            "MANUAL",
            [
                ("工具目标", "从 SFTP 日志中提取基线并识别异常。"),
                ("输入说明", summarize_sources(context.get("dataset_summary", {}))),
                ("核心流程", "日志解析 -> 基线生成 -> 异常评分 -> 告警输出 -> LLM 解释。"),
                ("用户基线查看方式", summarize_views(views)),
                ("告警解释方式", summarize_alerts(alerts)),
                ("参数与阈值说明", "事件级 17 维度 + 会话级 5 维度，总分 ≥ 60 触发。noise_policy.json 可调阈值。"),
                ("告警文件说明", "查看 task2/TOOLS/alerts/alert_output.log。"),
            ],
        )

    # Generate AI_REPORT
    ai = render_markdown(
        "AI_REPORT",
        [
            ("使用的模型与工具", f"{llm_mode_desc}。\n异常评分脚本: score_anomalies.py（确定性多维打分，阈值 >= 60）。"),
            ("AI 参与环节", f"告警解释和文档生成。LLM 模式: {llm_mode_desc}。\n异常结论只能来自脚本打分，LLM 不参与最终判定。"),
            ("输入材料与中间数据", "task2_report_context.json、task2_alerts.json、task2_baseline_views.json、task2_session_views.ndjson"),
            ("关键提示策略", "强调 LLM 不直接改动异常判定结果，只负责解释和文档。异常结论必须可追溯到脚本评分。"),
            ("AI 产出与人工修正", "告警解释和报告内容可人工复核后定稿。异常判定结果由脚本确定性产出，无需 LLM 修正。"),
            ("有效实践总结", "两层架构：脚本确定性打分 + LLM 解释文档。JSON 中间态有利于限制幻觉。"),
            ("局限性", summarize_list(context.get("limitations", []))),
            ("工具评价", f"LLM: {llm_mode_desc}。适合做解释与文档，不适合作为核心判定。"),
            ("可复用沉淀", "基线/告警 JSON 结构、评分维度和阈值、LLM 客户端（外网/内网双模式）、task2 skill。"),
        ],
    )

    write_text(task_out / "MANUAL.md", manual)
    write_text(task_out / "REPORT.md", report)
    write_text(task_out / "AI_REPORT.md", ai)


if __name__ == "__main__":
    main()
