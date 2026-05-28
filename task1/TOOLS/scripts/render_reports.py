#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, render_markdown, write_text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--project-root", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    project_root = Path(args.project_root)
    json_dir = run_dir / "task1" / "json"
    task_out = project_root / "task1"

    profile = load_json(json_dir / "task1_target_profile.json", {})
    facts = load_json(json_dir / "task1_recon_facts.json", {})
    hypotheses = load_json(json_dir / "task1_vuln_hypotheses.json", {})
    searchsploit = load_json(json_dir / "task1_searchsploit_matches.json", {})
    plan = load_json(json_dir / "task1_validation_plan.json", {})
    timeline = load_json(json_dir / "task1_execution_timeline.json", {})
    results = load_json(json_dir / "task1_validation_results.json", {})
    evidence = load_json(json_dir / "task1_evidence_index.json", {})

    att = render_markdown(
        "ATT_REPORT",
        [
            ("执行摘要", results.get("impact_summary", "待补充。")),
            ("测试边界与授权说明", str(profile.get("authorization_scope", ""))),
            ("目标识别与服务研判", str(facts.get("service_candidates", []))),
            ("漏洞发现过程", str({"hypotheses": hypotheses.get("candidate_vulnerabilities", []), "tool_intel": searchsploit.get("summary", {}), "sftp_candidate_ports": facts.get("sftp_candidate_ports", [])})),
            ("验证思路", str(plan.get("validation_sequence", []))),
            ("验证结果与成果", str(results.get("overall_result", ""))),
            ("影响分析", str(results.get("limitations", []))),
            ("关键证据索引", str(evidence.get("evidence_items", []))),
            ("修复与缓解建议", "升级版本、收敛暴露面、减少危险模块。"),
            ("附录", str(timeline.get("events", []))),
        ],
    )
    ai = render_markdown(
        "AI_REPORT",
        [
            ("使用的模型与工具", "题 1 允许外网 LLM，但仅处理脱敏上下文。"),
            ("AI 参与环节", "漏洞候选归纳、验证思路整理、报告起草。"),
            ("输入材料与中间数据", "task1_report_context.json、tool_manifest.json、ai_usage_trace.json"),
            ("关键提示策略", "强调事实、假设、验证结果分离。"),
            ("AI 产出与人工修正", "高风险结论需要人工复核。"),
            ("有效实践总结", "使用结构化 JSON 限制幻觉范围。"),
            ("局限性", "第一版未自动执行授权验证。"),
            ("工具评价", "LLM 适合归纳，不适合作为唯一判定器。"),
            ("可复用沉淀", "task1 skill、模板、JSON 模式。"),
        ],
    )

    write_text(task_out / "ATT_REPORT.md", att)
    write_text(task_out / "AI_REPORT.md", ai)


if __name__ == "__main__":
    main()
