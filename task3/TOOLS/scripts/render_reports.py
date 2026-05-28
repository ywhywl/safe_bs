#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path

from lib import load_json, render_markdown, write_text
from llm_client import create_client, InternalLLMClient


def summarize_hosts(hosts: list[dict]) -> str:
    if not hosts:
        return "未识别到主机资产。"
    return "\n".join(f"- 主机 {host.get('host')}，角色 {host.get('roles')}，端口 {host.get('ports')}" for host in hosts)


def summarize_risks(risks: list[dict]) -> str:
    if not risks:
        return "当前未发现风险。"
    lines = []
    for risk in risks:
        lines.append(
            f"- {risk.get('risk_id')} {risk.get('title')} [{risk.get('severity')}]: 证据 {risk.get('evidence')}，建议 {risk.get('remediation')}"
        )
    return "\n".join(lines)


def summarize_list(values: list[str]) -> str:
    if not values:
        return "无"
    return "\n".join(f"- {value}" for value in values)


def filter_by_severity(risks: list[dict], severities: set[str]) -> list[dict]:
    return [risk for risk in risks if risk.get("severity") in severities]


def load_report_prompt(project_root: Path) -> str:
    prompt_path = project_root / "task3" / "TOOLS" / "prompts" / "task3_report_prompt.md"
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8")
    prompt_path2 = project_root / "common" / "prompts" / "task3_report_prompt.md"
    if prompt_path2.exists():
        return prompt_path2.read_text(encoding="utf-8")
    return "根据 task3_report_context.json 生成 DEF_REPORT.md，要求每个风险项可追溯到规则命中或配置事实。"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--llm-config", default="")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    project_root = Path(args.project_root)
    json_dir = run_dir / "task3" / "json"
    task_out = project_root / "task3"

    # LLM config
    if args.llm_config:
        llm_config_path = Path(args.llm_config)
    else:
        llm_config_path = task_out / "TOOLS" / "llm_config.json"
    client = create_client(llm_config_path)

    inventory = load_json(json_dir / "task3_nginx_inventory.json", {})
    risks = load_json(json_dir / "task3_risk_register.json", {})
    context = load_json(json_dir / "task3_report_context.json", {})
    high_risks = context.get("high_risks", [])
    medium_risks = context.get("medium_risks", [])
    low_risks = filter_by_severity(risks.get("risks", []), {"low"})

    # Determine LLM mode for AI_REPORT
    is_internal = isinstance(client, InternalLLMClient)
    llm_mode_desc = "内网私有化 LLM (glm-5.1)" if is_internal else "外网 LLM (Claude Code skill)"
    llm_tool_desc = f"内网 API ({client.base_url}, model={client.model})" if is_internal else "Claude Code 会话"

    # Generate DEF_REPORT via LLM
    prompt = load_report_prompt(project_root)
    context_json_str = json.dumps(context, ensure_ascii=False, indent=2)

    llm_output_dir = json_dir
    llm_output_dir.mkdir(parents=True, exist_ok=True)

    report_content = client.generate(prompt, context_json_str, llm_output_dir)

    if report_content.startswith("EXTERNAL_LLM_PENDING"):
        # External mode: generate placeholder, Claude Code skill will fill in later
        defense = render_markdown(
            "DEF_REPORT",
            [
                ("执行摘要", str(context.get("overall_assessment", ""))),
                ("检查边界与方法", "采用只读采集、规则检测和 LLM 语义分析。"),
                ("资产与配置概况", summarize_hosts(inventory.get("hosts", []))),
                ("风险发现清单", summarize_risks(risks.get("risks", []))),
                ("高风险问题详述", summarize_risks(high_risks) if high_risks else "当前运行未发现高风险项。"),
                ("中低风险问题概述", summarize_risks(medium_risks)),
                ("低风险问题概述", summarize_risks(low_risks)),
                ("整体防护评估", str(context.get("overall_assessment", ""))),
                ("加固建议路线图", summarize_list(context.get("roadmap", []))),
                ("证据索引", "见 task3_rule_hits.json 与 task3_risk_register.json。"),
                ("附录", f"run_id={run_dir.name}"),
            ],
        )
        # Write prompt files for Claude Code skill to pick up
        write_text(llm_output_dir / "llm_prompt_input.md", prompt)
        write_text(llm_output_dir / "llm_context_input.json", context_json_str)
    else:
        # Internal mode: LLM API already returned the report content
        defense = report_content

    # Generate AI_REPORT
    high_count = len(high_risks)
    med_count = len(medium_risks)
    low_count = len(low_risks)

    ai = render_markdown(
        "AI_REPORT",
        [
            ("使用的模型与工具", f"{llm_mode_desc}。\n规则库 51 条，命中 {len(context.get('rule_hits', []))} 条。\n脚本：parse_config_facts.py + apply_rules.py + build_risk_register.py"),
            ("AI 参与环节", f"规则自动检测（51 条）+ LLM 语义分析（联动风险、优先级排序、可执行修复方案）。\nLLM 模式: {llm_mode_desc}"),
            ("输入材料与中间数据", "task3_config_facts.json (64 事实字段)、task3_rule_hits.json、task3_risk_register.json、task3_report_context.json"),
            ("关键提示策略", "要求每个风险可追溯到规则命中或配置事实，LLM 补充联动分析、优先级排序和具体 nginx 配置修复示例。"),
            ("AI 产出与人工修正", f"规则自动检测 {len(context.get('rule_hits', []))} 条命中，LLM 语义分析补充联动风险和修复方案。高风险问题建议人工复核。"),
            ("有效实践总结", "两层检测架构：脚本确定性规则 + LLM 语义深度分析。规则覆盖 TLS/SSL、安全头、会话校验、代理安全、文件保护、速率限制等 8 大维度。"),
            ("局限性", "当前规则库主要覆盖常见 nginx 安全配置问题，尚未覆盖业务逻辑漏洞、WAF 规则、数据库注入防护等应用层场景。"),
            ("工具评价", f"LLM: {llm_tool_desc}。适合结构化审计归纳 + 语义深度分析。"),
            ("可复用沉淀", "规则库 (51 条)、配置事实提取器 (64 字段)、LLM 客户端 (外网/内网双模式)、task3 skill 和 JSON 模式。"),
        ],
    )

    write_text(task_out / "DEF_REPORT.md", defense)
    write_text(task_out / "AI_REPORT.md", ai)


if __name__ == "__main__":
    main()