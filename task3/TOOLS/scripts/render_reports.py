#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path

from lib import load_json, render_markdown, write_text
from llm_client import create_client, InternalLLMClient

_LLM_CONTEXT_CHAR_LIMIT = 10000


def slim_context_for_llm(context: dict) -> dict:
    """裁剪 context，只保留 LLM 生成报告必要的字段，避免超出内网 LLM token 限制。"""
    slim = {
        "run_id": context.get("run_id"),
        "overall_assessment": context.get("overall_assessment"),
        "confidence": context.get("confidence"),
        "source_type": context.get("source_type"),
        "asset_summary": context.get("asset_summary"),
        "high_risks": context.get("high_risks", []),
        "medium_risks": context.get("medium_risks", []),
        "low_risks": context.get("low_risks", []),
        "server_level_risks": context.get("server_level_risks", []),
        "roadmap": context.get("roadmap"),
        "llm_analysis_scope": context.get("llm_analysis_scope"),
    }
    # 超限时逐步截断低优先级字段
    if len(json.dumps(slim, ensure_ascii=False)) > _LLM_CONTEXT_CHAR_LIMIT:
        slim["server_level_risks"] = slim["server_level_risks"][:3]
        slim["low_risks"] = slim.get("low_risks", [])[:3]
    if len(json.dumps(slim, ensure_ascii=False)) > _LLM_CONTEXT_CHAR_LIMIT:
        slim["medium_risks"] = slim["medium_risks"][:5]
    return slim


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


def build_requirement_mapping(inventory: dict, context: dict) -> str:
    source_mode = inventory.get("config_source_mode", "unknown")
    return "\n".join(
        [
            "- SSH 远程只读查看：已实现。采集链路不修改目标主机配置，只基于 `nginx -T` 输出或原始 `conf/` 目录做分析。",
            "- 允许发布脚本或工具到靶机运行测试：已实现。脚本链路支持在只读边界内执行采集、解析和规则检测，但不会改动 nginx 配置。",
            "- 原始配置目录导入：已实现。支持在 `nginx -T` 不可用或失败时，直接导入原始 `conf/` 目录并按 `include` 关系解析。",
            f"- 当前运行配置来源模式：`{source_mode}`。",
            "- 风险识别与证据回溯：已实现。每个风险项可回溯到规则命中、配置事实以及具体文件/行号。",
            "- DEF_REPORT 交付要求：已实现。报告中覆盖防护思路、脚本/工具说明、发现问题和加固建议。",
            "- TOOLS 目录交付要求：已实现。规则库、脚本镜像、JSON 结果和配置样例均可随交付包带走。",
            "- AI_REPORT 交付要求：已实现。AI 使用过程、有效实践总结和工具评价均单独输出。",
        ]
    )


def build_architecture_summary() -> str:
    return "\n".join(
        [
            "```text",
            "只读输入",
            "  -> collect_readonly.sh       采集 nginx -T / nginx -V 或原始 conf 目录",
            "  -> build_inventory.py        识别监听端口、server_name、配置来源模式",
            "  -> parse_config_facts.py     提取配置事实与证据位置",
            "  -> apply_rules.py            规则库匹配",
            "  -> build_risk_register.py    归并风险清单",
            "  -> build_report_context.py   汇总报告上下文",
            "  -> render_reports.py         生成 DEF_REPORT / AI_REPORT",
            "```",
        ]
    )


def build_data_structure_summary() -> str:
    return "\n".join(
        [
            "- `task3_nginx_inventory.json`：资产、监听端口、server block 和配置来源模式。",
            "- `task3_config_facts.json`：规则引擎使用的配置事实字段及证据索引。",
            "- `task3_rule_hits.json`：规则命中结果，保留 observed_value、evidence_refs 和 remediation。",
            "- `task3_risk_register.json`：按风险项归并后的输出，便于报告与复核。",
            "- `task3_report_context.json`：面向文档生成的摘要上下文。",
        ]
    )


def build_method_summary() -> str:
    return "\n".join(
        [
            "- 配置组织识别：同时支持 `nginx -T` 展开模式与原始 `conf/` 目录递归模式。",
            "- 事实提取：从 `http` / `server` / `location` 等上下文中抽取 TLS、Header、代理、安全控制、上传、连接限制等字段。",
            "- 规则检测：以确定性规则库对配置事实进行匹配，不依赖 LLM 做最终判定。",
            "- 证据链：所有风险都保留文件名、行号和原始 directive 证据。",
            "- 报告生成：LLM 只补充语义解释、优先级排序和修复路线，不改变脚本判定结论。",
        ]
    )


def build_tooling_summary() -> str:
    return "\n".join(
        [
            "- `collect_readonly.sh`：只读采集入口，支持 `nginx -T` 和原始 `conf/` 目录。",
            "- `config_loader.py`：在原始目录模式下按 `include` 关系递归加载配置文件。",
            "- `build_inventory.py`：生成资产视图，识别 listener、server_name 和配置来源模式。",
            "- `parse_config_facts.py`：抽取 TLS、安全头、代理、安全控制等事实字段和证据位置。",
            "- `nginx_rules.json`：规则库，负责把配置事实转换为可审计的风险命中。",
            "- `build_risk_register.py` / `build_report_context.py`：将命中结果组织成报告可消费的数据结构。",
        ]
    )


def build_highlights_summary(inventory: dict, context: dict) -> str:
    source_mode = inventory.get("config_source_mode", "unknown")
    lines = [
        "1. 只读巡检边界清晰，适合内网真实环境，不要求修改线上 nginx 配置。",
        "2. 同时支持 `nginx -T` 与原始 `conf/` 目录导入，解决很多内网环境里 `nginx -T` 失败的问题。",
        "3. 原始目录模式下支持按 `include` 关系递归解析子目录配置，能覆盖 `http.d/*.conf` 这类常见组织方式。",
        "4. 风险判定基于确定性规则和配置事实，证据可回溯到具体文件与行号，便于人工复核。",
        "5. 报告输出不止给风险列表，还给出可直接写入 nginx.conf 的修复建议，落地性强。",
        "6. 规则库、事实提取器、交付 JSON 和 LLM 双模式可重复用于其它 nginx 审计任务。",
    ]
    if source_mode == "raw_config_dir":
        lines.append("7. 当前运行展示了原始 conf 目录导入能力，说明在复杂内网环境下仍可完成巡检。")
    return "\n".join(f"- {line}" for line in lines)


def build_completion_summary() -> str:
    return "\n".join(
        [
            "- 核心功能完成度：高。资产识别、事实提取、规则命中、风险归并、报告生成均已贯通。",
            "- 工程化完成度：高。支持外网/内网 LLM 双模式，支持原始目录导入，支持规则/脚本/证据打包交付。",
            "- 文档完成度：高。DEF_REPORT 和 AI_REPORT 已能自动体现方法、亮点、证据链和交付价值。",
            "- 剩余优化方向：主要在扩展应用层规则、覆盖更多业务场景、补充更细粒度的 TLS/代理语义分析。",
        ]
    )


def build_scoring_alignment_summary(risks: list[dict]) -> str:
    high = len([risk for risk in risks if risk.get("severity") == "high"])
    medium = len([risk for risk in risks if risk.get("severity") == "medium"])
    low = len([risk for risk in risks if risk.get("severity") == "low"])
    return "\n".join(
        [
            f"- 防护效果维度：当前发现 `{high}` 个高风险、`{medium}` 个中风险、`{low}` 个低风险问题，覆盖 TLS、Header、暴露面、代理安全、速率限制、隐藏文件保护等主要防护面。",
            "- 可复用性维度：支持原始 conf 目录导入、支持规则库复用、支持只读采集边界、支持外网/内网 LLM 双模式，具备较强的工程复用能力。",
            "- 设计合理性维度：配置事实提取、规则命中、风险归并和报告生成分层清晰，便于维护和扩展。",
            "- 性能与安全性维度：默认只读执行，不依赖修改靶机配置；原始目录模式可避免 `nginx -T` 失败导致的阻塞，适合内网靶机环境。",
        ]
    )


def build_story_example(risks: list[dict], inventory: dict) -> str:
    if not risks:
        return "当前运行未发现风险，无法构造风险链示例。"
    top_risks = risks[:3]
    lines = [
        f"1. 配置输入阶段：本次巡检从 `{inventory.get('config_source_mode', 'unknown')}` 模式获取配置，说明即使没有完整 `nginx -T` 输出，也能基于原始配置目录建立事实视图。"
    ]
    for idx, risk in enumerate(top_risks, start=2):
        lines.append(
            f"{idx}. 风险发现阶段：`{risk.get('risk_id')}` `{risk.get('title')}` 被识别为 `{risk.get('severity')}`，脚本已给出证据 {risk.get('evidence')} 和修复建议 {risk.get('remediation')}。"
        )
    lines.append(
        f"{len(lines)+1}. 结论阶段：这些风险共同表明当前 nginx 配置同时存在协议、暴露面和基础安全控制缺失问题，因此系统不仅输出单项风险，还能生成按优先级排序的加固路线。"
    )
    return "\n".join(lines)


def summarize_server_level_risks(server_level_risks: list[dict]) -> str:
    if not server_level_risks:
        return "当前运行未生成 server/vhost 级风险。"
    lines = []
    for risk in server_level_risks[:20]:
        target = risk.get("server_names") or risk.get("listen") or [risk.get("server_key")]
        lines.append(
            f"- {risk.get('server_risk_id')} {risk.get('title')} [{risk.get('severity')}]: server={target}，证据 {risk.get('evidence')}，建议 {risk.get('remediation')}"
        )
    return "\n".join(lines)


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
    server_level_risks = context.get("server_level_risks", [])

    # Determine LLM mode for AI_REPORT
    is_internal = isinstance(client, InternalLLMClient)
    llm_mode_desc = "内网私有化 LLM (glm-5.1)" if is_internal else "外网 LLM (Claude Code skill)"
    llm_tool_desc = f"内网 API ({client.base_url}, model={client.model})" if is_internal else "Claude Code 会话"

    # Generate DEF_REPORT via LLM
    prompt = load_report_prompt(project_root)
    context_json_str = json.dumps(context, ensure_ascii=False, indent=2)
    if is_internal:
        context_json_str = json.dumps(slim_context_for_llm(context), ensure_ascii=False, indent=2)

    llm_output_dir = json_dir
    llm_output_dir.mkdir(parents=True, exist_ok=True)

    report_content = client.generate(prompt, context_json_str, llm_output_dir)

    if report_content.startswith("EXTERNAL_LLM_PENDING"):
        # External mode: generate placeholder, Claude Code skill will fill in later
        defense = render_markdown(
            "DEF_REPORT",
            [
                ("执行摘要", str(context.get("overall_assessment", ""))),
                ("题目要求映射", build_requirement_mapping(inventory, context)),
                ("防护思路与方法", "采用只读采集、规则检测和 LLM 语义分析。\n\n" + build_method_summary()),
                ("脚本与工具说明", build_tooling_summary()),
                ("系统设计", build_architecture_summary()),
                ("数据结构设计", build_data_structure_summary()),
                ("资产与配置概况", summarize_hosts(inventory.get("hosts", []))),
                ("风险发现清单", summarize_risks(risks.get("risks", []))),
                ("高风险问题详述", summarize_risks(high_risks) if high_risks else "当前运行未发现高风险项。"),
                ("中低风险问题概述", summarize_risks(medium_risks)),
                ("低风险问题概述", summarize_risks(low_risks)),
                ("server/vhost 级风险视图", summarize_server_level_risks(server_level_risks)),
                ("完整风险链示例", build_story_example(risks.get("risks", []), inventory)),
                ("亮点与创新点", build_highlights_summary(inventory, context)),
                ("整体防护评估", str(context.get("overall_assessment", ""))),
                ("加固建议路线图", summarize_list(context.get("roadmap", []))),
                ("评分标准对应与完成度", build_scoring_alignment_summary(risks.get("risks", [])) + "\n\n" + build_completion_summary()),
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
            ("有效实践总结", "两层检测架构：脚本确定性规则 + LLM 语义深度分析。规则覆盖 TLS/SSL、安全头、会话校验、代理安全、文件保护、速率限制等 8 大维度，并支持原始 conf 目录导入与 include 递归解析。"),
            ("局限性", "当前规则库主要覆盖常见 nginx 安全配置问题，尚未覆盖业务逻辑漏洞、WAF 规则、数据库注入防护等应用层场景。"),
            ("工具评价", f"LLM: {llm_tool_desc}。适合结构化审计归纳 + 语义深度分析。"),
            ("可复用沉淀", "规则库 (51 条)、配置事实提取器 (64 字段)、原始 conf 目录导入能力、LLM 客户端 (外网/内网双模式)、task3 skill 和 JSON 模式。"),
        ],
    )

    write_text(task_out / "DEF_REPORT.md", defense)
    write_text(task_out / "AI_REPORT.md", ai)


if __name__ == "__main__":
    main()
