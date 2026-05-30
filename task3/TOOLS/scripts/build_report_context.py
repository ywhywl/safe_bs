#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from config_loader import load_active_configs
from lib import dump_json, load_json, make_base_record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task3" / "json"
    raw_dir = run_dir / "task3" / "raw"

    inventory = load_json(json_dir / "task3_nginx_inventory.json", {})
    config_facts = load_json(json_dir / "task3_config_facts.json", {})
    risks = load_json(json_dir / "task3_risk_register.json", {})
    rule_hits = load_json(json_dir / "task3_rule_hits.json", {})

    high_risks = [risk for risk in risks.get("risks", []) if risk.get("severity") == "high"]
    medium_risks = [risk for risk in risks.get("risks", []) if risk.get("severity") == "medium"]
    low_risks = [risk for risk in risks.get("risks", []) if risk.get("severity") == "low"]
    server_level_risks = risks.get("server_level_risks", [])

    # Collect raw config texts for LLM context
    raw_configs = load_active_configs(raw_dir)

    record = make_base_record(run_dir.name, "task3", "build_report_context.py")
    record.update(
        {
            "asset_summary": inventory.get("hosts", []),
            "config_facts": config_facts,
            "rule_hits": rule_hits.get("hits", []),
            "risk_summary": risks.get("risks", []),
            "server_level_risks": server_level_risks,
            "overall_assessment": f"只读巡检完成：{len(high_risks)} 高风险、{len(medium_risks)} 中风险、{len(low_risks)} 低风险。配置来源模式：{inventory.get('config_source_mode', 'unknown')}。",
            "high_risks": high_risks,
            "medium_risks": medium_risks,
            "low_risks": low_risks,
            "evidence_index": {
                "rule_hit_count": len(rule_hits.get("hits", [])),
                "risk_count": len(risks.get("risks", [])),
                "rule_hits_with_refs": [hit for hit in rule_hits.get("hits", []) if hit.get("evidence_refs")],
            },
            "config_files": raw_configs,
            "roadmap": [
                "若 nginx -T 失败，先修复配置组织错误（如 include 位置不当、顶层指令落入 http.d）并重新验证",
                "优先处理高风险项：关闭目录浏览、修补路径遍历、统一会话校验覆盖",
                "补齐缺失的安全响应头（HSTS、CSP、X-Content-Type-Options），并复核敏感路径的访问控制",
                "修复 HTTP 未重定向到 HTTPS、cookie 缺少 Secure 标记、proxy_pass HTTPS 未验证证书",
                "继续扩展规则库，覆盖鉴权、缓存、上传链路和反向代理边界",
            ],
            "llm_analysis_required": True,
            "llm_analysis_scope": [
                "对规则命中结果做语义解释和优先级排序",
                "识别规则未覆盖的潜在风险（如 alias+try_files 路径遍历细节、cookie 中 org_code 的业务影响）",
                "为每个风险项补充具体的影响分析和加固建议",
                "生成面向运维人员的可执行修复方案",
            ],
        }
    )
    dump_json(json_dir / "task3_report_context.json", record)


if __name__ == "__main__":
    main()
