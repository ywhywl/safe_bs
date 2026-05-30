#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, make_base_record


SERVER_LEVEL_RULES = [
    {
        "rule_id": "server_tls_v13_missing",
        "title": "server 级未启用 TLSv1.3",
        "severity": "medium",
        "field": "tls_protocols",
        "predicate": lambda server: server.get("has_ssl_block") and "TLSv1.3" not in server.get("tls_protocols", []),
        "remediation": "在对应 HTTPS server 块中显式配置 ssl_protocols TLSv1.2 TLSv1.3;",
    },
    {
        "rule_id": "server_missing_hsts",
        "title": "server 级缺少 Strict-Transport-Security 头",
        "severity": "high",
        "field": "security_headers",
        "predicate": lambda server: server.get("has_ssl_block") and "Strict-Transport-Security" not in server.get("security_headers", []),
        "remediation": "在对应 HTTPS server 块中添加 add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;",
    },
    {
        "rule_id": "server_missing_security_headers",
        "title": "server 级缺少关键安全响应头",
        "severity": "medium",
        "field": "security_headers",
        "predicate": lambda server: any(h not in server.get("security_headers", []) for h in ["X-Content-Type-Options", "Content-Security-Policy"]),
        "remediation": "在对应 server 块中补充 add_header X-Content-Type-Options nosniff always; 和合适的 Content-Security-Policy;",
    },
    {
        "rule_id": "server_http_no_redirect_to_https",
        "title": "server 级 HTTP 未重定向到 HTTPS",
        "severity": "high",
        "field": "http_redirects_to_https",
        "predicate": lambda server: server.get("is_http_server") and not server.get("http_redirects_to_https", True),
        "remediation": "将该 HTTP server 块改为 return 301 https://$host$request_uri;",
    },
    {
        "rule_id": "server_autoindex_enabled",
        "title": "server 级目录列表功能已开启",
        "severity": "high",
        "field": "autoindex",
        "predicate": lambda server: server.get("autoindex", False),
        "remediation": "在对应 server/location 中关闭 autoindex，除非该目录列表是明确业务需求。",
    },
    {
        "rule_id": "server_hidden_files_not_blocked",
        "title": "server 级未阻止隐藏文件访问",
        "severity": "high",
        "field": "hidden_files_blocked",
        "predicate": lambda server: not server.get("hidden_files_blocked", False),
        "remediation": "在对应 server 块中添加 location ~ /\\\\.{ deny all; }",
    },
    {
        "rule_id": "server_limit_conn_missing",
        "title": "server 级未配置连接数限制",
        "severity": "medium",
        "field": "limit_conn_configured",
        "predicate": lambda server: not server.get("limit_conn_configured", False),
        "remediation": "在对应 server/location 中补充 limit_conn，并确保上层已定义 limit_conn_zone。",
    },
]


def collect_evidence_refs(field: str, facts: dict) -> list[dict]:
    catalog = facts.get("evidence_catalog", {})
    refs = []
    for file_name, file_catalog in catalog.items():
        for ref in file_catalog.get(field, []):
            if ref not in refs:
                refs.append(ref)
    if refs:
        return refs[:20]
    for file_name, file_catalog in catalog.items():
        for ref in file_catalog.get("scope_refs", []):
            if ref not in refs:
                refs.append(ref)
            if len(refs) >= 5:
                return refs
    return refs[:20]


def hit_rule(rule: dict, facts: dict) -> bool:
    field_value = facts.get(rule.get("field"))
    match_type = rule.get("match_type")

    if match_type == "equals":
        return field_value == rule.get("value")

    if match_type == "contains_any":
        return any(value in (field_value or []) for value in rule.get("values", []))

    if match_type == "missing_any":
        current = set(field_value or [])
        return any(value not in current for value in rule.get("values", []))

    if match_type == "missing_all":
        current = set(field_value or [])
        return all(value not in current for value in rule.get("values", []))

    if match_type == "contains_substring_any":
        values = field_value or []
        return any(any(pattern in value for pattern in rule.get("values", [])) for value in values)

    if match_type == "greater_than":
        threshold = rule.get("value", 0)
        try:
            return float(field_value or 0) > float(threshold)
        except (TypeError, ValueError):
            return False

    if match_type == "less_than":
        threshold = rule.get("value", 0)
        try:
            return float(field_value or 0) < float(threshold)
        except (TypeError, ValueError):
            return False

    return False


def build_server_level_findings(facts: dict) -> list[dict]:
    findings = []
    for server in facts.get("server_level_facts", []):
        for rule in SERVER_LEVEL_RULES:
            if not rule["predicate"](server):
                continue
            findings.append(
                {
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "field": rule["field"],
                    "scope": "server",
                    "server_key": server.get("server_key"),
                    "server_names": server.get("server_names", []),
                    "listen": server.get("listen", []),
                    "observed_value": server.get(rule["field"]),
                    "evidence_refs": [
                        {
                            "file": server.get("file"),
                            "line_no": server.get("start_line_no"),
                            "line_text": "server {",
                        }
                    ],
                    "context_snippet": server.get("context_snippet", ""),
                    "remediation": rule["remediation"],
                }
            )
    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--rules", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task3" / "json"
    facts = load_json(json_dir / "task3_config_facts.json", {})
    rules = load_json(Path(args.rules), [])
    hits = []
    for rule in rules:
        if hit_rule(rule, facts):
            hits.append(
                {
                    "rule_id": rule.get("rule_id"),
                    "title": rule.get("title"),
                    "severity": rule.get("severity"),
                    "field": rule.get("field"),
                    "observed_value": facts.get(rule.get("field")),
                    "evidence_refs": collect_evidence_refs(rule.get("field"), facts),
                    "remediation": rule.get("remediation"),
                }
            )
    record = make_base_record(run_dir.name, "task3", "apply_rules.py")
    record["hits"] = hits
    record["server_level_findings"] = build_server_level_findings(facts)
    dump_json(json_dir / "task3_rule_hits.json", record)


if __name__ == "__main__":
    main()
