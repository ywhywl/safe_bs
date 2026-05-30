#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, make_base_record


def collect_global_evidence(fields: list[str], facts: dict) -> list[dict]:
    catalog = facts.get("evidence_catalog", {})
    evidence = []
    seen = set()
    for field in fields:
        refs = []
        for file_catalog in catalog.values():
            for ref in file_catalog.get(field, []):
                key = (ref.get("file"), ref.get("line_no"), ref.get("line_text"))
                if key in seen:
                    continue
                seen.add(key)
                refs.append(ref)
        evidence.append(
            {
                "field": field,
                "observed_value": facts.get(field),
                "evidence_refs": refs[:10],
            }
        )
    return evidence


def make_composite_risk(title: str, severity: str, evidence: list[dict], remediation: str, impact: str, source: str = "composite") -> dict:
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "impact": impact,
        "remediation": remediation,
        "status": "open",
        "source": source,
    }


def build_global_composite_risks(facts: dict) -> list[dict]:
    risks = []
    if not facts.get("http_redirects_to_https", True) and not facts.get("cookie_has_secure_flag", True):
        risks.append(
            make_composite_risk(
                "HTTP 明文入口与 Cookie 缺少 Secure 标记形成会话劫持链",
                "high",
                collect_global_evidence(["http_redirects_to_https", "cookie_has_secure_flag"], facts),
                "先为 HTTP server 增加 301 跳转到 HTTPS，再为 cookie 策略补充 Secure 标记，避免明文通道暴露会话令牌。",
                "用户请求可先通过明文 HTTP 到达，再携带未受 Secure 约束的 Cookie，形成中间人窃取或会话降级风险。",
            )
        )
    if facts.get("client_max_body_size_unlimited", False) and not facts.get("upload_dir_execution_blocked", True):
        risks.append(
            make_composite_risk(
                "上传面未收敛且未禁止脚本执行，形成上传利用链",
                "high",
                collect_global_evidence(["client_max_body_size_unlimited", "upload_dir_execution_blocked"], facts),
                "同时收紧 client_max_body_size，并在上传目录显式禁止 php/jsp/py/sh/cgi 等脚本执行。",
                "攻击者可借助超大上传能力投递恶意文件，并在上传目录缺少执行限制时进一步尝试代码执行。",
            )
        )
    if facts.get("status_pages_without_acl", False) and facts.get("has_access_log_off", False):
        risks.append(
            make_composite_risk(
                "状态页暴露且访问日志关闭，形成可探测但难追溯的监控盲区",
                "high",
                collect_global_evidence(["status_pages_without_acl", "has_access_log_off"], facts),
                "为状态页增加 allow/deny ACL，并恢复对应 location 的 access_log 记录。",
                "攻击者可访问状态页获取运行信息，而日志关闭会降低事后审计与追踪能力。",
            )
        )
    if facts.get("proxy_pass_https_without_verify", False) and not facts.get("proxy_hide_headers_configured", True):
        risks.append(
            make_composite_risk(
                "HTTPS 后端证书未校验且后端响应头未隐藏，形成后端信任链缺口",
                "high",
                collect_global_evidence(["proxy_pass_https_without_verify", "proxy_hide_headers_configured"], facts),
                "启用 proxy_ssl_verify、trusted_certificate 等配置校验后端证书，并通过 proxy_hide_header 隐藏后端技术栈信息。",
                "上游 HTTPS 连接可能遭受中间人或错误证书接入，同时后端响应头还会扩大信息暴露面。",
            )
        )
    if not facts.get("ssl_ciphers_defined", True) and not facts.get("ssl_prefer_server_ciphers_on", True) and not facts.get("ocsp_stapling_enabled", True):
        risks.append(
            make_composite_risk(
                "TLS 加固缺失形成传输面弱防护组合",
                "medium",
                collect_global_evidence(["ssl_ciphers_defined", "ssl_prefer_server_ciphers_on", "ocsp_stapling_enabled"], facts),
                "显式配置现代 ssl_ciphers，开启 ssl_prefer_server_ciphers on，并补充 ssl_stapling/ssl_stapling_verify。",
                "服务端未约束密码套件且未启用 stapling，会同时削弱密码套件控制、握手安全性和客户端证书状态校验体验。",
            )
        )
    return risks


def build_server_composite_risks(facts: dict) -> list[dict]:
    risks = []
    for server in facts.get("server_level_facts", []):
        target = server.get("server_names") or server.get("listen") or [server.get("server_key")]
        base_evidence = [
            {
                "field": "server_context",
                "observed_value": target,
                "evidence_refs": [
                    {
                        "file": server.get("file"),
                        "line_no": server.get("start_line_no"),
                        "line_text": "server {",
                    }
                ],
                "context_snippet": server.get("context_snippet", ""),
            }
        ]
        if server.get("is_http_server") and not server.get("http_redirects_to_https", True) and server.get("autoindex", False):
            risks.append(
                {
                    "server_key": server.get("server_key"),
                    "server_names": server.get("server_names", []),
                    "listen": server.get("listen", []),
                    **make_composite_risk(
                        "server 级明文入口与目录列表联动暴露",
                        "high",
                        base_evidence + [
                            {"field": "http_redirects_to_https", "observed_value": server.get("http_redirects_to_https"), "evidence_refs": []},
                            {"field": "autoindex", "observed_value": server.get("autoindex"), "evidence_refs": []},
                        ],
                        "将该 HTTP server 块改为仅做 HTTPS 跳转，并关闭 autoindex。",
                        "明文访问入口与目录列表同时存在时，攻击者既可枚举目录结构，也可在未加密链路上观察访问行为。",
                        source="server_composite",
                    ),
                }
            )
        if server.get("has_ssl_block") and "Strict-Transport-Security" not in server.get("security_headers", []) and any(h not in server.get("security_headers", []) for h in ["X-Content-Type-Options", "Content-Security-Policy"]):
            risks.append(
                {
                    "server_key": server.get("server_key"),
                    "server_names": server.get("server_names", []),
                    "listen": server.get("listen", []),
                    **make_composite_risk(
                        "server 级 HTTPS 传输保护与内容防护头同时缺失",
                        "high",
                        base_evidence + [
                            {"field": "security_headers", "observed_value": server.get("security_headers", []), "evidence_refs": []},
                        ],
                        "在对应 HTTPS server 中同时补充 HSTS、X-Content-Type-Options 和 CSP。",
                        "该 HTTPS 入口虽然启用了 TLS，但缺少传输层强制与内容层约束，容易在降级、类型混淆和前端注入防护上同时失守。",
                        source="server_composite",
                    ),
                }
            )
        if not server.get("hidden_files_blocked", True) and not server.get("http_methods_limited", True) and not server.get("limit_conn_configured", True):
            risks.append(
                {
                    "server_key": server.get("server_key"),
                    "server_names": server.get("server_names", []),
                    "listen": server.get("listen", []),
                    **make_composite_risk(
                        "server 级入口暴露面过大（隐藏文件、方法、连接控制同时缺失）",
                        "high",
                        base_evidence + [
                            {"field": "hidden_files_blocked", "observed_value": server.get("hidden_files_blocked"), "evidence_refs": []},
                            {"field": "http_methods_limited", "observed_value": server.get("http_methods_limited"), "evidence_refs": []},
                            {"field": "limit_conn_configured", "observed_value": server.get("limit_conn_configured"), "evidence_refs": []},
                        ],
                        "在对应 server 中同时补上隐藏文件访问控制、limit_except 方法限制和 limit_conn 连接限制。",
                        "缺少这三类基础控制时，攻击者更容易探测敏感文件、尝试危险方法并发起高并发打点或压测。",
                        source="server_composite",
                    ),
                }
            )
    return risks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task3" / "json"
    facts = load_json(json_dir / "task3_config_facts.json", {})
    rule_hits_record = load_json(json_dir / "task3_rule_hits.json", {})
    hits = rule_hits_record.get("hits", [])
    server_level_findings = rule_hits_record.get("server_level_findings", [])
    risks = []
    for hit in hits:
        risks.append(
            {
                "title": hit.get("title"),
                "severity": hit.get("severity"),
                "evidence": [
                    {
                        "field": hit.get("field"),
                        "observed_value": hit.get("observed_value"),
                        "evidence_refs": hit.get("evidence_refs", []),
                    }
                ],
                "impact": "Potential hardening gap identified by rule.",
                "remediation": hit.get("remediation"),
                "status": "open",
                "source": "rule",
            }
        )
    server_risks = []
    for finding in server_level_findings:
        server_risks.append(
            {
                "server_key": finding.get("server_key"),
                "server_names": finding.get("server_names", []),
                "listen": finding.get("listen", []),
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "evidence": [
                    {
                        "field": finding.get("field"),
                        "observed_value": finding.get("observed_value"),
                        "evidence_refs": finding.get("evidence_refs", []),
                        "context_snippet": finding.get("context_snippet", ""),
                    }
                ],
                "impact": "Per-server hardening gap identified by server-level analysis.",
                "remediation": finding.get("remediation"),
                "status": "open",
                "source": "server_rule",
            }
        )
    risks.extend(build_global_composite_risks(facts))
    server_risks.extend(build_server_composite_risks(facts))
    for idx, risk in enumerate(risks, start=1):
        risk["risk_id"] = f"risk-{idx}"
    for idx, risk in enumerate(server_risks, start=1):
        risk["server_risk_id"] = f"server-risk-{idx}"
    record = make_base_record(run_dir.name, "task3", "build_risk_register.py")
    record["risks"] = risks
    record["server_level_risks"] = server_risks
    dump_json(json_dir / "task3_risk_register.json", record)


if __name__ == "__main__":
    main()
