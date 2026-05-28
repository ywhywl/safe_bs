# AI_REPORT

## 使用的模型与工具

外网 LLM (Claude Code skill)。
规则库 51 条，命中 29 条。
脚本：parse_config_facts.py + apply_rules.py + build_risk_register.py

## AI 参与环节

规则自动检测（51 条）+ LLM 语义分析（联动风险、优先级排序、可执行修复方案）。
LLM 模式: 外网 LLM (Claude Code skill)

## 输入材料与中间数据

task3_config_facts.json (64 事实字段)、task3_rule_hits.json、task3_risk_register.json、task3_report_context.json

## 关键提示策略

要求每个风险可追溯到规则命中或配置事实，LLM 补充联动分析、优先级排序和具体 nginx 配置修复示例。

## AI 产出与人工修正

规则自动检测 29 条命中，LLM 语义分析补充联动风险和修复方案。高风险问题建议人工复核。

## 有效实践总结

两层检测架构：脚本确定性规则 + LLM 语义深度分析。规则覆盖 TLS/SSL、安全头、会话校验、代理安全、文件保护、速率限制等 8 大维度。

## 局限性

当前规则库主要覆盖常见 nginx 安全配置问题，尚未覆盖业务逻辑漏洞、WAF 规则、数据库注入防护等应用层场景。

## 工具评价

LLM: Claude Code 会话。适合结构化审计归纳 + 语义深度分析。

## 可复用沉淀

规则库 (51 条)、配置事实提取器 (64 字段)、LLM 客户端 (外网/内网双模式)、task3 skill 和 JSON 模式。
