---
name: task1-vuln-assessment
description: 对授权目标做服务研判、漏洞候选归纳、验证留痕和攻击报告生成。
---

# Purpose

规范题 1 的识别、验证、固证和报告流程。

# When to use

题 1 开始时，或需要重新验证时。

# Inputs

- 目标信息
- 侦察输出
- 协议响应
- 漏洞情报摘要

# Workflow

1. 确认边界
2. 抽取服务事实
3. 生成漏洞候选
4. 输出验证计划
5. 记录执行时间线
6. 生成报告上下文

# Outputs

- `task1_*` JSON
- `ATT_REPORT.md`
- `AI_REPORT.md`

# Guardrails

- 先识别服务身份，再做漏洞匹配
- 先分离事实、假设、验证结果，再写报告
- 外网 LLM 只读脱敏上下文

# Report expectations

- 包含边界、时间线、证据、影响和修复建议
