---
name: task3-nginx-audit
description: 对 Nginx 做只读安全巡检，输出风险清单和防护报告。
---

# Purpose

规范题 3 的只读采集、规则检测和防护报告流程。

# When to use

题 3 开始时，或需要重新巡检时。

# Inputs

- 只读采集结果
- Nginx 配置
- TLS 或日志摘要

# Workflow

1. 生成资产清单
2. 抽取配置事实
3. 运行规则检测
4. 生成风险登记
5. 输出报告上下文

# Outputs

- `task3_*` JSON
- `DEF_REPORT.md`
- `AI_REPORT.md`

# Guardrails

- 只能基于只读证据做判断
- 每个问题必须可追溯到证据位置
- 规则库需要显式保存

# Report expectations

- 包含风险等级、影响、证据和加固建议
