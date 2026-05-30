---
name: ai-report-writer
description: 统一记录模型使用过程、输入材料、人工修订和局限性，并生成 AI_REPORT。
---

# Purpose

规范三题 AI 使用报告格式。

# When to use

每题主报告形成后。

# Inputs

- `ai_usage_trace.json`
- `tool_manifest.json`
- 各题 `report_context.json`

# Workflow

1. 汇总模型与用途
2. 汇总输入材料
3. 记录人工修订点
4. 输出统一格式 AI 报告

# Outputs

- `AI_REPORT.md`

# Guardrails

- 不夸大 LLM 作用
- 必须写清哪些步骤由脚本确定性产出、哪些由 LLM 负责解释和串联
- 所有 LLM 产出结论必须可追溯到脚本输出字段

# Report expectations

- 包含模型、输入、修订、有效实践和局限性
- task2 需额外说明关联发现的脚本来源和 LLM 攻击叙事的角色