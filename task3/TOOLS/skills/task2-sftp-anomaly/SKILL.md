---
name: task2-sftp-anomaly
description: 从 SFTP 日志中生成用户行为基线，识别异常并输出告警和说明文档。
---

# Purpose

规范题 2 的日志解析、基线生成、异常评分和报告流程。

# When to use

题 2 开始时，或导入新日志样本时。

# Inputs

- 原始 SFTP 日志
- 日志格式说明

# Workflow

1. 归一化事件
2. 生成用户基线
3. 计算异常分
4. 归并告警
5. 生成基线视图
6. 输出报告上下文

# Outputs

- `task2_*` JSON
- `alerts/alert_output.log`
- `MANUAL.md`
- `REPORT.md`
- `AI_REPORT.md`

# Guardrails

- 异常结论只能来自脚本
- LLM 只负责解释和文档
- 必须提供基线查看方式

# Report expectations

- 说明基线、评分逻辑、告警解释和局限性
