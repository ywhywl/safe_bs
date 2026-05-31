---
name: task2-sftp-anomaly
description: 从 SFTP 日志中生成用户行为基线，识别异常，发现跨实体关联，输出告警和攻击叙事报告。
---

# Purpose

规范题 2 的日志解析、基线生成、异常评分、关联发现和报告流程。

# When to use

题 2 开始时，或导入新日志样本时。

# Inputs

- 原始 SFTP 日志
- 日志格式说明

# Workflow

1. 归一化事件
2. 生成用户基线
3. 计算异常分
4. 构建会话视图
5. 构建行为序列聚类（跨用户模式发现）
6. 归并告警（含关联攻击集群告警）
7. 生成基线视图
9. 输出报告上下文
10. LLM 生成攻击叙事和报告

# Outputs

- `task2_*` JSON（含 task2_sequence_clusters.json）
- `alerts/alert_output.log`
- `MANUAL.md`
- `REPORT.md`（含行为序列聚类章节）
- `AI_REPORT.md`

# Guardrails

- 异常判定和关联发现只能来自脚本确定性产出
- LLM 负责语义化解释和攻击叙事串联，不自行推断未由脚本提供的关联关系
- 所有结论必须可追溯到脚本输出字段
- 必须提供基线和关联分析查看方式

# Report expectations

- 说明基线、评分逻辑、关联发现方法、告警解释、攻击叙事和局限性