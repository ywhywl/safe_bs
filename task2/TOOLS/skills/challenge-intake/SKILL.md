---
name: challenge-intake
description: 读取题面并生成交付物映射、评分点对齐和执行检查清单。
---

# Purpose

解析题目要求，统一后续执行边界。

# When to use

新题开始时，或题面发生变化时。

# Inputs

- 题面文本
- 图片或扫描件
- 用户补充约束

# Workflow

1. 识别每题交付物
2. 识别评分标准
3. 识别允许与禁止动作
4. 输出执行清单

# Outputs

- 题目检查清单
- 交付物映射

# Guardrails

- 不擅自扩展题目范围
- 明确区分允许攻击和只读巡检

# Report expectations

- 每题报告必须显式对齐题面
