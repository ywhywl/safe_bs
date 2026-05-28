# AI_REPORT

## 使用的模型与工具

外网 LLM (Claude Code skill)。
异常评分脚本: score_anomalies.py（确定性多维打分，阈值 >= 60）。

## AI 参与环节

告警解释和文档生成。LLM 模式: 外网 LLM (Claude Code skill)。
异常结论只能来自脚本打分，LLM 不参与最终判定。

## 输入材料与中间数据

task2_report_context.json、task2_alerts.json、task2_baseline_views.json、task2_session_views.ndjson

## 关键提示策略

强调 LLM 不直接改动异常判定结果，只负责解释和文档。异常结论必须可追溯到脚本评分。

## AI 产出与人工修正

告警解释和报告内容可人工复核后定稿。异常判定结果由脚本确定性产出，无需 LLM 修正。

## 有效实践总结

两层架构：脚本确定性打分 + LLM 解释文档。JSON 中间态有利于限制幻觉。

## 局限性

阈值仍采用启发式设置，尚未针对更大规模历史样本做调优；会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检；暴力破解检测基于滑动窗口，密集慢速攻击可能不触发

## 工具评价

LLM: 外网 LLM (Claude Code skill)。适合做解释与文档，不适合作为核心判定。

## 可复用沉淀

基线/告警 JSON 结构、评分维度和阈值、LLM 客户端（外网/内网双模式）、task2 skill。
