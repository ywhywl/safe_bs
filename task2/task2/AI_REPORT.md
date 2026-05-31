# AI_REPORT

## 使用的模型与工具

外网 LLM (Claude Code skill)。
异常评分脚本: score_anomalies.py（行为异常 + 协议安全异常的确定性多维打分）。

## AI 参与环节

告警解释、关联推理和攻击叙事生成。LLM 模式: 外网 LLM (Claude Code skill)。
异常判定、基线比对、协议安全判断和关联发现由脚本确定性产出，LLM 只做语义化解释与叙事串联。

## 输入材料与中间数据

task2_report_context.json、task2_alerts.json、task2_baseline_views.json、task2_session_views.ndjson、task2_sequence_clusters.json

## 关键提示策略

强调 LLM 不自行推断未由脚本提供的关联关系，所有结论必须可追溯到脚本评分和关联数据。LLM 负责把基线比对结果、协议安全异常和序列模式串联为攻击叙事。

## AI 产出与人工修正

告警解释和报告内容可人工复核后定稿。异常判定结果由脚本确定性产出，无需 LLM 修正。

## 有效实践总结

三层架构：历史基线对比 + 脚本确定性打分 + LLM 语义化解释与攻击叙事。JSON 中间态有利于限制幻觉，序列聚类数据提供跨实体推理的依据。

## 局限性

阈值仍采用启发式设置，尚未针对更大规模历史样本做调优；会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检；暴力破解检测基于滑动窗口，密集慢速攻击可能不触发；开启 TASK2_LARGE_MODE=1 时，会对路径画像和序列聚类样本做截断，以换取 16G 机器上的稳定运行；当前 scoped 抽取仍以候选时间窗、session、来源和目标命中为主，真实大数据上的压缩率仍需进一步验证和调优

## 工具评价

LLM: 外网 LLM (Claude Code skill)。适合做告警解释、关联推理和攻击叙事，不适合作为核心判定或关联发现。

## 可复用沉淀

baseline/current 对比目录模式、第三类 mod_sftp 协议日志解析、基线/告警/关联 JSON 结构、行为+协议安全评分维度、序列聚类算法、账户风险聚合策略、LLM 客户端（外网/内网双模式）、task2 skill。
