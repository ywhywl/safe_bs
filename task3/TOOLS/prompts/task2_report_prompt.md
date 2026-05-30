根据 `task2_report_context.json` 生成 `MANUAL.md` 和 `REPORT.md`。要求异常判定和关联发现以脚本结果为准，LLM 负责语义化解释和攻击叙事串联。

关联分析要求：
1. REPORT.md 中必须包含"关联分析"章节，基于 `ip_correlation_summary` 和 `sequence_cluster_summary` 呈现发现。
2. 对于每个 `ip_correlation_summary.anomalous_clusters`，描述IP集群如何连接了原本独立的告警。
3. 对于每个 `sequence_cluster_summary.cross_user_patterns`，描述不同用户执行相同异常序列的攻击叙事。
4. 如果 `correlation_insights` 中有条目，将其整合为"攻击叙事"子章节，说明多个告警如何构成一个连贯的攻击故事。
5. 所有结论必须可追溯到 `task2_report_context.json` 中的脚本输出字段，LLM 不得自行推断未由脚本提供的关联关系。
6. 使用中文撰写，结构清晰，引用具体的 alert_id、session_id、IP 地址和动作序列。