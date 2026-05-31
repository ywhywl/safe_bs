# MANUAL

## 工具目标

自动分析 SFTP 日志，提取用户行为基线，对新日志进行异常识别、关联分析和账户风险聚合，输出可审计告警。

## 输入说明

当前检测数据：
- 文件: task2/TOOLS/datasets/demo_abnormal/proftpd_program.log，格式猜测: sftp_program_proftpd，行数: 9
- 文件: task2/TOOLS/datasets/demo_abnormal/runtime_pipe.log，格式猜测: sftp_runtime_pipe，行数: 11

## 输出说明

输出 JSON / NDJSON 中间态、结构化告警日志、用户基线视图、关联分析结果以及 MANUAL / REPORT / AI_REPORT。默认按账户风险聚合输出，同时保留会话级和关联级证据。

## 核心流程

日志解析 -> 事件归一化 -> 历史基线生成 -> 新日志多维异常评分 -> 会话/关联分析 -> 账户风险聚合 -> 解释与文档生成。

## 题目要求映射

- 自动分析用户行为基线：已实现。脚本从成功事件中提取用户常见来源 IP/网段、常见访问时段、常见动作/路径、认证方式、客户端版本及协议协商参数，形成 JSON 基线。
- 监控 SFTP 日志并识别异常：已实现。事件级采用多维确定性打分，会话级做聚合分析，并输出结构化告警与告警日志。
- 告警可打印到指定日志文件模拟：已实现。脚本生成 `alert_output.log`，便于评测环境直接检查告警结果。
- 行为基线需自动分析获得并提供查看方式：已实现。`task2_user_baselines.json`、`task2_baseline_views.json`、`MANUAL.md` 中均提供查看入口。
- 行为基线可保存为 JSON：已实现。所有中间态与交付态均为 JSON/NDJSON，适合内网环境直接落地。
- 以某一天/某几天日志对比新日志：已实现。目录支持 `baseline/` 与 `current/` 分离模式，直接对应题意中的《基准日志 vs 新日志》。
- 大文件内网落地：已增强。支持 `TASK2_LARGE_MODE=1`，在 16G 内存机器上通过限制路径画像和序列聚类样本规模换取稳定运行。

## 结果查看方式

本次运行共 5 个用户基线、14 个会话、13 条告警。

查看方式：
- 用户基线：`task2_baseline_views.json`（每个用户的常见来源、动作、时段、客户端、协议安全参数）
- 完整基线画像：`task2_user_baselines.json`
- 会话视图：`task2_session_views.ndjson`（按 session_id 聚合，含动作序列、路径、时间范围）
- 告警列表：`task2_alerts.json`（按账户风险聚合，含触发原因、打分明细、推荐处置）
- 告警日志文件：`task2/TOOLS/alerts/alert_output.log`
- 关联序列模式：`task2_sequence_clusters.json`（跨用户行为序列聚类）
- 异常评分明细：`task2_anomaly_scores.ndjson`

详细分析结果见 REPORT.md。

## 参数与阈值说明

支持 baseline/current 对比模式。事件级加入协议安全维度：弱 KEX、弱 hostkey、弱 cipher、弱 MAC、协议协商偏离、老旧客户端指纹偏离；会话级保留 5 维度；默认按账户风险聚合输出。可信网段、可信用户、可信客户端、算法白名单/黑名单可在 noise_policy.json 调整。

## 大数据模式说明

- 当前运行启用 `TASK2_LARGE_MODE=1`。
- 脚本会限制每用户路径画像规模、限制序列聚类参与 session 数，避免 16G 机器在超大日志上内存失控。
- 代价是部分长尾路径和低频序列模式可能被截断，因此建议先全量粗筛，再对高风险账户做小范围精跑。

## 适用范围与局限

阈值仍采用启发式设置，尚未针对更大规模历史样本做调优；会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检；暴力破解检测基于滑动窗口，密集慢速攻击可能不触发；开启 TASK2_LARGE_MODE=1 时，会对路径画像和序列聚类样本做截断，以换取 16G 机器上的稳定运行

## 告警文件说明

查看 task2/TOOLS/alerts/alert_output.log 或 runs 下对应输出。
