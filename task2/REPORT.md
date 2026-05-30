# REPORT

## 需求定义

自动分析 SFTP 日志，以基准日志对比新日志，识别异常行为并输出可审计告警。

## 数据与假设

当前检测数据：
- 文件: task2/TOOLS/datasets/demo_abnormal/proftpd_program.log，格式猜测: sftp_program_proftpd，行数: 9
- 文件: task2/TOOLS/datasets/demo_abnormal/runtime_pipe.log，格式猜测: sftp_runtime_pipe，行数: 11

## 题目要求映射

- 自动分析用户行为基线：已实现。脚本从成功事件中提取用户常见来源 IP/网段、常见访问时段、常见动作/路径、认证方式、客户端版本及协议协商参数，形成 JSON 基线。
- 监控 SFTP 日志并识别异常：已实现。事件级采用多维确定性打分，会话级做聚合分析，并输出结构化告警与告警日志。
- 告警可打印到指定日志文件模拟：已实现。脚本生成 `alert_output.log`，便于评测环境直接检查告警结果。
- 行为基线需自动分析获得并提供查看方式：已实现。`task2_user_baselines.json`、`task2_baseline_views.json`、`MANUAL.md` 中均提供查看入口。
- 行为基线可保存为 JSON：已实现。所有中间态与交付态均为 JSON/NDJSON，适合内网环境直接落地。
- 以某一天/某几天日志对比新日志：已实现。目录支持 `baseline/` 与 `current/` 分离模式，直接对应题意中的“基准日志 vs 新日志”。
- 大文件内网落地：已增强。支持 `TASK2_LARGE_MODE=1`，在 16G 内存机器上通过限制路径画像、序列聚类样本和关联图候选规模换取稳定运行。

## 系统设计

```text
原始日志
  -> ingest_logs.py           识别数据集布局与日志类型
  -> normalize_events.py      归一化为 task2_events.ndjson
  -> build_baseline.py        构建历史用户画像
  -> score_anomalies.py       事件级 / 会话级异常评分
  -> build_session_views.py   聚合会话视图
  -> build_correlation_graph.py   构建 IP 关联图
  -> build_sequence_clusters.py   构建跨用户行为序列模式
  -> build_alerts.py          生成账户级/关联级告警
  -> emit_alert_log.py        输出告警日志
  -> build_report_context.py  汇总报告上下文
  -> render_reports.py        生成 MANUAL / REPORT / AI_REPORT
```

## 数据结构设计

- `task2_events.ndjson`：归一化事件流，字段覆盖用户、来源、动作、路径、结果、协议协商参数等。
- `task2_user_baselines.json`：用户基线画像，包含常见来源、常见动作、时段、认证方式、客户端版本、协议安全特征、失败率和传输统计。
- `task2_session_views.ndjson`：按 `session_id` 聚合后的会话视图，便于复核完整行为链。
- `task2_anomaly_scores.ndjson`：事件级与会话级确定性打分结果，保留每个触发原因。
- `task2_ip_correlation.json`：IP 节点、边、集群及跨用户共享 IP 模式。
- `task2_sequence_clusters.json`：异常会话序列模式与跨用户共享序列模式。
- `task2_alerts.json`：最终告警，默认按账户风险聚合，同时保留关联攻击集群告警。

## 基线建模方法

- 用户 farms_warn_dongyayh: 常见来源 ['124.74.41.42'], 常见动作 ['AUTH'], 常见路径 [], 常见时段 [9], 常见客户端 ['SSH-2.0-JSCH_2.27.3'], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}
- 用户 farms_warn_ruisuiyh: 常见来源 ['220.248.41.29'], 常见动作 ['AUTH'], 常见路径 [], 常见时段 [9], 常见客户端 ['SSH-2.0-JSCH-0.1.72'], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}
- 用户 farms_warn_zsbank: 常见来源 ['101.68.90.115', '203.0.113.55'], 常见动作 ['AUTH'], 常见路径 [], 常见时段 [9, 23], 常见客户端 ['SSH-2.0-JSCH-0.1.54', 'SSH-2.0-OpenSSH_9.9'], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}
- 用户 mms_cmb: 常见来源 ['202.104.136.69'], 常见动作 ['AUTH', 'LOGIN'], 常见路径 [], 常见时段 [9], 常见客户端 ['SSH-2.0-JSCH-0.1.54'], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}
- 用户 unknown: 常见来源 ['203.0.113.55', '220.248.41.29'], 常见动作 ['SESSION_CLOSE', 'SESSION_OPEN'], 常见路径 [], 常见时段 [9, 23], 常见客户端 [], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}

## 会话行为建模

- 会话 3001001: 用户 ['mms_cmb']，推断用户 mms_cmb，来源 ['202.104.136.69']，动作序列 ['AUTH']，时间范围 2026-05-18T09:00:00,101 -> 2026-05-18T09:00:00,101
- 会话 3001002: 用户 ['farms_warn_ruisuiyh']，推断用户 farms_warn_ruisuiyh，来源 ['220.248.41.29']，动作序列 ['AUTH']，时间范围 2026-05-18T09:00:01,205 -> 2026-05-18T09:00:01,205
- 会话 3001003: 用户 ['farms_warn_dongyayh']，推断用户 farms_warn_dongyayh，来源 ['124.74.41.42']，动作序列 ['AUTH']，时间范围 2026-05-18T09:00:02,115 -> 2026-05-18T09:00:02,115
- 会话 3001004: 用户 ['farms_warn_zsbank']，推断用户 farms_warn_zsbank，来源 ['101.68.90.115']，动作序列 ['AUTH']，时间范围 2026-05-18T09:00:03,451 -> 2026-05-18T09:00:03,451
- 会话 3002001: 用户 ['mms_cmb']，推断用户 mms_cmb，来源 ['202.104.136.69']，动作序列 ['AUTH']，时间范围 2026-05-19T09:02:10,301 -> 2026-05-19T09:02:10,301
- 会话 3002002: 用户 ['farms_warn_ruisuiyh']，推断用户 farms_warn_ruisuiyh，来源 ['220.248.41.29']，动作序列 ['AUTH']，时间范围 2026-05-19T09:02:11,309 -> 2026-05-19T09:02:11,309
- 会话 3002003: 用户 ['farms_warn_dongyayh']，推断用户 farms_warn_dongyayh，来源 ['124.74.41.42']，动作序列 ['AUTH']，时间范围 2026-05-19T09:02:12,318 -> 2026-05-19T09:02:12,318
- 会话 3002004: 用户 ['farms_warn_zsbank']，推断用户 farms_warn_zsbank，来源 ['101.68.90.115']，动作序列 ['AUTH']，时间范围 2026-05-19T09:02:13,327 -> 2026-05-19T09:02:13,327
- 会话 3999001: 用户 ['mms_cmb']，推断用户 mms_cmb，来源 ['8.8.8.8']，动作序列 ['AUTH']，时间范围 2026-05-20T23:59:59,999 -> 2026-05-20T23:59:59,999
- 会话 3999002: 用户 ['farms_warn_ruisuiyh']，推断用户 farms_warn_ruisuiyh，来源 ['198.51.100.77']，动作序列 ['AUTH']，时间范围 2026-05-20T23:59:59,998 -> 2026-05-20T23:59:59,998
- 会话 3999003: 用户 ['farms_warn_zsbank']，推断用户 farms_warn_zsbank，来源 ['203.0.113.55']，动作序列 ['AUTH']，时间范围 2026-05-20T23:59:58,777 -> 2026-05-20T23:59:58,777
- 会话 4100001: 用户 ['mms_cmb']，推断用户 mms_cmb，来源 ['202.104.136.69']，动作序列 ['LOGIN']，时间范围 2026-05-18T09:00:00,201 -> 2026-05-18T09:00:00,201
- 会话 4100002: 用户 ['unknown']，推断用户 farms_warn_ruisuiyh，来源 ['220.248.41.29']，动作序列 ['SESSION_OPEN', 'SESSION_CLOSE']，时间范围 2026-05-18T09:00:00,202 -> 2026-05-18T09:00:00,203
- 会话 4200001: 用户 ['mms_cmb']，推断用户 mms_cmb，来源 ['202.104.136.69']，动作序列 ['LOGIN']，时间范围 2026-05-19T09:02:10,201 -> 2026-05-19T09:02:10,201
- 会话 4200002: 用户 ['unknown']，推断用户 farms_warn_ruisuiyh，来源 ['220.248.41.29']，动作序列 ['SESSION_OPEN', 'SESSION_CLOSE']，时间范围 2026-05-19T09:02:10,202 -> 2026-05-19T09:02:10,203
- 会话 4999001: 用户 ['mms_cmb']，推断用户 mms_cmb，来源 ['8.8.8.8']，动作序列 ['LOGIN']，时间范围 2026-05-20T23:59:58,001 -> 2026-05-20T23:59:58,001
- 会话 4999002: 用户 ['farms_warn_ruisuiyh']，推断用户 farms_warn_ruisuiyh，来源 ['198.51.100.77']，动作序列 ['LOGIN']，时间范围 2026-05-20T23:59:58,002 -> 2026-05-20T23:59:58,002
- 会话 4999003: 用户 ['unknown']，推断用户 farms_warn_zsbank，来源 ['203.0.113.55']，动作序列 ['SESSION_OPEN']，时间范围 2026-05-20T23:59:58,003 -> 2026-05-20T23:59:58,003

## 异常识别逻辑

采用四层确定性架构：(1) 历史基线对比：若输入目录包含 baseline/ 与 current/，则只用 baseline/ 建立历史用户画像，对 current/ 逐条评分，满足“以某一天/某几天基准日志对比新日志”的要求。(2) 事件级多维打分：来源偏离、动作偏离、路径偏离、认证偏离、客户端偏离、时段偏离、失败偏离、体量偏离、首次来源IP、特权路径、敏感文件、数据外泄指标、批量下载、进出比偏离、暴力破解、休眠账户激活、异常结果类型；并新增 SSH/SFTP 协议安全维度：弱 KEX、弱 hostkey、弱 cipher、弱 MAC、协议协商偏离、老旧客户端指纹偏离。(3) 会话与关联分析：会话级 5 维度、IP关联图、跨用户IP模式、LCS 行为序列聚类。(4) 风险输出：默认按账户风险聚合，并保留会话级和关联级明细。LLM 仅负责将脚本产出的告警、IP集群和序列模式串联为攻击叙事。

事件级检测包含两层：
- 行为偏离：来源 IP/网段、动作、路径、认证方式、客户端版本、访问时段、失败率、传输体量、首次来源 IP、进出流量比、休眠账户激活等。
- 协议安全：弱 KEX、弱 hostkey、弱 cipher、弱 MAC、协议协商参数偏离历史基线、老旧客户端指纹漂移。
会话级检测包含五层：
- 长会话、多 IP 会话、短时间路径爬取、会话级数据外泄、孤立会话（打开未关闭）。
关联检测包含两层：
- IP 关联图：共享用户、共享会话、时间邻近、子网邻近。
- 行为序列聚类：不同用户执行相同异常动作序列时，提升为关联攻击模式。

## IP关联分析

- 集群 ip-cluster-001: IP ['101.68.90.115', '198.51.100.77', '203.0.113.55', '220.248.41.29'], 共享用户 ['farms_warn_ruisuiyh', 'farms_warn_zsbank'], 事件总数 12
- 集群 ip-cluster-002: IP ['202.104.136.69', '8.8.8.8'], 共享用户 ['mms_cmb'], 事件总数 6

## 行为序列聚类

- 模式 seq-cluster-001: 用户 ['farms_warn_ruisuiyh', 'mms_cmb'], 序列 ['AUTH']
- 异常模式 pattern-001: 序列 ['AUTH'], 影响用户 ['farms_warn_dongyayh', 'farms_warn_ruisuiyh', 'farms_warn_zsbank', 'mms_cmb'], 最高分数 140

## 完整攻击故事示例

1. 基线阶段：集群 `ip-cluster-001` 涉及 IP ['101.68.90.115', '198.51.100.77', '203.0.113.55', '220.248.41.29']，共享用户 ['farms_warn_ruisuiyh', 'farms_warn_zsbank']。这说明这些来源并非随机孤立，而是在基线之外形成了可关联的访问基础设施。
2. 告警阶段：`alert-2` 指向用户 `farms_warn_ruisuiyh` 的会话 `3999002`，触发原因为 ['auth deviation', 'client deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，来源 ['198.51.100.77']。这说明攻击者先在单账户维度表现为新来源、异常时段或异常动作。
3. 告警阶段：`alert-4` 指向用户 `farms_warn_ruisuiyh` 的会话 `4999002`，触发原因为 ['action deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，来源 ['198.51.100.77']。这说明攻击者先在单账户维度表现为新来源、异常时段或异常动作。
4. 关联阶段：跨用户序列模式 `seq-cluster-001` 表明用户 ['farms_warn_ruisuiyh', 'mms_cmb'] 在会话 ['3999001', '3999002', '4999002', '4999001'] 中执行了相同异常序列 ['AUTH']。这把原本独立的单账户异常串成了一条统一攻击路径。
5. 结论阶段：从“基线外单点异常”到“共享 IP 集群”再到“跨用户相同异常序列”，当前样本可被解释为同一批外部来源对多个账户发起了相似访问尝试，系统通过账户告警、IP 关联和序列模式三层输出完成闭环。

## 亮点与创新点

- 1. 原生支持 `baseline/current` 双目录模式，和题目“基准日志对比新日志”完全对齐。
- 2. 不仅解析普通认证日志，还统一纳入 `runtime pipe`、`proftpd` 程序日志、`mod_sftp` 协议协商日志。
- 3. 异常判定是确定性脚本规则，不是黑盒模型，所有告警都能追溯到触发原因和得分。
- 4. 在单用户基线之外，增加了 IP 关联图、跨用户行为序列聚类和账户风险聚合，更接近真实 SOC 分析链路。
- 5. 输出结构化 JSON/NDJSON，可直接在内网环境中沉淀为可复核、可回归、可自动化的产物。
- 6. 针对 16G 内存机器增加大数据模式，优先保证超大日志可跑完，再通过二次精跑补回长尾细节。

## 结果展示方式

本次运行共触发 10 条告警。

- 告警 alert-1: 用户 mms_cmb，会话 3999001，级别 high，原因 ['auth deviation', 'client deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 认证方式偏离历史基线；客户端版本偏离历史基线；失败行为与历史失败率不一致；首次出现的新来源IP地址；来源地址偏离历史基线；访问时段偏离历史基线；异常结果类型
- 告警 alert-2: 用户 farms_warn_ruisuiyh，会话 3999002，级别 high，原因 ['auth deviation', 'client deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 认证方式偏离历史基线；客户端版本偏离历史基线；失败行为与历史失败率不一致；首次出现的新来源IP地址；来源地址偏离历史基线；访问时段偏离历史基线；异常结果类型
- 告警 alert-3: 用户 mms_cmb，会话 4999001，级别 high，原因 ['failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 失败行为与历史失败率不一致；首次出现的新来源IP地址；来源地址偏离历史基线；访问时段偏离历史基线；异常结果类型
- 告警 alert-4: 用户 farms_warn_ruisuiyh，会话 4999002，级别 high，原因 ['action deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 操作类型偏离历史基线；失败行为与历史失败率不一致；首次出现的新来源IP地址；来源地址偏离历史基线；访问时段偏离历史基线；异常结果类型
- 告警 alert-5: 用户 farms_warn_zsbank，推断用户 farms_warn_zsbank，会话 4999003，级别 medium，原因 ['session imbalance']，说明 会话出现打开未关闭或开闭不平衡现象
- 告警 alert-6: 用户 farms_warn_ruisuiyh，会话 account-risk:farms_warn_ruisuiyh，级别 high，原因 ['account risk aggregation', 'action deviation', 'auth deviation', 'client deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 同一账户在同一时间窗口内聚合出多类异常，账户整体风险升高；该账户在当前窗口内关联 2 条异常告警。
- 告警 alert-7: 用户 mms_cmb，会话 account-risk:mms_cmb，级别 high，原因 ['account risk aggregation', 'auth deviation', 'client deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 同一账户在同一时间窗口内聚合出多类异常，账户整体风险升高；该账户在当前窗口内关联 2 条异常告警。
- 告警 alert-8: 用户 multiple，会话 correlated-cluster:ip-cluster-001，级别 high，原因 ['correlated IP cluster']，说明 IP集群 ip-cluster-001 关联 4 个IP，共享用户 ['farms_warn_ruisuiyh', 'farms_warn_zsbank']。2 条已有告警与此集群关联。
- 告警 alert-9: 用户 multiple，会话 correlated-cluster:ip-cluster-002，级别 high，原因 ['correlated IP cluster']，说明 IP集群 ip-cluster-002 关联 2 个IP，共享用户 ['mms_cmb']。2 条已有告警与此集群关联。
- 告警 alert-10: 用户 multiple，会话 correlated-seq:seq-cluster-001，级别 medium，原因 ['correlated action sequence']，说明 跨用户序列模式: 2 个用户执行序列 ['AUTH']。2 个不同用户执行了相同的异常认证序列

## 性能与工程考虑

解析阶段使用 NDJSON 和流式聚合，避免大日志一次性载入内存；transfer/path 明细做 top-N 截断；baseline/current 分离避免重复建模；默认账户风险聚合减少重复告警；关联图和序列聚类在大数据模式下引入截断护栏以适配 16G 机器。

## 评分标准对应与完成度

- 功能验证维度：当前实现已覆盖自动基线提取、异常识别、告警输出、基线查看、JSON 保存、日志文件告警模拟、基准日志对比新日志。
- 可复用性维度：当前实现已具备目录规范、脚本流水线、JSON/NDJSON 中间态、内网大数据模式、账户级风险聚合和结构化报告生成能力。
- 设计合理性维度：异常判定由脚本确定性输出，LLM 只做解释；这能降低幻觉风险，并提高复核性与回归测试能力。
- 性能与工程维度：通过 NDJSON、流式处理、top-N 截断和大数据模式护栏，保证在内网 16G 机器上也能运行大批量日志。

- 核心功能完成度：高。题目主要求已经全部覆盖。
- 工程化完成度：高。已有可运行脚本、结构化输出、基线查看方式、告警日志模拟和内网大数据模式。
- 文档完成度：高。当前 MANUAL / REPORT / AI_REPORT 已能随脚本执行自动刷新并体现设计亮点。
- 剩余优化方向：主要在阈值调优、低频慢速攻击识别、超大规模关联分析精度和针对真实生产样本的验证深度。

## 准确性与可复用性分析

异常判定和关联发现由脚本确定性产出，LLM 负责语义化解释和攻击叙事串联，所有结论可追溯到脚本评分和关联数据。结构化 JSON 产物便于回归测试、规则迭代和内网长期复用。

## 局限与改进方向

阈值仍采用启发式设置，尚未针对更大规模历史样本做调优；会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检；暴力破解检测基于滑动窗口，密集慢速攻击可能不触发；开启 TASK2_LARGE_MODE=1 时，会对路径画像、序列聚类样本和关联图候选规模做截断，以换取 16G 机器上的稳定运行

## 总结

脚本决定异常，LLM 负责解释和报告。
