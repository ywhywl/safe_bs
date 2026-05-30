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
- 以某一天/某几天日志对比新日志：已实现。目录支持 `baseline/` 与 `current/` 分离模式，直接对应题意中的“基准日志 vs 新日志”。
- 大文件内网落地：已增强。支持 `TASK2_LARGE_MODE=1`，在 16G 内存机器上通过限制路径画像、序列聚类样本规模换取稳定运行。

## 用户基线查看方式

- 用户 farms_warn_dongyayh: 常见来源 ['124.74.41.42'], 常见动作 ['AUTH'], 常见路径 [], 常见时段 [9], 常见客户端 ['SSH-2.0-JSCH_2.27.3'], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}
- 用户 farms_warn_ruisuiyh: 常见来源 ['220.248.41.29'], 常见动作 ['AUTH'], 常见路径 [], 常见时段 [9], 常见客户端 ['SSH-2.0-JSCH-0.1.72'], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}
- 用户 farms_warn_zsbank: 常见来源 ['101.68.90.115', '203.0.113.55'], 常见动作 ['AUTH'], 常见路径 [], 常见时段 [9, 23], 常见客户端 ['SSH-2.0-JSCH-0.1.54', 'SSH-2.0-OpenSSH_9.9'], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}
- 用户 mms_cmb: 常见来源 ['202.104.136.69'], 常见动作 ['AUTH', 'LOGIN'], 常见路径 [], 常见时段 [9], 常见客户端 ['SSH-2.0-JSCH-0.1.54'], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}
- 用户 unknown: 常见来源 ['203.0.113.55', '220.248.41.29'], 常见动作 ['SESSION_CLOSE', 'SESSION_OPEN'], 常见路径 [], 常见时段 [9, 23], 常见客户端 [], 常见协议安全参数 {'cipher_c2s': [], 'cipher_s2c': [], 'hostkey': [], 'kex': [], 'mac_c2s': [], 'mac_s2c': []}

## 会话查看方式

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

## 告警解释方式

- 告警 alert-1: 用户 mms_cmb，会话 3999001，级别 high，原因 ['auth deviation', 'client deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 认证方式偏离历史基线；客户端版本偏离历史基线；失败行为与历史失败率不一致；首次出现的新来源IP地址；来源地址偏离历史基线；访问时段偏离历史基线；异常结果类型
- 告警 alert-2: 用户 farms_warn_ruisuiyh，会话 3999002，级别 high，原因 ['auth deviation', 'client deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 认证方式偏离历史基线；客户端版本偏离历史基线；失败行为与历史失败率不一致；首次出现的新来源IP地址；来源地址偏离历史基线；访问时段偏离历史基线；异常结果类型
- 告警 alert-3: 用户 mms_cmb，会话 4999001，级别 high，原因 ['failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 失败行为与历史失败率不一致；首次出现的新来源IP地址；来源地址偏离历史基线；访问时段偏离历史基线；异常结果类型
- 告警 alert-4: 用户 farms_warn_ruisuiyh，会话 4999002，级别 high，原因 ['action deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 操作类型偏离历史基线；失败行为与历史失败率不一致；首次出现的新来源IP地址；来源地址偏离历史基线；访问时段偏离历史基线；异常结果类型
- 告警 alert-5: 用户 farms_warn_zsbank，推断用户 farms_warn_zsbank，会话 4999003，级别 medium，原因 ['session imbalance']，说明 会话出现打开未关闭或开闭不平衡现象
- 告警 alert-6: 用户 farms_warn_ruisuiyh，会话 account-risk:farms_warn_ruisuiyh，级别 high，原因 ['account risk aggregation', 'action deviation', 'auth deviation', 'client deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 同一账户在同一时间窗口内聚合出多类异常，账户整体风险升高；该账户在当前窗口内关联 2 条异常告警。
- 告警 alert-7: 用户 mms_cmb，会话 account-risk:mms_cmb，级别 high，原因 ['account risk aggregation', 'auth deviation', 'client deviation', 'failure deviation', 'first-time source IP', 'source deviation', 'time deviation', 'unusual result type']，说明 同一账户在同一时间窗口内聚合出多类异常，账户整体风险升高；该账户在当前窗口内关联 2 条异常告警。
- 告警 alert-10: 用户 multiple，会话 correlated-seq:seq-cluster-001，级别 medium，原因 ['correlated action sequence']，说明 跨用户序列模式: 2 个用户执行序列 ['AUTH']。2 个不同用户执行了相同的异常认证序列

## 关联分析

序列模式: - 模式 seq-cluster-001: 用户 ['farms_warn_ruisuiyh', 'mms_cmb'], 序列 ['AUTH']
- 异常模式 pattern-001: 序列 ['AUTH'], 影响用户 ['farms_warn_dongyayh', 'farms_warn_ruisuiyh', 'farms_warn_zsbank', 'mms_cmb'], 最高分数 140

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
