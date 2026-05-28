# REPORT

## 需求定义

自动分析 SFTP 日志并识别异常行为。

## 数据与假设

历史基线数据：
- 文件: /private/tmp/task2_hist_case/baseline/proftpd_program_sample.log，格式猜测: sftp_program_proftpd，行数: 5
- 文件: /private/tmp/task2_hist_case/baseline/sample_kv.log，格式猜测: key_value，行数: 4
当前检测数据：
- 文件: /private/tmp/task2_hist_case/current/runtime_pipe_sample.log，格式猜测: sftp_runtime_pipe，行数: 4
- 文件: /private/tmp/task2_hist_case/current/sample.log，格式猜测: plain_text，行数: 4

## 系统设计

日志解析 -> 基线生成 -> 异常评分 -> 告警输出 -> LLM 解释。

## 数据结构设计

使用 events、baselines、alerts 三层 JSON。

## 基线建模方法

- 用户 finance: 常见来源 ['10.10.2.20'], 常见动作 ['PUT'], 常见路径 ['/finance/payroll.csv'], 常见时段 [9]
- 用户 ops: 常见来源 ['10.10.1.15'], 常见动作 ['GET', 'LIST'], 常见路径 ['/dropbox', '/dropbox/config.yml'], 常见时段 [8, 9]
- 用户 tms_cmb: 常见来源 ['202.104.136.69'], 常见动作 ['LOGIN'], 常见路径 [], 常见时段 [0]
- 用户 unknown: 常见来源 ['202.104.136.69', '222.76.46.33'], 常见动作 ['SESSION_CLOSE', 'SESSION_OPEN'], 常见路径 [], 常见时段 [0]

## 会话行为建模

- 会话 2689379: 用户 ['farms_warn_ruisuiyh']，来源 ['220.248.41.29']，动作序列 ['AUTH']，时间范围 2026-05-20T00:00:00,018 -> 2026-05-20T00:00:00,018
- 会话 2689385: 用户 ['mms_cmb']，来源 ['202.104.136.69']，动作序列 ['AUTH']，时间范围 2026-05-20T00:00:00,223 -> 2026-05-20T00:00:00,223
- 会话 2689397: 用户 ['farms_warn_dongyayh']，来源 ['124.74.41.42']，动作序列 ['AUTH']，时间范围 2026-05-20T00:00:00,429 -> 2026-05-20T00:00:00,429
- 会话 2689999: 用户 ['mms_cmb']，来源 ['8.8.8.8']，动作序列 ['AUTH']，时间范围 2026-05-20T23:59:59,999 -> 2026-05-20T23:59:59,999
- 会话 sess-1: 用户 ['alice']，来源 ['10.0.0.10']，动作序列 ['GET', 'PUT']，时间范围 2026-05-26T09:00:00Z -> 2026-05-26T09:05:00Z
- 会话 sess-2: 用户 ['bob']，来源 ['10.0.0.20']，动作序列 ['LIST']，时间范围 2026-05-26T09:10:00Z -> 2026-05-26T09:10:00Z
- 会话 sess-9: 用户 ['alice']，来源 ['203.0.113.55']，动作序列 ['DELETE']，时间范围 2026-05-26T23:30:00Z -> 2026-05-26T23:30:00Z

## 异常识别逻辑

采用确定性多维打分，事件级 17 维度（来源偏离、动作偏离、路径偏离、认证偏离、客户端偏离、时段偏离、失败偏离、体量偏离、首次来源IP、特权路径、敏感文件、数据外泄指标、批量下载、进出比偏离、暴力破解、休眠账户激活、异常结果类型），会话级 5 维度（长会话、多IP会话、爬取行为、会话数据外泄、孤立会话），外加暴力破解集群和跨用户共享IP检测。总分 ≥ 60 触发告警，并结合可信网段和降优先级策略调整严重等级。休眠账户按当前事件与历史 last_seen 间隔天数判定。

## 结果展示方式

本次运行共触发 7 条告警。

- 告警 alert-1: 用户 farms_warn_ruisuiyh，会话 2689379，级别 medium，原因 ['action deviation', 'auth deviation', 'client deviation', 'source deviation']，说明 操作类型偏离历史基线；认证方式偏离历史基线；客户端版本偏离历史基线；来源地址偏离历史基线
- 告警 alert-2: 用户 mms_cmb，会话 2689385，级别 medium，原因 ['action deviation', 'auth deviation', 'client deviation', 'source deviation']，说明 操作类型偏离历史基线；认证方式偏离历史基线；客户端版本偏离历史基线；来源地址偏离历史基线
- 告警 alert-3: 用户 farms_warn_dongyayh，会话 2689397，级别 medium，原因 ['action deviation', 'auth deviation', 'client deviation', 'source deviation']，说明 操作类型偏离历史基线；认证方式偏离历史基线；客户端版本偏离历史基线；来源地址偏离历史基线
- 告警 alert-4: 用户 mms_cmb，会话 2689999，级别 high，原因 ['action deviation', 'auth deviation', 'client deviation', 'failure deviation', 'source deviation']，说明 操作类型偏离历史基线；认证方式偏离历史基线；客户端版本偏离历史基线；失败行为与历史失败率不一致；来源地址偏离历史基线
- 告警 alert-5: 用户 alice，会话 sess-1，级别 medium，原因 ['action deviation', 'path deviation', 'source deviation']，说明 操作类型偏离历史基线；访问路径偏离历史基线；来源地址偏离历史基线
- 告警 alert-6: 用户 bob，会话 sess-2，级别 medium，原因 ['action deviation', 'path deviation', 'source deviation']，说明 操作类型偏离历史基线；访问路径偏离历史基线；来源地址偏离历史基线
- 告警 alert-7: 用户 alice，会话 sess-9，级别 high，原因 ['action deviation', 'failure deviation', 'path deviation', 'source deviation']，说明 操作类型偏离历史基线；失败行为与历史失败率不一致；访问路径偏离历史基线；来源地址偏离历史基线

## 准确性与可复用性分析

第一版强调可解释性与结构化过程，异常由脚本打分决定，LLM 不参与最终判定。

## 局限与改进方向

阈值仍采用启发式设置，尚未针对更大规模历史样本做调优；会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检；暴力破解检测基于滑动窗口，密集慢速攻击可能不触发

## 总结

脚本决定异常，LLM 负责解释和报告。
