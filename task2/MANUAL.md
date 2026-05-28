# MANUAL

## 工具目标

从 SFTP 日志中提取基线并识别异常。

## 输入说明

历史基线数据：
- 文件: /private/tmp/task2_hist_case/baseline/proftpd_program_sample.log，格式猜测: sftp_program_proftpd，行数: 5
- 文件: /private/tmp/task2_hist_case/baseline/sample_kv.log，格式猜测: key_value，行数: 4
当前检测数据：
- 文件: /private/tmp/task2_hist_case/current/runtime_pipe_sample.log，格式猜测: sftp_runtime_pipe，行数: 4
- 文件: /private/tmp/task2_hist_case/current/sample.log，格式猜测: plain_text，行数: 4

## 输出说明

输出 JSON、告警日志和报告草稿。

## 核心流程

日志解析 -> 事件归一化 -> 用户基线生成 -> 多维异常评分 -> 告警输出 -> 解释与文档生成。

## 用户基线查看方式

- 用户 finance: 常见来源 ['10.10.2.20'], 常见动作 ['PUT'], 常见路径 ['/finance/payroll.csv'], 常见时段 [9]
- 用户 ops: 常见来源 ['10.10.1.15'], 常见动作 ['GET', 'LIST'], 常见路径 ['/dropbox', '/dropbox/config.yml'], 常见时段 [8, 9]
- 用户 tms_cmb: 常见来源 ['202.104.136.69'], 常见动作 ['LOGIN'], 常见路径 [], 常见时段 [0]
- 用户 unknown: 常见来源 ['202.104.136.69', '222.76.46.33'], 常见动作 ['SESSION_CLOSE', 'SESSION_OPEN'], 常见路径 [], 常见时段 [0]

## 会话查看方式

- 会话 2689379: 用户 ['farms_warn_ruisuiyh']，来源 ['220.248.41.29']，动作序列 ['AUTH']，时间范围 2026-05-20T00:00:00,018 -> 2026-05-20T00:00:00,018
- 会话 2689385: 用户 ['mms_cmb']，来源 ['202.104.136.69']，动作序列 ['AUTH']，时间范围 2026-05-20T00:00:00,223 -> 2026-05-20T00:00:00,223
- 会话 2689397: 用户 ['farms_warn_dongyayh']，来源 ['124.74.41.42']，动作序列 ['AUTH']，时间范围 2026-05-20T00:00:00,429 -> 2026-05-20T00:00:00,429
- 会话 2689999: 用户 ['mms_cmb']，来源 ['8.8.8.8']，动作序列 ['AUTH']，时间范围 2026-05-20T23:59:59,999 -> 2026-05-20T23:59:59,999
- 会话 sess-1: 用户 ['alice']，来源 ['10.0.0.10']，动作序列 ['GET', 'PUT']，时间范围 2026-05-26T09:00:00Z -> 2026-05-26T09:05:00Z
- 会话 sess-2: 用户 ['bob']，来源 ['10.0.0.20']，动作序列 ['LIST']，时间范围 2026-05-26T09:10:00Z -> 2026-05-26T09:10:00Z
- 会话 sess-9: 用户 ['alice']，来源 ['203.0.113.55']，动作序列 ['DELETE']，时间范围 2026-05-26T23:30:00Z -> 2026-05-26T23:30:00Z

## 告警解释方式

- 告警 alert-1: 用户 farms_warn_ruisuiyh，会话 2689379，级别 medium，原因 ['action deviation', 'auth deviation', 'client deviation', 'source deviation']，说明 操作类型偏离历史基线；认证方式偏离历史基线；客户端版本偏离历史基线；来源地址偏离历史基线
- 告警 alert-2: 用户 mms_cmb，会话 2689385，级别 medium，原因 ['action deviation', 'auth deviation', 'client deviation', 'source deviation']，说明 操作类型偏离历史基线；认证方式偏离历史基线；客户端版本偏离历史基线；来源地址偏离历史基线
- 告警 alert-3: 用户 farms_warn_dongyayh，会话 2689397，级别 medium，原因 ['action deviation', 'auth deviation', 'client deviation', 'source deviation']，说明 操作类型偏离历史基线；认证方式偏离历史基线；客户端版本偏离历史基线；来源地址偏离历史基线
- 告警 alert-4: 用户 mms_cmb，会话 2689999，级别 high，原因 ['action deviation', 'auth deviation', 'client deviation', 'failure deviation', 'source deviation']，说明 操作类型偏离历史基线；认证方式偏离历史基线；客户端版本偏离历史基线；失败行为与历史失败率不一致；来源地址偏离历史基线
- 告警 alert-5: 用户 alice，会话 sess-1，级别 medium，原因 ['action deviation', 'path deviation', 'source deviation']，说明 操作类型偏离历史基线；访问路径偏离历史基线；来源地址偏离历史基线
- 告警 alert-6: 用户 bob，会话 sess-2，级别 medium，原因 ['action deviation', 'path deviation', 'source deviation']，说明 操作类型偏离历史基线；访问路径偏离历史基线；来源地址偏离历史基线
- 告警 alert-7: 用户 alice，会话 sess-9，级别 high，原因 ['action deviation', 'failure deviation', 'path deviation', 'source deviation']，说明 操作类型偏离历史基线；失败行为与历史失败率不一致；访问路径偏离历史基线；来源地址偏离历史基线

## 参数与阈值说明

事件级 17 维度 + 会话级 5 维度 + 暴力破解 + 跨用户共享IP，总分 ≥ 60 触发。可信网段降级、降优先级类型、抑制用户可在 noise_policy.json 调整。

## 适用范围与局限

阈值仍采用启发式设置，尚未针对更大规模历史样本做调优；会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检；暴力破解检测基于滑动窗口，密集慢速攻击可能不触发

## 告警文件说明

查看 task2/TOOLS/alerts/alert_output.log 或 runs 下对应输出。
