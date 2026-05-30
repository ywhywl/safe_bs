# Task 2 内网落地手册

## 1. 适用范围

本手册用于在内网环境落地运行题目 2 的 SFTP 异常行为识别能力。

当前已支持的日志类型：

- `sftp` 运行日志
  - 典型特征：`|||||` 分隔，包含 `AuthSuccess/AuthFailure`、`publickey/password`、`SSH-2.0-*`、用户名等字段
- `sftp` 程序日志
  - 典型特征：`proftpd[...]`，包含 `SSH2 session opened/closed`、`USER xxx: Login successful/failed`
- `mod_sftp` 协议协商与认证日志
  - 典型特征：`mod_sftp/0.9.9[...]` 或对齐续行 `[...]`
  - 可抽取字段：客户端版本、KEX、hostkey、cipher、MAC、USERAUTH 请求、publickey 指纹、SFTP 子系统、REALPATH/读偏移异常等

## 2. 内网部署要求

最小要求：

- `python3`
- `bash`
- 保持当前项目目录结构不变

推荐保留目录：

- `bin/`
- `scripts/`
- `common/`
- `task2/`
- `docs/`

## 3. 真实日志目录规范

强烈建议每一批待分析日志单独放一个目录。

推荐目录结构：

```text
/data/task2_case_001/
  runtime_pipe.log
  proftpd_program.log
  noise_policy.json
```

若你希望用“历史基线 vs 当前窗口”模式，推荐目录结构：

```text
/data/task2_case_002/
  baseline/
    runtime_pipe_20260520.log
    proftpd_program_20260520.log
  current/
    runtime_pipe_20260528.log
    proftpd_program_20260528.log
  noise_policy.json
```

要求：

- 一个目录只放同一批次日志
- 不要把截图、说明文档、历史 JSON 结果放进去
- 不要把多个来源、多个时间段、多个业务环境的数据混在同一目录
- `noise_policy.json` 可选；若存在，会被用作降噪策略

## 4. 推荐文件命名

推荐命名如下：

- `runtime_pipe.log`
  - 对应运行日志
- `proftpd_program.log`
  - 对应程序日志
- `noise_policy.json`
  - 对应降噪与可信网段策略

如果你有更多文件，可以命名为：

- `runtime_pipe_20260520.log`
- `proftpd_program_20260520.log`

只要内容格式正确，脚本会自动识别，不强制要求固定文件名。

## 5. noise_policy.json 说明

示例：

```json
{
  "suppress_users": ["unknown"],
  "trusted_users": ["batch_sync_user"],
  "trusted_client_versions": ["SSH-2.0-OpenSSH_8.4"],
  "trusted_src_subnets": [
    "202.104.136.0/24",
    "172.31.160.0/24"
  ],
  "deprioritize_trigger_types": ["multi_source_burst"],
  "account_risk_strategy": "account",
  "expected_algorithms": {
    "forbidden_kex": ["diffie-hellman-group1-sha1"],
    "forbidden_hostkeys": ["ssh-dss", "ssh-rsa"],
    "forbidden_ciphers": ["aes128-cbc", "aes192-cbc", "aes256-cbc"],
    "forbidden_macs": ["hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"]
  }
}
```

字段说明：

- `suppress_users`
  - 需要直接抑制的用户，例如 `unknown`
- `trusted_src_subnets`
  - 业务已知可信出口网段
  - 命中这些网段时，部分保守告警会被降级
- `trusted_users`
  - 业务已知可信账户
- `trusted_client_versions`
  - 业务认可的客户端版本白名单
- `deprioritize_trigger_types`
  - 需要降低等级的触发类型
  - 当前可用于压低 `multi_source_burst`
- `account_risk_strategy`
  - 默认 `account`
  - 表示最终输出优先按账户风险归并
- `expected_algorithms`
  - 定义明确不安全的 KEX / hostkey / cipher / MAC
  - 命中后可直接触发协议安全类告警

## 6. 运行方式

从项目根目录执行：

```bash
RUN_ID=task2_case_001 ./bin/run_task2.sh /data/task2_case_001
```

说明：

- `RUN_ID` 建议显式指定，便于后续回溯
- 第二个参数是日志目录
- 若目录内存在 `baseline/` 和 `current/`，脚本会优先使用 `baseline/` 构建历史基线，仅对 `current/` 触发检测
- 若没有拆分目录，则保持旧行为：同一批数据内建基线并打分
- 当前版本默认开启大数据模式 `TASK2_LARGE_MODE=1`，用于避免大日志场景下基线、关联图和序列聚类阶段无约束膨胀。
- 对 5G 级以上日志，在 16G 内存机器上建议保持默认值，或显式指定：

```bash
TASK2_LARGE_MODE=1 RUN_ID=task2_case_001 ./bin/run_task2.sh /data/task2_case_001
```

- 大数据模式会限制每用户路径画像、序列聚类样本数、关联图候选规模和部分明细输出，目标是优先保证任务能稳定完成
- 若数据规模较小、希望保留更多细节，可手动关闭：

```bash
TASK2_LARGE_MODE=0 RUN_ID=task2_case_small ./bin/run_task2.sh /data/task2_case_small
```

## 7. 输出结果位置

运行后，重点看两处：

### 7.1 运行产物

路径：

```text
runs/<RUN_ID>/task2/json/
runs/<RUN_ID>/task2/alerts/
```

重点文件：

- `task2_alerts.json`
- `task2_user_baselines.json`
- `task2_session_views.json`
- `task2_events.json`
- `task2_anomaly_scores.json`
- `alert_output.log`

### 7.2 交付展示产物

路径：

- `task2/MANUAL.md`
- `task2/REPORT.md`
- `task2/AI_REPORT.md`
- `task2/TOOLS/json/`
- `task2/TOOLS/alerts/alert_output.log`

## 8. 结果怎么看

### 8.1 先看告警

优先打开：

- `runs/<RUN_ID>/task2/json/task2_alerts.json`
- `runs/<RUN_ID>/task2/alerts/alert_output.log`

看这些字段：

- `user`
- `session_id`
- `severity`
- `trigger_reasons`
- `llm_explanation`
- `session_summary`

### 8.2 再看用户基线

打开：

- `runs/<RUN_ID>/task2/json/task2_user_baselines.json`

重点看：

- `usual_src_ips`
- `usual_src_subnets`
- `usual_actions`
- `usual_auth_methods`
- `usual_client_versions`
- `active_time_profile`
- `usual_failure_rate`

另外建议关注：

- `baseline_mode`
- `baseline_event_count`
- `current_event_count`

### 8.3 再看会话视图

打开：

- `runs/<RUN_ID>/task2/json/task2_session_views.json`
- `runs/<RUN_ID>/task2/json/task2_session_views.ndjson`

重点看：

- `action_sequence`
- `src_ips`
- `start_time`
- `end_time`
- `unbalanced_session`
- `inferred_user`

## 9. 当前已支持的异常类型

已实现：

- 来源 IP 偏离
- 来源网段偏离
- 认证方式偏离
- 客户端版本偏离
- 协议协商偏离（KEX / hostkey / cipher / MAC）
- 明确弱算法检测
- 动作偏离
- 路径偏离
- 夜间或非常见时段偏离
- 登录失败偏离
- 会话开闭不平衡
- 同一用户短时间多源并发
- 默认账户风险聚合

## 10. 常见问题

### 10.1 为什么没有告警

可能原因：

- 数据全都符合当前基线
- 数据量太少，基线本身不稳定
- `noise_policy.json` 把部分告警压掉了
- 若使用 `baseline/current` 模式，可能是历史基线过宽，已把当前行为视为正常

### 10.2 为什么误报较多

可能原因：

- 多种来源日志混在一个目录
- 可信出口网段没有加入 `trusted_src_subnets`
- 当前阈值仍是启发式，未针对你内网真实数据调优
- 未拆分历史与当前窗口，导致当前异常事件被“吸进基线”

### 10.3 为什么程序日志里的会话用户是 unknown

原因：

- `SESSION_OPEN/CLOSE` 本身通常不显式带用户名
- 只有在同源 IP 和近邻时间窗口中有足够强的认证成功证据时，才会补 `inferred_user`

### 10.4 1GB 文件能不能跑

当前可以跑，但建议：

- 每批日志单独目录运行
- 尽量按天、按环境、按系统拆分目录
- 先在一小批样本上验证策略，再扩大到全量

当前实现已经把事件和打分切成 `NDJSON`，比最初版本更适合大文件。

## 11. 推荐操作顺序

1. 先准备一个独立日志目录
2. 推荐拆成 `baseline/` 和 `current/`；最少也要把当前待检测窗口单独成批
3. 可选增加 `noise_policy.json`
4. 执行 `RUN_ID=... ./bin/run_task2.sh <log_dir>`
5. 先看 `task2_alerts.json`
6. 再看 `task2_user_baselines.json`
7. 必要时调整 `noise_policy.json` 重新运行
