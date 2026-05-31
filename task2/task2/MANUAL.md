# MANUAL

## 工具目标

自动分析 SFTP 日志，提取用户行为基线，对新日志进行异常识别、关联分析和账户风险聚合，输出可审计告警。

## 使用方法

### 流水线执行顺序

```bash
# Step 1: 识别数据集布局与日志类型
python3 task2/TOOLS/scripts/ingest_logs.py --run-dir <run_dir> --input-dir <input_dir>

# Step 2: 归一化事件为 NDJSON
python3 task2/TOOLS/scripts/normalize_events.py --run-dir <run_dir> --input-dir <input_dir>

# Step 3: 会话用户属性推断（将 protocol 事件的 user=unknown 替换为真实用户）
python3 task2/TOOLS/scripts/reattribute_session_users.py --run-dir <run_dir>

# Step 4: Stage 1 轻基线粗筛
python3 task2/TOOLS/scripts/stage1_build_baseline.py --run-dir <run_dir>

# Step 5: Stage 1 候选发现
python3 task2/TOOLS/scripts/stage1_detect_candidates.py --run-dir <run_dir>

# Step 6: 抽取 Stage 2 scoped 事件子集
python3 task2/TOOLS/scripts/extract_stage2_scope.py --run-dir <run_dir>

# Step 7: 精细基线构建
python3 task2/TOOLS/scripts/build_baseline.py --run-dir <run_dir>

# Step 8: 多维异常评分（事件级 + 会话级）
python3 task2/TOOLS/scripts/score_anomalies.py --run-dir <run_dir>

# Step 9: 会话视图聚合
python3 task2/TOOLS/scripts/build_session_views.py --run-dir <run_dir>

# Step 10: 跨用户行为序列聚类
python3 task2/TOOLS/scripts/build_sequence_clusters.py --run-dir <run_dir>

# Step 11: 生成账户级/关联级告警
python3 task2/TOOLS/scripts/build_alerts.py --run-dir <run_dir>

# Step 12: 输出告警日志文件
python3 task2/TOOLS/scripts/emit_alert_log.py --run-dir <run_dir> --project-root <project_root>

# Step 13: 构建基线视图
python3 task2/TOOLS/scripts/build_baseline_views.py --run-dir <run_dir>

# Step 14: 汇总报告上下文
python3 task2/TOOLS/scripts/build_report_context.py --run-dir <run_dir>

# Step 15: 生成 MANUAL / REPORT / AI_REPORT
python3 task2/TOOLS/scripts/render_reports.py --run-dir <run_dir> --project-root <project_root> [--llm-config <path>]
```
初次使用：TASK2_LARGE_MODE=1 ; ./task2/TOOLS/run.sh
### 参数说明

- `--run-dir`：运行输出目录（所有中间 JSON 写入此处），例如 `runs/20260531T080814Z`
- `--input-dir`：原始日志所在目录，支持两种布局：
  - 单目录模式：所有日志在同一目录下，自动区分 baseline/current
  - 分离模式：目录下包含 `baseline/` 和 `current/` 子目录
- `--project-root`：项目根目录（task2 目录所在位置），例如 `/path/to/safe_bs`
- `--llm-config`：LLM 配置文件路径（可选），默认为 `task2/TOOLS/llm_config.json`

### 环境变量

- `TASK2_LARGE_MODE=1`：大数据模式（默认开启），适合 >8G 日志。限制每用户路径画像规模和序列聚类样本数，在 16G 内存机器上稳定运行。
- `TASK2_LARGE_MODE=0`：关闭大数据模式，保留完整细节优先（适合小数据集精跑）。

### 目录结构要求

``text
<input_dir>/
  baseline/           # 历史基准日志（可选）
    proftpd.log-20260526
    run-2026-05-25T16-00-00.000.log
    sftp.log-20260526
  current/            # 当前检测日志（可选，无此目录时根目录即为当前日志）
    proftpd_program.log
    runtime_pipe.log
    sftp.log
  noise_policy.json   # 噪声策略配置（可选）
```

### 噪声策略配置

`noise_policy.json` 支持以下可调项：
- `suppress_users`：不纳入基线的用户列表
- `trusted_users`：可信用户（降低告警优先级）
- `trusted_src_subnets`：可信来源网段
- `trusted_client_versions`：可信客户端版本
- `expected_algorithms.forbidden_kex/hostkeys/ciphers/macs`：算法黑白名单
- `account_risk_strategy`：告警聚合策略（默认 account）
- `business_hours_by_user`：每个用户的业务时段定义

### LLM 配置

`llm_config.json` 支持两种模式：
- 内网私有化模式（glm-5.1）：适合内网环境，不依赖外网 API
- 外网模式（Claude Code skill）：利用外部 LLM API 增强报告质量

### 支持的日志格式

工具自动识别以下三类日志格式，无需手动指定：

**1. proftpd 程序日志（sftp_program_proftpd）**
```
2026-05-25 00:01:01,768 nucc-30-test-uat-app-1-dmz-11 proftpd[3764202] 172.31.160.3 (221.182.181.18[221.182.181.18]): USER hnbank: Login successful.
```
识别特征：行内含 `proftpd[` 且含 `SSH2 session` / `Login successful` / `Login failed`。
提取字段：时间戳、服务器 IP、客户端 IP、PID（作为 session_id）、用户名、动作（SESSION_OPEN/SESSION_CLOSE/LOGIN）。

**2. runtime pipe 认证日志（sftp_runtime_pipe）**
```
2026-05-25 23:59:59,891|||||172.31.160.31|SZ30test||||||||||13761601|36.110.9.121|SSH-2.0-JSCH-0.1.54|hnb_001|publickey|0|AuthSuccess|user 'hnb_001' authenticated via 'publickey' method
```
识别特征：行内含 `AuthSuccess` 且含 `publickey`，字段以 `|` 分隔。
提取字段：时间戳、服务器 IP、系统名、session_id、来源 IP、客户端版本、用户名、认证方式、结果（ok/fail）。

**3. mod_sftp 协议协商日志（sftp_protocol_mod_sftp）**
```
2026-05-25 00:01:13,597 mod_sftp/0.9.9[3764562]: + Session key exchange: ecdh-sha2-nistp256
2026-05-25 00:01:13,597 mod_sftp/0.9.9[3764562]: + Session client-to-server encryption: aes128-ctr
2026-05-25 00:01:13,597 mod_sftp/0.9.9[3764562]: + Session client-to-server MAC: hmac-md5
```
识别特征：行内含 `mod_sftp/0.9.9` 或 `[PID]:` 格式。
提取字段：KEX 算法、主机密钥算法、加密算法（c2s/s2c）、MAC 算法（c2s/s2c）、客户端版本、认证方式。
用途：识别弱算法协商（弱 KEX、弱 cipher、弱 MAC）并纳入协议安全维度评分。

## 核心流程

日志解析 -> 事件归一化 -> 历史基线生成 -> 新日志多维异常评分 -> 会话/关联分析 -> 账户风险聚合 -> 解释与文档生成。

## 输入说明

当前检测数据：
- 文件: task2/TOOLS/datasets/demo_abnormal/proftpd_program.log，格式猜测: sftp_program_proftpd，行数: 9
- 文件: task2/TOOLS/datasets/demo_abnormal/runtime_pipe.log，格式猜测: sftp_runtime_pipe，行数: 11

## 输出说明

输出 JSON / NDJSON 中间态、结构化告警日志、用户基线视图、关联分析结果以及 MANUAL / REPORT / AI_REPORT。默认按账户风险聚合输出，同时保留会话级和关联级证据。

## 结果查看方式

查看方式：
- 用户基线：`task2_baseline_views.json`（每个用户的常见来源、动作、时段、客户端、协议安全参数）
- 完整基线画像：`task2_user_baselines.json`
- 会话视图：`task2_session_views.ndjson`（按 session_id 聚合，含动作序列、路径、时间范围）
- 告警列表：`task2_alerts.json`（按账户风险聚合，含触发原因、打分明细、推荐处置）
- 告警日志文件：`task2/TOOLS/alerts/alert_output.log`
- 关联序列模式：`task2_sequence_clusters.json`（跨用户行为序列聚类）
- 异常评分明细：`task2_anomaly_scores.ndjson`

详细分析结果见 REPORT.md。

## 题目要求映射

- 自动分析用户行为基线：已实现。脚本从成功事件中提取用户常见来源 IP/网段、常见访问时段、常见动作/路径、认证方式、客户端版本及协议协商参数，形成 JSON 基线。
- 监控 SFTP 日志并识别异常：已实现。事件级采用多维确定性打分，会话级做聚合分析，并输出结构化告警与告警日志。
- 告警可打印到指定日志文件模拟：已实现。脚本生成 `alert_output.log`，便于评测环境直接检查告警结果。
- 行为基线需自动分析获得并提供查看方式：已实现。`task2_user_baselines.json`、`task2_baseline_views.json`、`MANUAL.md` 中均提供查看入口。
- 行为基线可保存为 JSON：已实现。所有中间态与交付态均为 JSON/NDJSON，适合内网环境直接落地。
- 以某一天/某几天日志对比新日志：已实现。目录支持 `baseline/` 与 `current/` 分离模式，直接对应题意中的《基准日志 vs 新日志》。
- 大文件内网落地：已增强。支持 `TASK2_LARGE_MODE=1`，在 16G 内存机器上通过限制路径画像和序列聚类样本规模换取稳定运行。

## 参数与阈值说明

支持 baseline/current 对比模式。事件级加入协议安全维度：弱 KEX、弱 hostkey、弱 cipher、弱 MAC、协议协商偏离、老旧客户端指纹偏离；会话级保留 5 维度；默认按账户风险聚合输出。可信网段、可信用户、可信客户端、算法白名单/黑名单可在 noise_policy.json 调整。

## 大数据模式说明

- 当前运行启用 `TASK2_LARGE_MODE=1`。
- 脚本会限制每用户路径画像规模、限制序列聚类参与 session 数，避免 16G 机器在超大日志上内存失控。
- 代价是部分长尾路径和低频序列模式可能被截断，因此建议先全量粗筛，再对高风险账户做小范围精跑。

## 适用范围与局限

阈值仍采用启发式设置，尚未针对更大规模历史样本做调优；会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检；暴力破解检测基于滑动窗口，密集慢速攻击可能不触发；开启 TASK2_LARGE_MODE=1 时，会对路径画像和序列聚类样本做截断，以换取 16G 机器上的稳定运行；当前 scoped 抽取仍以候选时间窗、session、来源和目标命中为主，真实大数据上的压缩率仍需进一步验证和调优

## 告警文件说明

查看 task2/TOOLS/alerts/alert_output.log 或 runs 下对应输出。
