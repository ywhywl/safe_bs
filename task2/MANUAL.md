# MANUAL

## 工具目标

自动分析 SFTP 日志，提取用户行为基线，对新日志进行异常识别、关联分析和账户风险聚合，输出可审计告警。

## 核心流程

```text
原始日志
  -> ingest_logs.py              识别数据集布局与日志类型
  -> normalize_events.py         归一化为 task2_events.ndjson
  -> reattribute_session_users.py  会话用户属性推断
  -> stage1_build_baseline.py    Stage 1 轻基线粗筛
  -> stage1_detect_candidates.py Stage 1 候选发现
  -> extract_stage2_scope.py     抽取 Stage 2 scoped 事件子集
  -> build_baseline.py           精细基线构建
  -> score_anomalies.py          多维异常评分（事件级 + 会话级）
  -> build_session_views.py      会话视图聚合
  -> build_sequence_clusters.py  跨用户行为序列聚类
  -> build_alerts.py             生成账户级/关联级告警
  -> emit_alert_log.py           输出告警日志文件
  -> build_baseline_views.py     构建基线视图
  -> build_report_context.py     汇总报告上下文
  -> render_reports.py           生成 MANUAL / REPORT / AI_REPORT
```

## 使用方法

### 快速开始（独立运行，推荐）

工具已自包含，无需配置外部 PYTHONPATH：

```bash
cd task2/TOOLS

# 使用内置演示数据运行
bash run.sh

# 指定自定义日志目录
bash run.sh /path/to/your/logs

# 指定 LLM 配置（内网模式）
LLM_CONFIG=/path/to/llm_config.json bash run.sh /path/to/logs
```

### 参数说明

| 参数 | 方式 | 默认值 | 说明 |
|---|---|---|---|
| INPUT_DIR | 位置参数 $1 | TOOLS/datasets/demo_abnormal | 原始日志目录 |
| LLM_CONFIG | 环境变量 | TOOLS/llm_config.json | LLM 配置文件路径 |
| RUN_ID | 环境变量 | 时间戳 | 运行 ID，输出写入 runs/<RUN_ID>/ |
| TASK2_LARGE_MODE | 环境变量 | 1 | 大数据模式（1=开启，0=关闭） |

### 输出位置

```text
task2/TOOLS/runs/<RUN_ID>/task2/
  json/          # 中间 JSON（基线、告警、会话视图等）
  alerts/        # 告警日志和步骤耗时
task2/TOOLS/alerts/alert_output.log   # 最新告警日志（每次运行覆盖）
task2/MANUAL.md                       # 使用手册（自动刷新）
task2/REPORT.md                       # 分析报告（自动刷新）
task2/AI_REPORT.md                    # AI 使用报告（自动刷新）
```

### 分步执行（调试用）

在 `task2/TOOLS/` 目录下，设置 `PYTHONPATH` 后逐步运行：

```bash
cd task2/TOOLS
export PYTHONPATH="$(pwd)/scripts"
RUN_DIR="runs/$(date -u +%Y%m%dT%H%M%SZ)"
INPUT_DIR=/path/to/logs
mkdir -p "${RUN_DIR}/task2"/{json,alerts}

python3 scripts/ingest_logs.py               --run-dir $RUN_DIR --input-dir $INPUT_DIR
python3 scripts/normalize_events.py          --run-dir $RUN_DIR --input-dir $INPUT_DIR
python3 scripts/reattribute_session_users.py --run-dir $RUN_DIR
python3 scripts/stage1_build_baseline.py     --run-dir $RUN_DIR
python3 scripts/stage1_detect_candidates.py  --run-dir $RUN_DIR --input-dir $INPUT_DIR
python3 scripts/extract_stage2_scope.py      --run-dir $RUN_DIR
python3 scripts/build_baseline.py            --run-dir $RUN_DIR
python3 scripts/score_anomalies.py           --run-dir $RUN_DIR --input-dir $INPUT_DIR
python3 scripts/build_session_views.py       --run-dir $RUN_DIR
python3 scripts/build_sequence_clusters.py   --run-dir $RUN_DIR
python3 scripts/build_alerts.py              --run-dir $RUN_DIR --input-dir $INPUT_DIR
python3 scripts/emit_alert_log.py            --run-dir $RUN_DIR
python3 scripts/build_baseline_views.py      --run-dir $RUN_DIR
python3 scripts/build_report_context.py      --run-dir $RUN_DIR
python3 scripts/render_reports.py            --run-dir $RUN_DIR --project-root ../..
```

### 目录结构要求

```text
<input_dir>/
  baseline/           # 历史基准日志（可选）
    proftp.log-20260526
    run-2026-05-25T16-00-00.000.log
    sftp.log-20260526
  current/            # 当前检测日志（可选，无此目录时根目录即为当前日志）
    proftpd_program.log
    runtime_pipe.log
    sftp.log
  noise_policy.json   # 噪声策略配置（可选）
```

### 环境变量

- `TASK2_LARGE_MODE=1`：大数据模式（默认开启），适合 >8G 日志。限制每用户路径画像规模和序列聚类样本数，在 16G 内存机器上稳定运行。
- `TASK2_LARGE_MODE=0`：关闭大数据模式，保留完整细节优先（适合小数据集精跑）。

## 支持的日志格式

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

## 参数与阈值说明

支持 baseline/current 对比模式。事件级加入协议安全维度：弱 KEX、弱 hostkey、弱 cipher、弱 MAC、协议协商偏离、老旧客户端指纹偏离；会话级保留 5 维度；默认按账户风险聚合输出。可信网段、可信用户、可信客户端、算法白名单/黑名单可在 noise_policy.json 调整。

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

## 大数据模式说明

- 当前运行启用 `TASK2_LARGE_MODE=1`。
- 脚本会限制每用户路径画像规模、限制序列聚类参与 session 数，避免 16G 机器在超大日志上内存失控。
- 代价是部分长尾路径和低频序列模式可能被截断，因此建议先全量粗筛，再对高风险账户做小范围精跑。

## 适用范围与局限

阈值仍采用启发式设置，尚未针对更大规模历史样本做调优；会话级检测依赖 SESSION_OPEN/CLOSE 动作，日志格式不全时可能漏检；暴力破解检测基于滑动窗口，密集慢速攻击可能不触发；开启 TASK2_LARGE_MODE=1 时，会对路径画像和序列聚类样本做截断，以换取 16G 机器上的稳定运行。

## 告警文件说明

查看 `task2/TOOLS/alerts/alert_output.log` 或 `runs/<run_id>/task2/alerts/alert_output.log`。
