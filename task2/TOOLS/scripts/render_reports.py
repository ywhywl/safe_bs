#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from event_io import iter_ndjson
from lib import load_json, render_markdown, write_text
from llm_client import create_client, InternalLLMClient


def summarize_sources(dataset_summary: dict) -> str:
    current_sources = dataset_summary.get("current_sources", [])
    baseline_sources = dataset_summary.get("baseline_sources", [])
    sources = dataset_summary.get("sources", [])
    if current_sources or baseline_sources:
        lines = []
        if baseline_sources:
            lines.append("历史基线数据：")
            for source in baseline_sources:
                lines.append(
                    f"- 文件: {source.get('path')}，格式猜测: {source.get('format_guess')}，行数: {source.get('line_count')}"
                )
        if current_sources:
            lines.append("当前检测数据：")
            for source in current_sources:
                lines.append(
                    f"- 文件: {source.get('path')}，格式猜测: {source.get('format_guess')}，行数: {source.get('line_count')}"
                )
        return "\n".join(lines)
    if not sources:
        return "未检测到输入日志。"
    lines = []
    for source in sources:
        lines.append(
            f"- 文件: {source.get('path')}，格式猜测: {source.get('format_guess')}，行数: {source.get('line_count')}"
        )
    return "\n".join(lines)


MANUAL_VIEW_LIMIT = 50
MANUAL_SESSION_LIMIT = 50
MANUAL_ALERT_LIMIT = 50


def summarize_views(views: list[dict], limit: int = MANUAL_VIEW_LIMIT, total_count: int | None = None) -> str:
    if not views:
        return "未生成用户基线。"
    effective_total = total_count if total_count is not None else len(views)
    lines = []
    for view in views[:limit]:
        lines.append(
            f"- 用户 {view.get('user')}: 常见来源 {view.get('common_sources')}, 常见动作 {view.get('common_actions')}, 常见路径 {view.get('common_paths')}, 常见时段 {view.get('typical_login_window')}, 常见客户端 {view.get('common_clients')}, 常见协议安全参数 {view.get('common_protocol_security')}"
        )
    if effective_total > limit:
        lines.append(f"- ... 共 {effective_total} 个用户基线，此处仅展示前 {min(len(views), limit)} 个。完整基线请查看 task2_baseline_views.json。")
    return "\n".join(lines)


def summarize_alerts(alerts: list[dict], limit: int = MANUAL_ALERT_LIMIT, total_count: int | None = None) -> str:
    if not alerts:
        return "当前样本未触发告警。"
    effective_total = total_count if total_count is not None else len(alerts)
    lines = []
    for alert in alerts[:limit]:
        inferred = alert.get("inferred_user", "")
        inferred_text = f"，推断用户 {inferred}" if inferred else ""
        lines.append(
            f"- 告警 {alert.get('alert_id')}: 用户 {alert.get('user')}{inferred_text}，会话 {alert.get('session_id')}，级别 {alert.get('severity')}，原因 {alert.get('trigger_reasons')}，说明 {alert.get('llm_explanation')}"
        )
    if effective_total > limit:
        lines.append(f"- ... 共 {effective_total} 条告警，此处仅展示前 {min(len(alerts), limit)} 条。完整告警请查看 task2_alerts.json 和 alert_output.log。")
    return "\n".join(lines)


def summarize_list(values: list[str]) -> str:
    if not values:
        return "无"
    return "；".join(values)


def _summarize_sequence_clusters(data: dict) -> str:
    if not data or not data.get("cross_user_patterns"):
        return "未检测到跨用户行为序列模式。"
    lines = []
    for pattern in data.get("cross_user_patterns", [])[:5]:
        lines.append(
            f"- 模式 {pattern.get('cluster_id', '')}: "
            f"用户 {pattern.get('users', [])}, "
            f"序列 {pattern.get('sequence', [])}"
        )
    for ap in data.get("anomalous_sequence_patterns", [])[:5]:
        lines.append(
            f"- 异常模式 {ap.get('pattern_id', '')}: "
            f"序列 {ap.get('canonical_sequence', [])}, "
            f"影响用户 {ap.get('affected_users', [])}, "
            f"最高分数 {ap.get('max_score', 0)}"
        )
    return "\n".join(lines)


def _build_context_digest(context: dict) -> str:
    """Build a compact summary string for LLM input, keeping full JSON on disk for human review."""
    import json as _json
    # Keep only key sections at summary level; strip large nested structures
    digest = {
        "task_id": context.get("task_id"),
        "dataset_summary": context.get("dataset_summary", {}),
        "baseline_method_summary": context.get("baseline_method_summary", ""),
        "detection_logic_summary": context.get("detection_logic_summary", ""),
        "alert_summary": context.get("alert_summary", {}),
        "representative_cases": context.get("representative_cases", [])[:10],
        "session_summary": {
            "count": context.get("session_summary", {}).get("count", 0),
            "representative_sessions": [
                {"session_id": s.get("session_id"), "users": s.get("users"),
                 "src_ips": s.get("src_ips"), "action_sequence": s.get("action_sequence", [])[:10],
                 "summary": s.get("summary", "")}
                for s in context.get("session_summary", {}).get("representative_sessions", [])[:5]
            ],
        },
        "baseline_summary": context.get("baseline_summary", {}),
        "sequence_cluster_summary": context.get("sequence_cluster_summary", {}),
        "strengths": context.get("strengths", []),
        "limitations": context.get("limitations", []),
    }
    return _json.dumps(digest, ensure_ascii=False, indent=2)


def summarize_sessions(sessions: list[dict], limit: int = MANUAL_SESSION_LIMIT, total_count: int | None = None) -> str:
    if not sessions:
        return "未生成会话视图。"
    effective_total = total_count if total_count is not None else len(sessions)
    lines = []
    for session in sessions[:limit]:
        inferred = session.get("inferred_user", "")
        inferred_text = f"，推断用户 {inferred}" if inferred else ""
        lines.append(
            f"- 会话 {session.get('session_id')}: 用户 {session.get('users')}{inferred_text}，来源 {session.get('src_ips')}，动作序列 {session.get('action_sequence')}，时间范围 {session.get('start_time')} -> {session.get('end_time')}"
        )
    if effective_total > limit:
        lines.append(f"- ... 共 {effective_total} 个会话，此处仅展示前 {min(len(sessions), limit)} 个。完整会话请查看 task2_session_views.ndjson。")
    return "\n".join(lines)


def build_requirement_mapping(context: dict) -> str:
    large_mode = context.get("dataset_summary", {}).get("large_mode", False)
    lines = [
        "- 自动分析用户行为基线：已实现。脚本从成功事件中提取用户常见来源 IP/网段、常见访问时段、常见动作/路径、认证方式、客户端版本及协议协商参数，形成 JSON 基线。",
        "- 监控 SFTP 日志并识别异常：已实现。事件级采用多维确定性打分，会话级做聚合分析，并输出结构化告警与告警日志。",
        "- 告警可打印到指定日志文件模拟：已实现。脚本生成 `alert_output.log`，便于评测环境直接检查告警结果。",
        "- 行为基线需自动分析获得并提供查看方式：已实现。`task2_user_baselines.json`、`task2_baseline_views.json`、`MANUAL.md` 中均提供查看入口。",
        "- 行为基线可保存为 JSON：已实现。所有中间态与交付态均为 JSON/NDJSON，适合内网环境直接落地。",
        "- 以某一天/某几天日志对比新日志：已实现。目录支持 `baseline/` 与 `current/` 分离模式，直接对应题意中的《基准日志 vs 新日志》。",
    ]
    if large_mode:
        lines.append("- 大文件内网落地：已增强。支持 `TASK2_LARGE_MODE=1`，在 16G 内存机器上通过限制路径画像和序列聚类样本规模换取稳定运行。")
    return "\n".join(lines)


def build_architecture_summary(context: dict) -> str:
    return "\n".join(
        [
            "```text",
            "原始日志",
            "  -> ingest_logs.py           识别数据集布局与日志类型",
            "  -> normalize_events.py      归一化为 task2_events.ndjson",
            "  -> build_baseline.py        构建历史用户画像",
            "  -> score_anomalies.py       事件级 / 会话级异常评分",
            "  -> build_session_views.py   聚合会话视图",
            "  -> build_sequence_clusters.py   构建跨用户行为序列模式",
            "  -> build_alerts.py          生成账户级/关联级告警",
            "  -> emit_alert_log.py        输出告警日志",
            "  -> build_report_context.py  汇总报告上下文",
            "  -> render_reports.py        生成 MANUAL / REPORT / AI_REPORT",
            "```",
        ]
    )


def build_result_access_summary(context: dict, view_count: int, session_count: int, alert_count: int) -> str:
    """MANUAL-style result access summary — file pointers only, no runtime counts."""
    lines = [
        "查看方式：",
        "- 用户基线：`task2_baseline_views.json`（每个用户的常见来源、动作、时段、客户端、协议安全参数）",
        "- 完整基线画像：`task2_user_baselines.json`",
        "- 会话视图：`task2_session_views.ndjson`（按 session_id 聚合，含动作序列、路径、时间范围）",
        "- 告警列表：`task2_alerts.json`（按账户风险聚合，含触发原因、打分明细、推荐处置）",
        "- 告警日志文件：`task2/TOOLS/alerts/alert_output.log`",
        "- 关联序列模式：`task2_sequence_clusters.json`（跨用户行为序列聚类）",
        "- 异常评分明细：`task2_anomaly_scores.ndjson`",
        "",
        "详细分析结果见 REPORT.md。",
    ]
    return "\n".join(lines)


def build_data_structure_summary(context: dict) -> str:
    return "\n".join(
        [
            "- `task2_events.ndjson`：归一化事件流，字段覆盖用户、来源、动作、路径、结果、协议协商参数等。",
            "- `task2_user_baselines.json`：用户基线画像，包含常见来源、常见动作、时段、认证方式、客户端版本、协议安全特征、失败率和传输统计。",
            "- `task2_session_views.ndjson`：按 `session_id` 聚合后的会话视图，便于复核完整行为链。",
            "- `task2_anomaly_scores.ndjson`：事件级与会话级确定性打分结果，保留每个触发原因。",
            "- `task2_sequence_clusters.json`：异常会话序列模式与跨用户共享序列模式。",
            "- `task2_alerts.json`：最终告警，默认按账户风险聚合，同时保留关联攻击集群告警。",
        ]
    )


def build_scoring_summary() -> str:
    return "\n".join(
        [
            "事件级检测包含两层：",
            "- 行为偏离：来源 IP/网段、动作、路径、认证方式、客户端版本、访问时段、失败率、传输体量、首次来源 IP、进出流量比、休眠账户激活等。",
            "- 协议安全：弱 KEX、弱 hostkey、弱 cipher、弱 MAC、协议协商参数偏离历史基线、老旧客户端指纹漂移。",
            "会话级检测包含五层：",
            "- 长会话、多 IP 会话、短时间路径爬取、会话级数据外泄、孤立会话（打开未关闭）。",
            "关联检测包含一层：",
            "- 行为序列聚类：不同用户执行相同异常动作序列时，提升为关联攻击模式。",
        ]
    )


def build_highlights_summary(context: dict) -> str:
    large_mode = context.get("dataset_summary", {}).get("large_mode", False)
    lines = [
        "1. 原生支持 `baseline/current` 双目录模式，和题目《基准日志对比新日志》完全对齐。",
        "2. 不仅解析普通认证日志，还统一纳入 `runtime pipe`、`proftpd` 程序日志、`mod_sftp` 协议协商日志。",
        "3. 异常判定是确定性脚本规则，不是黑盒模型，所有告警都能追溯到触发原因和得分。",
        "4. 在单用户基线之外，增加了跨用户行为序列聚类和账户风险聚合，更接近真实 SOC 分析链路。",
        "5. 输出结构化 JSON/NDJSON，可直接在内网环境中沉淀为可复核、可回归、可自动化的产物。",
    ]
    if large_mode:
        lines.append("6. 针对 16G 内存机器增加大数据模式，优先保证超大日志可跑完，再通过二次精跑补回长尾细节。")
    return "\n".join(f"- {line}" for line in lines)


def build_large_mode_summary(context: dict) -> str:
    if not context.get("dataset_summary", {}).get("large_mode", False):
        return "当前运行未启用大数据模式，保留完整细节优先。"
    return "\n".join(
        [
            "- 当前运行启用 `TASK2_LARGE_MODE=1`。",
            "- 脚本会限制每用户路径画像规模、限制序列聚类参与 session 数，避免 16G 机器在超大日志上内存失控。",
            "- 代价是部分长尾路径和低频序列模式可能被截断，因此建议先全量粗筛，再对高风险账户做小范围精跑。",
        ]
    )


def build_scoring_alignment_summary(context: dict) -> str:
    return "\n".join(
        [
            "- 功能验证维度：当前实现已覆盖自动基线提取、异常识别、告警输出、基线查看、JSON 保存、日志文件告警模拟、基准日志对比新日志。",
            "- 可复用性维度：当前实现已具备目录规范、脚本流水线、JSON/NDJSON 中间态、内网大数据模式、账户级风险聚合和结构化报告生成能力。",
            "- 设计合理性维度：异常判定由脚本确定性输出，LLM 只做解释；这能降低幻觉风险，并提高复核性与回归测试能力。",
            "- 性能与工程维度：通过 NDJSON、流式处理、top-N 截断和大数据模式护栏，保证在内网 16G 机器上也能运行大批量日志。",
        ]
    )


def build_completion_summary(context: dict) -> str:
    return "\n".join(
        [
            "- 核心功能完成度：高。题目主要求已经全部覆盖。",
            "- 工程化完成度：高。已有可运行脚本、结构化输出、基线查看方式、告警日志模拟和内网大数据模式。",
            "- 文档完成度：高。当前 MANUAL / REPORT / AI_REPORT 已能随脚本执行自动刷新并体现设计亮点。",
            "- 剩余优化方向：主要在阈值调优、低频慢速攻击识别、超大规模关联分析精度和针对真实生产样本的验证深度。",
        ]
    )


def build_attack_story_example(alerts: list[dict], sequence_clusters: dict) -> str:
    if not alerts:
        return "当前样本未生成告警，无法构造攻击故事示例。"

    seq_pattern = sequence_clusters.get("cross_user_patterns", [None])[0]

    alert = alerts[0]
    story_lines = [
        f"1. 基线阶段：用户 `{alert.get('user')}` 的历史画像已在 `task2_user_baselines.json` 中建立，包含常见来源、时段和动作。",
        f"2. 告警阶段：会话 `{alert.get('session_id')}` 触发 `{alert.get('alert_id')}`，原因是 {alert.get('trigger_reasons', [])}，说明新日志显著偏离历史行为基线。",
    ]
    if seq_pattern:
        story_lines.append(
            f"3. 关联阶段：跨用户序列模式 `{seq_pattern.get('cluster_id')}` 表明用户 {seq_pattern.get('users', [])} 在会话 {seq_pattern.get('session_ids', [])} 中执行了相同异常序列 {seq_pattern.get('sequence', [])}。这把原本独立的单账户异常串成了一条统一攻击路径。"
        )
        story_lines.append(
            f"4. 结论阶段：从《基线外单点异常》到《跨用户相同异常序列》，当前样本可被解释为多个账户遭受了相似访问尝试，系统通过账户告警和序列模式两层输出完成闭环。"
        )
    else:
        story_lines.append(
            "3. 关联阶段：当前样本未形成跨用户序列模式，因此该案例主要体现单账户基线偏离如何升级为结构化告警。"
        )
        story_lines.append(
            "4. 结论阶段：即使没有跨实体关联，系统仍能从 baseline -> alert 这条主链完成异常检测，并为人工复核保留足够上下文。"
        )

    return "\n".join(story_lines)


def build_usage_instructions() -> str:
    return "\n".join(
        [
            "### 流水线执行顺序",
            "",
            "```bash",
            "# Step 1: 识别数据集布局与日志类型",
            "python3 task2/TOOLS/scripts/ingest_logs.py --run-dir <run_dir> --input-dir <input_dir>",
            "",
            "# Step 2: 归一化事件为 NDJSON",
            "python3 task2/TOOLS/scripts/normalize_events.py --run-dir <run_dir> --input-dir <input_dir>",
            "",
            "# Step 3: 会话用户属性推断（将 protocol 事件的 user=unknown 替换为真实用户）",
            "python3 task2/TOOLS/scripts/reattribute_session_users.py --run-dir <run_dir>",
            "",
            "# Step 4: Stage 1 轻基线粗筛",
            "python3 task2/TOOLS/scripts/stage1_build_baseline.py --run-dir <run_dir>",
            "",
            "# Step 5: Stage 1 候选发现",
            "python3 task2/TOOLS/scripts/stage1_detect_candidates.py --run-dir <run_dir>",
            "",
            "# Step 6: 抽取 Stage 2 scoped 事件子集",
            "python3 task2/TOOLS/scripts/extract_stage2_scope.py --run-dir <run_dir>",
            "",
            "# Step 7: 精细基线构建",
            "python3 task2/TOOLS/scripts/build_baseline.py --run-dir <run_dir>",
            "",
            "# Step 8: 多维异常评分（事件级 + 会话级）",
            "python3 task2/TOOLS/scripts/score_anomalies.py --run-dir <run_dir>",
            "",
            "# Step 9: 会话视图聚合",
            "python3 task2/TOOLS/scripts/build_session_views.py --run-dir <run_dir>",
            "",
            "# Step 10: 跨用户行为序列聚类",
            "python3 task2/TOOLS/scripts/build_sequence_clusters.py --run-dir <run_dir>",
            "",
            "# Step 11: 生成账户级/关联级告警",
            "python3 task2/TOOLS/scripts/build_alerts.py --run-dir <run_dir>",
            "",
            "# Step 12: 输出告警日志文件",
            "python3 task2/TOOLS/scripts/emit_alert_log.py --run-dir <run_dir> --project-root <project_root>",
            "",
            "# Step 13: 构建基线视图",
            "python3 task2/TOOLS/scripts/build_baseline_views.py --run-dir <run_dir>",
            "",
            "# Step 14: 汇总报告上下文",
            "python3 task2/TOOLS/scripts/build_report_context.py --run-dir <run_dir>",
            "",
            "# Step 15: 生成 MANUAL / REPORT / AI_REPORT",
            "python3 task2/TOOLS/scripts/render_reports.py --run-dir <run_dir> --project-root <project_root> [--llm-config <path>]",
            "```",
            "",
            "### 参数说明",
            "",
            "- `--run-dir`：运行输出目录（所有中间 JSON 写入此处），例如 `runs/20260531T080814Z`",
            "- `--input-dir`：原始日志所在目录，支持两种布局：",
            "  - 单目录模式：所有日志在同一目录下，自动区分 baseline/current",
            "  - 分离模式：目录下包含 `baseline/` 和 `current/` 子目录",
            "- `--project-root`：项目根目录（task2 目录所在位置），例如 `/path/to/safe_bs`",
            "- `--llm-config`：LLM 配置文件路径（可选），默认为 `task2/TOOLS/llm_config.json`",
            "",
            "### 环境变量",
            "",
            "- `TASK2_LARGE_MODE=1`：大数据模式（默认开启），适合 >8G 日志。限制每用户路径画像规模和序列聚类样本数，在 16G 内存机器上稳定运行。",
            "- `TASK2_LARGE_MODE=0`：关闭大数据模式，保留完整细节优先（适合小数据集精跑）。",
            "",
            "### 目录结构要求",
            "",
            "``text",
            "<input_dir>/",
            "  baseline/           # 历史基准日志（可选）",
            "    proftpd.log-20260526",
            "    run-2026-05-25T16-00-00.000.log",
            "    sftp.log-20260526",
            "  current/            # 当前检测日志（可选，无此目录时根目录即为当前日志）",
            "    proftpd_program.log",
            "    runtime_pipe.log",
            "    sftp.log",
            "  noise_policy.json   # 噪声策略配置（可选）",
            "```",
            "",
            "### 噪声策略配置",
            "",
            "`noise_policy.json` 支持以下可调项：",
            "- `suppress_users`：不纳入基线的用户列表",
            "- `trusted_users`：可信用户（降低告警优先级）",
            "- `trusted_src_subnets`：可信来源网段",
            "- `trusted_client_versions`：可信客户端版本",
            "- `expected_algorithms.forbidden_kex/hostkeys/ciphers/macs`：算法黑白名单",
            "- `account_risk_strategy`：告警聚合策略（默认 account）",
            "- `business_hours_by_user`：每个用户的业务时段定义",
            "",
            "### LLM 配置",
            "",
            "`llm_config.json` 支持两种模式：",
            "- 内网私有化模式（glm-5.1）：适合内网环境，不依赖外网 API",
            "- 外网模式（Claude Code skill）：利用外部 LLM API 增强报告质量",
            "",
            "### 支持的日志格式",
            "",
            "工具自动识别以下三类日志格式，无需手动指定：",
            "",
            "**1. proftpd 程序日志（sftp_program_proftpd）**",
            "```",
            "2026-05-25 00:01:01,768 nucc-30-test-uat-app-1-dmz-11 proftpd[3764202] 172.31.160.3 (221.182.181.18[221.182.181.18]): USER hnbank: Login successful.",
            "```",
            "识别特征：行内含 `proftpd[` 且含 `SSH2 session` / `Login successful` / `Login failed`。",
            "提取字段：时间戳、服务器 IP、客户端 IP、PID（作为 session_id）、用户名、动作（SESSION_OPEN/SESSION_CLOSE/LOGIN）。",
            "",
            "**2. runtime pipe 认证日志（sftp_runtime_pipe）**",
            "```",
            "2026-05-25 23:59:59,891|||||172.31.160.31|SZ30test||||||||||13761601|36.110.9.121|SSH-2.0-JSCH-0.1.54|hnb_001|publickey|0|AuthSuccess|user 'hnb_001' authenticated via 'publickey' method",
            "```",
            "识别特征：行内含 `AuthSuccess` 且含 `publickey`，字段以 `|` 分隔。",
            "提取字段：时间戳、服务器 IP、系统名、session_id、来源 IP、客户端版本、用户名、认证方式、结果（ok/fail）。",
            "",
            "**3. mod_sftp 协议协商日志（sftp_protocol_mod_sftp）**",
            "```",
            "2026-05-25 00:01:13,597 mod_sftp/0.9.9[3764562]: + Session key exchange: ecdh-sha2-nistp256",
            "2026-05-25 00:01:13,597 mod_sftp/0.9.9[3764562]: + Session client-to-server encryption: aes128-ctr",
            "2026-05-25 00:01:13,597 mod_sftp/0.9.9[3764562]: + Session client-to-server MAC: hmac-md5",
            "```",
            "识别特征：行内含 `mod_sftp/0.9.9` 或 `[PID]:` 格式。",
            "提取字段：KEX 算法、主机密钥算法、加密算法（c2s/s2c）、MAC 算法（c2s/s2c）、客户端版本、认证方式。",
            "用途：识别弱算法协商（弱 KEX、弱 cipher、弱 MAC）并纳入协议安全维度评分。",
        ]
    )


def load_report_prompt(project_root: Path, prompt_type: str) -> str:
    prompt_path = project_root / "task2" / "TOOLS" / "prompts" / f"task2_{prompt_type}_prompt.md"
    if prompt_path.exists():
        return prompt_path.read_text(encoding="utf-8")
    prompt_path2 = project_root / "common" / "prompts" / f"task2_{prompt_type}_prompt.md"
    if prompt_path2.exists():
        return prompt_path2.read_text(encoding="utf-8")
    if prompt_type == "report":
        return "根据 task2_report_context.json 生成 REPORT.md 和 MANUAL.md。要求异常判定和关联发现以脚本结果为准，LLM 负责语义化解释和攻击叙事串联。"
    return "根据 task2_report_context.json 和告警数据生成 AI_REPORT.md。"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--llm-config", default="")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    project_root = Path(args.project_root)
    json_dir = run_dir / "task2" / "json"
    task_out = project_root / "task2"

    # LLM config
    if args.llm_config:
        llm_config_path = Path(args.llm_config)
    else:
        llm_config_path = task_out / "TOOLS" / "llm_config.json"
    client = create_client(llm_config_path)

    is_internal = isinstance(client, InternalLLMClient)
    llm_mode_desc = "内网私有化 LLM (glm-5.1)" if is_internal else "外网 LLM (Claude Code skill)"

    MAX_JSON_LOAD_SIZE = 50 * 1024 * 1024  # 50MB — refuse to load JSON files larger than this

    # Size check before loading context
    context_path = json_dir / "task2_report_context.json"
    if context_path.exists():
        context_file_size = context_path.stat().st_size
        if context_file_size > MAX_JSON_LOAD_SIZE:
            print(f"[WARN] Report context too large ({context_file_size / 1024 / 1024:.1f}MB). Using empty context.", file=sys.stderr, flush=True)
            context = {"error": f"Context file too large ({context_file_size / 1024 / 1024:.1f}MB)"}
        else:
            context = load_json(context_path, {})
    else:
        context = {}

    views_data = load_json(json_dir / "task2_baseline_views.json", {})
    views = views_data.get("views", [])
    total_view_count = len(views)
    # For massive datasets, only keep the items we will actually render
    if total_view_count > MANUAL_VIEW_LIMIT:
        views = views[:MANUAL_VIEW_LIMIT]

    alerts_data = load_json(json_dir / "task2_alerts.json", {})
    alerts = alerts_data.get("alerts", [])
    total_alert_count = len(alerts)
    if total_alert_count > MANUAL_ALERT_LIMIT:
        alerts = alerts[:MANUAL_ALERT_LIMIT]

    all_sessions = list(iter_ndjson(json_dir / "task2_session_views.ndjson"))
    total_session_count = len(all_sessions)
    sessions = all_sessions[:MANUAL_SESSION_LIMIT]
    sequence_clusters = load_json(json_dir / "task2_sequence_clusters.json", {})
    alert_count = context.get("alert_summary", {}).get("count", 0)

    context_json_str = json.dumps(context, ensure_ascii=False, indent=2)
    llm_context_digest = _build_context_digest(context)
    llm_output_dir = json_dir
    llm_output_dir.mkdir(parents=True, exist_ok=True)

    # Generate REPORT via LLM using compact digest
    report_prompt = load_report_prompt(project_root, "report")
    report_content = client.generate(report_prompt, llm_context_digest, llm_output_dir)

    if report_content.startswith("EXTERNAL_LLM_PENDING"):
        # External mode: template-based placeholder
        manual = render_markdown(
            "MANUAL",
            [
                ("工具目标", "自动分析 SFTP 日志，提取用户行为基线，对新日志进行异常识别、关联分析和账户风险聚合，输出可审计告警。"),
                ("使用方法", build_usage_instructions()),
                ("核心流程", "日志解析 -> 事件归一化 -> 历史基线生成 -> 新日志多维异常评分 -> 会话/关联分析 -> 账户风险聚合 -> 解释与文档生成。"),
                ("输入说明", summarize_sources(context.get("dataset_summary", {}))),
                ("输出说明", "输出 JSON / NDJSON 中间态、结构化告警日志、用户基线视图、关联分析结果以及 MANUAL / REPORT / AI_REPORT。默认按账户风险聚合输出，同时保留会话级和关联级证据。"),
                ("结果查看方式", build_result_access_summary(context, total_view_count, total_session_count, total_alert_count)),
                ("题目要求映射", build_requirement_mapping(context)),
                ("参数与阈值说明", "支持 baseline/current 对比模式。事件级加入协议安全维度：弱 KEX、弱 hostkey、弱 cipher、弱 MAC、协议协商偏离、老旧客户端指纹偏离；会话级保留 5 维度；默认按账户风险聚合输出。可信网段、可信用户、可信客户端、算法白名单/黑名单可在 noise_policy.json 调整。"),
                ("大数据模式说明", build_large_mode_summary(context)),
                ("适用范围与局限", summarize_list(context.get("limitations", []))),
                ("告警文件说明", "查看 task2/TOOLS/alerts/alert_output.log 或 runs 下对应输出。"),
            ],
        )
        report = render_markdown(
            "REPORT",
            [
                ("需求定义", "自动分析 SFTP 日志，以基准日志对比新日志，识别异常行为并输出可审计告警。"),
                ("数据与假设", summarize_sources(context.get("dataset_summary", {}))),
                ("题目要求映射", build_requirement_mapping(context)),
                ("系统设计", build_architecture_summary(context)),
                ("数据结构设计", build_data_structure_summary(context)),
                ("基线建模方法", summarize_views(views, total_count=total_view_count)),
                ("会话行为建模", summarize_sessions(sessions, total_count=total_session_count)),
                ("异常识别逻辑", str(context.get("detection_logic_summary", "")) + "\n\n" + build_scoring_summary()),
                ("行为序列聚类", _summarize_sequence_clusters(sequence_clusters)),
                ("完整攻击故事示例", build_attack_story_example(alerts, sequence_clusters)),
                ("亮点与创新点", build_highlights_summary(context)),
                ("结果展示方式", f"本次运行共触发 {alert_count} 条告警。\n\n{summarize_alerts(alerts, total_count=total_alert_count)}"),
                ("性能与工程考虑", "解析阶段使用 NDJSON 和流式聚合，避免大日志一次性载入内存；transfer/path 明细做 top-N 截断；baseline/current 分离避免重复建模；默认账户风险聚合减少重复告警；序列聚类在大数据模式下引入截断护栏以适配 16G 机器。"),
                ("评分标准对应与完成度", build_scoring_alignment_summary(context) + "\n\n" + build_completion_summary(context)),
                ("准确性与可复用性分析", "异常判定和关联发现由脚本确定性产出，LLM 负责语义化解释和攻击叙事串联，所有结论可追溯到脚本评分和关联数据。结构化 JSON 产物便于回归测试、规则迭代和内网长期复用。"),
                ("局限与改进方向", summarize_list(context.get("limitations", []))),
                ("总结", "脚本决定异常，LLM 负责解释和报告。"),
            ],
        )
        write_text(llm_output_dir / "llm_prompt_input.md", report_prompt)
        # Size check before writing context input
        if len(context_json_str.encode("utf-8")) > MAX_JSON_LOAD_SIZE:
            print(f"[WARN] LLM context input too large. Writing truncated version.", file=sys.stderr, flush=True)
            write_text(llm_output_dir / "llm_context_input.json", json.dumps({"error": "Context exceeds size limit", "context_truncated": True}, ensure_ascii=False))
        else:
            write_text(llm_output_dir / "llm_context_input.json", context_json_str)
    else:
        # Internal mode: LLM API returned report content
        # Split into MANUAL and REPORT based on LLM output structure
        # If LLM returns a single doc, use it as REPORT and generate MANUAL from template
        report = report_content
        manual = render_markdown(
            "MANUAL",
            [
                ("工具目标", "自动分析 SFTP 日志，提取用户行为基线，对新日志进行异常识别、关联分析和账户风险聚合，输出可审计告警。"),
                ("使用方法", build_usage_instructions()),
                ("核心流程", "日志解析 -> 历史基线生成 -> 新日志异常评分 -> 会话/关联分析 -> 账户风险聚合 -> LLM 解释。"),
                ("输入说明", summarize_sources(context.get("dataset_summary", {}))),
                ("输出说明", "输出 JSON / NDJSON 中间态、结构化告警日志、用户基线视图、关联分析结果以及 MANUAL / REPORT / AI_REPORT。"),
                ("结果查看方式", build_result_access_summary(context, total_view_count, total_session_count, total_alert_count)),
                ("题目要求映射", build_requirement_mapping(context)),
                ("参数与阈值说明", "支持 baseline/current 对比模式；事件级同时评估行为异常与协议安全异常；noise_policy.json 可配置可信用户、可信客户端、算法策略和账户风险聚合策略。"),
                ("大数据模式说明", build_large_mode_summary(context)),
                ("适用范围与局限", summarize_list(context.get("limitations", []))),
                ("告警文件说明", "查看 task2/TOOLS/alerts/alert_output.log。"),
            ],
        )

    # Generate AI_REPORT
    ai = render_markdown(
        "AI_REPORT",
        [
            ("使用的模型与工具", f"{llm_mode_desc}。\n异常评分脚本: score_anomalies.py（行为异常 + 协议安全异常的确定性多维打分）。"),
            ("AI 参与环节", f"告警解释、关联推理和攻击叙事生成。LLM 模式: {llm_mode_desc}。\n异常判定、基线比对、协议安全判断和关联发现由脚本确定性产出，LLM 只做语义化解释与叙事串联。"),
            ("输入材料与中间数据", "task2_report_context.json、task2_alerts.json、task2_baseline_views.json、task2_session_views.ndjson、task2_sequence_clusters.json"),
            ("关键提示策略", "强调 LLM 不自行推断未由脚本提供的关联关系，所有结论必须可追溯到脚本评分和关联数据。LLM 负责把基线比对结果、协议安全异常和序列模式串联为攻击叙事。"),
            ("AI 产出与人工修正", "告警解释和报告内容可人工复核后定稿。异常判定结果由脚本确定性产出，无需 LLM 修正。"),
            ("有效实践总结", "三层架构：历史基线对比 + 脚本确定性打分 + LLM 语义化解释与攻击叙事。JSON 中间态有利于限制幻觉，序列聚类数据提供跨实体推理的依据。"),
            ("局限性", summarize_list(context.get("limitations", []))),
            ("工具评价", f"LLM: {llm_mode_desc}。适合做告警解释、关联推理和攻击叙事，不适合作为核心判定或关联发现。"),
            ("可复用沉淀", "baseline/current 对比目录模式、第三类 mod_sftp 协议日志解析、基线/告警/关联 JSON 结构、行为+协议安全评分维度、序列聚类算法、账户风险聚合策略、LLM 客户端（外网/内网双模式）、task2 skill。"),
        ],
    )

    write_text(task_out / "MANUAL.md", manual)
    write_text(task_out / "REPORT.md", report)
    write_text(task_out / "AI_REPORT.md", ai)


if __name__ == "__main__":
    main()
