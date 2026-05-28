# 安全赛题整体方案

## 1. 目标与约束

本方案面向三道赛题：

1. 题目 1：攻击 SFTP
2. 题目 2：SFTP 异常行为识别
3. 题目 3：Nginx 安全防护

方案目标：

- 使用大模型、脚本、skills 形成可复现工作流
- 不引入 RAG、数据库、消息队列等额外复杂依赖
- 使用本地 JSON 作为唯一中间态
- 最终交付严格贴合题目要求
- 当前阶段只固化方案，不进入具体代码实现

技术路线约束：

- 允许使用 `Python + Shell`
- 题 1 可使用外网 LLM
- 题 2、题 3 优先使用内网私有化 LLM

## 2. 与题目要求的一致性

### 2.1 已对齐部分

- 三题均拆分为独立交付物，而不是混合为一个系统
- 三题均保留 `AI_REPORT.md`
- 三题均采用“脚本产出 JSON，LLM 读取 JSON，总结并生成 Markdown 报告”的结构
- 已明确 skill 的职责是固化流程、模板和检查清单

### 2.2 需要在实现阶段明确保留的点

题 1：

- 题面提到“源码扫描、漏洞收集、AI 攻击嗅探”
- 如果有源码或安装包，需要在流程中显式加入源码或静态审视步骤
- 如果没有源码，需要在报告中明确说明本次采用的是服务特征、公开漏洞情报、协议行为特征组合判断

题 2：

- 题面要求“告警可按网联日志规范打印到指定日志文件模拟”
- 实现时必须产出一个独立的模拟告警文件，例如 `alerts/alert_output.log`
- 题面要求“提供查看用户基线的方式”
- 实现时必须提供独立的基线查看视图文件，例如 `task2_baseline_views.json`

题 3：

- 题面要求 `TOOLS` 目录中包含规则库、脚本、软件工具等
- 实现时需要显式存在 `TOOLS/rules/`

此外：

- 最终提交时，实际用到的 skill 副本建议也放入各题 `TOOLS/skills/`

## 3. 总体架构

采用统一结构：

- `Shell`：负责采集、调度、打包
- `Python`：负责解析、抽取事实、规则判断、统计、JSON 生成、报告渲染、LLM 调用
- `JSON`：作为唯一中间态
- `Skill`：作为流程和报告模板的固化资产
- `Markdown`：作为最终交付形式

总体执行链路：

1. 原始输入采集
2. Python 解析并生成结构化 JSON
3. Python 汇总 `report_context.json`
4. LLM 读取脱敏后的结构化上下文
5. 输出主报告与 `AI_REPORT.md`
6. 打包至每题 `TOOLS/`

## 4. LLM / 脚本 / Skill 分工

### 4.1 通用原则

- 脚本负责确定性工作
- LLM 负责理解、归纳、解释、优先级与文档
- Skill 负责流程约束、输入输出定义、报告模板

### 4.2 题 1 分工

脚本：

- 服务识别与事实采集
- 原始证据留存
- 漏洞候选结构化整理
- 验证时间线记录
- 结果确认与证据索引生成

外网 LLM：

- 漏洞候选归纳
- 验证逻辑与影响说明
- `ATT_REPORT.md` 起草
- `AI_REPORT.md` 起草

Skill：

- 强制执行“识别 -> 候选 -> 验证计划 -> 验证 -> 固证 -> 报告”
- 强制区分事实、假设、验证结果

### 4.3 题 2 分工

脚本：

- 日志解析
- 用户基线生成
- 异常评分
- 告警归并
- 模拟告警文件输出

内网 LLM：

- 告警解释
- 典型案例总结
- `MANUAL.md` 与 `REPORT.md` 起草
- `AI_REPORT.md` 起草

Skill：

- 强制执行“事件层 -> 基线 -> 打分 -> 告警 -> 解释 -> 报告”
- 强制规定异常结论只能来自脚本

### 4.4 题 3 分工

脚本：

- 只读采集结果解析
- 配置事实抽取
- 规则匹配
- 风险登记

内网 LLM：

- 风险归纳
- 优先级整理
- 修复建议生成
- `DEF_REPORT.md` 与 `AI_REPORT.md` 起草

Skill：

- 强制执行“只读采集 -> 配置事实 -> 规则命中 -> 风险登记 -> 报告”
- 强制要求所有风险可追溯到证据

## 5. 最终交付形式

推荐最终呈现为：

- 命令行驱动
- JSON 留痕
- Markdown 交付

不是聊天机器人，也不需要复杂 Web 平台。

评委视角的交付顺序：

1. `SUMMARY.md`
2. 每题主报告
3. 每题 `TOOLS/json/` 中关键中间态
4. 每题 `AI_REPORT.md`

## 6. 项目目录骨架

```text
project/
  SUMMARY.md
  skills/
    challenge-intake/
      SKILL.md
    task1-vuln-assessment/
      SKILL.md
    task2-sftp-anomaly/
      SKILL.md
    task3-nginx-audit/
      SKILL.md
    ai-report-writer/
      SKILL.md
  common/
    prompts/
    schemas/
    templates/
  bin/
    run_task1.sh
    run_task2.sh
    run_task3.sh
  scripts/
    common/
    task1/
    task2/
    task3/
  task1/
    ATT_REPORT.md
    AI_REPORT.md
    TOOLS/
      scripts/
      skills/
      json/
      evidence/
      prompts/
  task2/
    MANUAL.md
    REPORT.md
    AI_REPORT.md
    TOOLS/
      scripts/
      skills/
      json/
      samples/
      prompts/
      alerts/
  task3/
    DEF_REPORT.md
    AI_REPORT.md
    TOOLS/
      scripts/
      skills/
      json/
      evidence/
      prompts/
      rules/
  runs/
    <run_id>/
      task1/
      task2/
      task3/
      evidence/
      logs/
```

## 7. Skill 设计

保留 5 个 skill 即可：

1. `challenge-intake`
2. `task1-vuln-assessment`
3. `task2-sftp-anomaly`
4. `task3-nginx-audit`
5. `ai-report-writer`

统一 `SKILL.md` 结构：

1. `Purpose`
2. `When to use`
3. `Inputs`
4. `Workflow`
5. `Outputs`
6. `Guardrails`
7. `Report expectations`

关键约束：

题 1：

- 必须先确认服务身份，再做漏洞映射
- 必须把事实、假设、验证结果分开
- 外网 LLM 只能读取脱敏后的 `report_context`

题 2：

- 异常判定只能来自脚本
- LLM 只负责解释，不负责最终异常结论
- 必须输出用户基线查看视图和告警文件

题 3：

- 只能基于只读证据判断
- 每个问题必须可回溯到证据位置
- 需要显式规则库

## 8. JSON 中间态设计

### 8.1 通用元字段

所有 JSON 建议统一保留：

- `run_id`
- `task_id`
- `created_at`
- `operator`
- `source_type`
- `source_name`
- `confidence`
- `evidence_refs`
- `manual_review_required`
- `notes`

### 8.2 通用附加 JSON

三题共用 3 个辅助文件：

- `tool_manifest.json`
- `ai_usage_trace.json`
- `package_manifest.json`

用途：

- `tool_manifest.json`：记录脚本、shell 命令、skill、模型和工具
- `ai_usage_trace.json`：记录模型调用与人工修订轨迹
- `package_manifest.json`：记录最终交付包内容及用途

### 8.3 题 1 JSON

建议文件：

- `task1_target_profile.json`
- `task1_recon_facts.json`
- `task1_vuln_hypotheses.json`
- `task1_validation_plan.json`
- `task1_execution_timeline.json`
- `task1_validation_results.json`
- `task1_evidence_index.json`
- `task1_report_context.json`

### 8.4 题 2 JSON

建议文件：

- `task2_log_ingest_manifest.json`
- `task2_events.json`
- `task2_user_baselines.json`
- `task2_anomaly_scores.json`
- `task2_alerts.json`
- `task2_baseline_views.json`
- `task2_report_context.json`

另需输出：

- `alerts/alert_output.log`

### 8.5 题 3 JSON

建议文件：

- `task3_host_profile.json`
- `task3_nginx_inventory.json`
- `task3_config_facts.json`
- `task3_rule_hits.json`
- `task3_risk_register.json`
- `task3_report_context.json`

## 9. 三题端到端流程

### 9.1 题 1

```text
题面解析
-> 边界确认
-> 目标画像
-> 原始采集
-> 事实抽取
-> 漏洞候选
-> 最小化验证计划
-> 授权验证与时间线记录
-> 结果确认
-> 证据索引
-> 报告上下文
-> 外网 LLM 生成 ATT_REPORT.md / AI_REPORT.md
-> 人工复核与脱敏
-> 打包
```

### 9.2 题 2

```text
题面解析
-> 日志登记
-> 事件归一化
-> 用户基线生成
-> 异常评分
-> 告警归并
-> 基线查看视图
-> 模拟告警日志
-> 报告上下文
-> 内网 LLM 生成 MANUAL.md / REPORT.md / AI_REPORT.md
-> 人工复核
-> 打包
```

### 9.3 题 3

```text
题面解析
-> 巡检边界确认
-> 主机与站点画像
-> 只读采集
-> 资产清单
-> 配置事实
-> 规则命中
-> 风险登记
-> 报告上下文
-> 内网 LLM 生成 DEF_REPORT.md / AI_REPORT.md
-> 人工复核高风险项
-> 打包
```

## 10. 报告映射

### 10.1 题 1 `ATT_REPORT.md`

建议章节：

1. 执行摘要
2. 测试边界与授权说明
3. 目标识别与服务研判
4. 漏洞发现过程
5. 验证思路
6. 验证结果与成果
7. 影响分析
8. 关键证据索引
9. 修复与缓解建议
10. 附录

主要来源：

- `task1_target_profile.json`
- `task1_recon_facts.json`
- `task1_vuln_hypotheses.json`
- `task1_validation_plan.json`
- `task1_execution_timeline.json`
- `task1_validation_results.json`
- `task1_evidence_index.json`
- `task1_report_context.json`

### 10.2 题 2 `MANUAL.md`

建议章节：

1. 工具目标
2. 输入说明
3. 输出说明
4. 核心流程
5. 用户基线查看方式
6. 告警解释方式
7. 参数与阈值说明
8. 适用范围与局限
9. 告警文件说明

主要来源：

- `task2_log_ingest_manifest.json`
- `task2_anomaly_scores.json`
- `task2_alerts.json`
- `task2_baseline_views.json`
- `task2_report_context.json`

### 10.3 题 2 `REPORT.md`

建议章节：

1. 需求定义
2. 数据与假设
3. 系统设计
4. 数据结构设计
5. 基线建模方法
6. 异常识别逻辑
7. 结果展示方式
8. 准确性与可复用性分析
9. 局限与改进方向
10. 总结

主要来源：

- `task2_log_ingest_manifest.json`
- `task2_events.json`
- `task2_user_baselines.json`
- `task2_anomaly_scores.json`
- `task2_alerts.json`
- `task2_baseline_views.json`
- `task2_report_context.json`

### 10.4 题 3 `DEF_REPORT.md`

建议章节：

1. 执行摘要
2. 检查边界与方法
3. 资产与配置概况
4. 风险发现清单
5. 高风险问题详述
6. 中低风险问题概述
7. 整体防护评估
8. 加固建议路线图
9. 证据索引
10. 附录

主要来源：

- `task3_host_profile.json`
- `task3_nginx_inventory.json`
- `task3_config_facts.json`
- `task3_rule_hits.json`
- `task3_risk_register.json`
- `task3_report_context.json`

### 10.5 通用 `AI_REPORT.md`

建议章节：

1. 使用的模型与工具
2. AI 参与环节
3. 输入材料与中间数据
4. 关键提示策略
5. AI 产出与人工修正
6. 有效实践总结
7. 局限性
8. 工具评价
9. 可复用沉淀

主要来源：

- `tool_manifest.json`
- `ai_usage_trace.json`
- `package_manifest.json`
- 各题 `report_context.json`

## 11. Python + Shell 实现建议

### 11.1 为什么选 Python + Shell

优点：

- 适合文本处理、日志解析、JSON 生成、Markdown 渲染
- 适合快速迭代
- 基本可依赖标准库完成
- Shell 方便进行系统命令调用与只读采集

不建议当前阶段使用 Go 作为主力语言，原因：

- 文本与日志处理更重
- 快速调整报告链路与 JSON 结构不如 Python 灵活
- 当前赛题更偏原型、证据链和文档，而非长期服务进程

### 11.2 依赖策略

默认目标：

- Python 标准库优先
- 第三方依赖尽量为零

可接受的轻依赖仅作为备选：

- `jinja2`
- `pyyaml`

但第一版推荐都不使用。

### 11.3 Shell 职责

- 启动每题流程
- 执行常见系统命令
- 保存原始输出
- 调用 Python 主脚本
- 打包交付目录

### 11.4 Python 职责

- 解析原始输出
- 生成结构化 JSON
- 进行规则判断与统计
- 生成报告上下文
- 调用模型并记录 AI 使用轨迹
- 渲染 Markdown

## 12. 最小可行实现范围

### 12.1 题 1

第一版必须有：

- 目标画像
- 原始事实采集与结构化
- 漏洞候选
- 验证时间线
- 结果确认
- 证据索引
- `ATT_REPORT.md`
- `AI_REPORT.md`

第一版不做：

- 自动化多目标验证
- 复杂利用链编排
- 仪表盘

### 12.2 题 2

第一版必须有：

- 单一日志格式支持
- 事件归一化
- 用户基线
- 异常评分
- 告警文件
- 基线查看视图
- `MANUAL.md`
- `REPORT.md`
- `AI_REPORT.md`

第一版不做：

- 在线学习
- 自动阈值调优
- 多格式自动识别
- 可视化页面

### 12.3 题 3

第一版必须有：

- 只读采集结果输入
- 配置事实抽取
- 规则命中
- 风险登记
- `DEF_REPORT.md`
- `AI_REPORT.md`

第一版不做：

- 自动修复
- 主动漏洞扫描
- 大规模并发巡检

## 13. 脚本清单与输入输出约定

### 13.1 Shell 入口

```text
bin/run_task1.sh
bin/run_task2.sh
bin/run_task3.sh
```

职责：

- 生成 `run_id`
- 准备目录
- 触发采集
- 调用 Python 主流程
- 打包 `TOOLS/`

### 13.2 通用 Python 脚本

```text
scripts/common/json_store.py
scripts/common/evidence.py
scripts/common/markdown_render.py
scripts/common/ai_trace.py
scripts/common/package_manifest.py
```

### 13.3 题 1 脚本

```text
scripts/task1/init_target_profile.py
scripts/task1/collect_recon.sh
scripts/task1/parse_recon.py
scripts/task1/build_hypotheses.py
scripts/task1/record_timeline.py
scripts/task1/build_validation_results.py
scripts/task1/build_evidence_index.py
scripts/task1/build_report_context.py
scripts/task1/render_reports.py
```

### 13.4 题 2 脚本

```text
scripts/task2/ingest_logs.py
scripts/task2/normalize_events.py
scripts/task2/build_baseline.py
scripts/task2/score_anomalies.py
scripts/task2/build_alerts.py
scripts/task2/emit_alert_log.py
scripts/task2/build_baseline_views.py
scripts/task2/build_report_context.py
scripts/task2/render_reports.py
```

### 13.5 题 3 脚本

```text
scripts/task3/collect_readonly.sh
scripts/task3/build_inventory.py
scripts/task3/parse_config_facts.py
scripts/task3/apply_rules.py
scripts/task3/build_risk_register.py
scripts/task3/build_report_context.py
scripts/task3/render_reports.py
```

## 14. 推荐实现顺序

建议顺序：

1. 先搭骨架目录、JSON 结构、模板和 skills
2. 先做题 2，形成第一条完整闭环
3. 再做题 3，形成规则化安全巡检能力
4. 最后做题 1 的授权验证、固证和报告链路

原因：

- 题 2 最容易先做出完整成果
- 题 3 最容易体现工程能力
- 题 1 最敏感，适合最后收口

## 15. 下一步

当前文档用于固化方案。

待确认后，再进入具体实现阶段。实现阶段建议先创建：

- 目录骨架
- 统一 JSON 结构说明
- 通用模板
- 三题 shell 入口
- 三题最小 JSON 生产链路
