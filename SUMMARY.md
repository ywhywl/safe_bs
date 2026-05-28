# 安全赛题工作台

本项目实现三道安全赛题的统一工作流，采用 `Python + Shell + JSON + Markdown + Skill` 的结构。

核心设计：

- Shell 负责采集、调度和打包
- Python 负责解析、统计、规则判断、JSON 生成与报告渲染
- JSON 作为唯一中间态
- LLM 读取结构化上下文，生成解释和文档
- Skill 固化流程、检查清单和报告约束

三题输出形式：

- 题 1：授权漏洞评估与攻击报告
- 题 2：SFTP 异常行为识别与说明文档
- 题 3：Nginx 只读安全巡检与防护报告

详细方案见 [docs/solution_plan.md](docs/solution_plan.md)。
