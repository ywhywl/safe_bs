# AI_REPORT

## 使用的模型与工具

题 1 允许外网 LLM，使用 Claude (glm-5.1) 模型。

工具清单：
- nc (netcat) — 端口探测、banner 抓取
- ssh/sftp (OpenSSH 8.6) — 认证测试、密钥指纹获取
- Python 3.12 + paramiko 5.0.0 — SSH 协议深度分析
- nmap 7.92 — 端口扫描
- searchsploit (exploitdb) — 漏洞情报查询

## AI 参与环节

1. 服务识别与版本推断（banner 解析、ProFTPD vs OpenSSH 区分）
2. SSH KEXINIT 报文解析与弱算法标注
3. 漏洞候选归纳（CVE 映射、CVSS 评级）
4. 验证思路整理（攻击路径分析、可达性判断）
5. 报告起草（ATT_REPORT.md 全文）

## 输入材料与中间数据

- task1_recon_facts.json（服务画像、算法协商、弱算法列表）
- task1_vuln_hypotheses.json（6 项漏洞候选）
- searchsploit_proftpd.json（ProFTPD 1.3.5 漏洞 4 条）
- SSH 协议交互原始记录

## 关键提示策略

- 强调事实、假设、验证结果分离
- 区分「软件含漏洞」与「当前可利用」
- 标注所有弱算法及其攻击场景（MITM 前提）
- 对 CVE-2015-3306 明确标注 FTP 端口不可达的限制

## AI 产出与人工修正

- CVE-2015-3306 影响：AI 评 Critical，人工确认 FTP 不可达但漏洞确实存在
- CVE-2011-1137：AI 评 High，人工验证发现原始 PoC 不崩溃但超长字符串部分 DoS
- 加密配置缺陷：AI 评 High（需 MITM），人工确认协商数据准确
- ProFTPD 版本：用户纠正为 1.3.5e（非 1.3.5），AI 更新所有引用

## 有效实践总结

- 使用结构化 KEXINIT 解析替代主观判断
- 使用 searchsploit 交叉验证 CVE 信息
- 先识别服务再映射漏洞，避免盲目枚举

## 局限性

- 无法完成完整 SSH 密钥交换（paramiko 不兼容 ssh-rsa/ssh-dss 主机密钥协商）
- auth_none 测试未能绕过公钥认证
- 无法验证 mod_copy 是否可通过 SFTP 通道触发
- 无法从外网验证 MITM 类攻击（弱算法需 MITM 前提）

## 工具评价

- LLM 适合归纳漏洞候选和起草报告，不适合作为唯一判定器
- paramiko 在弱算法兼容性方面受限
- nc + Python 原始 socket 更适合协议级测试

## 可复用沉淀

- KEXINIT 算法解析 Python 代码
- 弱算法标注模板（CBC/MD5/SHA1/DSA/group1）
- ProFTPD mod_sftp 漏洞映射表
- task1 skill、模板、JSON 模式

## 工具使用方法

### 独立运行（推荐）

工具已自包含，无需配置外部 PYTHONPATH：

```bash
cd task1/TOOLS

# 基本用法：对单个目标运行完整侦察与报告流水线
bash run.sh <TARGET_IP>

# 示例
bash run.sh 120.133.131.108

# 指定端口和授权范围
PORTS=22 SCOPE="authorized testing only" bash run.sh 120.133.131.108

# 使用已有侦察数据（跳过网络采集）
RECON_INPUT_DIR=/path/to/raw bash run.sh 120.133.131.108
```

### 参数说明

| 参数 | 方式 | 默认值 | 说明 |
|---|---|---|---|
| TARGET | 位置参数 $1 | 127.0.0.1 | 目标 IP 或主机名 |
| PORTS | 环境变量 | 22 | 扫描端口，逗号分隔 |
| SCOPE | 环境变量 | authorized testing only | 授权范围说明 |
| WINDOW | 环境变量 | （空） | 测试时间窗口 |
| NETWORK_PATH | 环境变量 | external | 网络路径（external/internal） |
| RECON_INPUT_DIR | 环境变量 | （空） | 已有侦察数据目录，非空时跳过网络采集 |
| RUN_ID | 环境变量 | 时间戳 | 运行 ID，输出写入 runs/<RUN_ID>/ |

### 输出位置

```text
task1/TOOLS/runs/<RUN_ID>/task1/
  json/          # 中间 JSON（目标画像、漏洞假设、验证结果等）
  evidence/      # 证据文件
  raw/           # 原始侦察输出
task1/ATT_REPORT.md   # 攻击报告（自动刷新）
task1/AI_REPORT.md    # AI 使用报告（自动刷新）
```

### 依赖

- Python 3.9+（无需额外安装，lib.py/llm_client.py 已内置于 scripts/）
- nc、ssh、nmap（可选，用于网络侦察；RECON_INPUT_DIR 模式下不需要）
- searchsploit（可选，用于漏洞情报查询）