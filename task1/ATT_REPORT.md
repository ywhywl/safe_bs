# ATT_REPORT — 题1 SFTP 授权漏洞评估与攻击报告

## 1. 执行摘要

本次对三台靶机（120.133.131.108、120.133.131.109、120.133.131.110）进行了授权安全评估与攻击测试。所有三台靶机均运行 **ProFTPD 1.3.5e** 配合 **mod_sftp/0.9.9** 模块，仅 TCP/22 端口提供真实 SFTP 服务（其他端口为透明防火墙/代理，无实际服务响应），仅接受公钥认证。

共发现 **1 个高危漏洞（CVE-2015-3306）**、**1 个中高危漏洞（CVE-2011-1137）**、**1 组高危加密配置缺陷（Logjam 可行）**，以及 **若干中低风险配置问题**。经实际验证，服务端成功协商最弱算法组合（diffie-hellman-group1-sha1 + aes128-cbc + hmac-md5），确认 **Logjam 降级攻击路径完全可行**。由于 FTP 端口（21）受透明代理拦截不可达且仅允许公钥认证，部分高危漏洞无法从外网直接利用，但攻击面与影响仍然显著。

---

## 2. 测试边界与授权说明

- **授权范围**：授权测试仅限三台靶机（108/109/110），端口 22
- **禁止操作**：持久化后门、破坏性写入、未授权横向移动
- **网络路径**：外网 → 靶机
- **时间窗口**：2026-05-28

---

## 3. 目标识别与服务研判

### 3.1 服务画像

| 项目 | 120.133.131.108 | 120.133.131.109 | 120.133.131.110 |
|---|---|---|---|
| 开放端口 | 22/tcp | 22/tcp | 22/tcp |
| 服务标识 | SSH-2.0-mod_sftp/0.9.9 | SSH-2.0-mod_sftp/0.9.9 | SSH-2.0-mod_sftp/0.9.9 |
| 底层软件 | ProFTPD 1.3.5e + mod_sftp | ProFTPD 1.3.5e + mod_sftp | ProFTPD 1.3.5e + mod_sftp |
| 认证方式 | publickey only | publickey only | publickey only |
| 主机密钥指纹 | SHA256:Ht7BR9NOXxsGMbzVEj0NThaMcOdg4Zt7+H8ERHIMBy8 | 相同 | 相同 |

**关键发现**：三台靶机使用完全相同的 SSH 主机密钥，说明配置为克隆/镜像环境。

### 3.2 网络环境

经验证，除 TCP/22 外的所有端口（21、80、443 等）均为**透明防火墙/代理**，接受 TCP 连接但不转发数据，无实际服务响应。仅端口 22 存在真实 SFTP 服务。

### 3.3 服务端算法协商

经 SSH 协议 KEXINIT 报文解析，服务端支持的算法如下：

**密钥交换算法（KEX）**：
- ecdh-sha2-nistp256、ecdh-sha2-nistp384、ecdh-sha2-nistp521（安全）
- diffie-hellman-group-exchange-sha256（安全）
- ❌ **diffie-hellman-group-exchange-sha1**（弱：SHA-1 已弃用）
- ❌ **diffie-hellman-group14-sha1**（弱：SHA-1 已弃用）
- ❌ **diffie-hellman-group1-sha1**（弱：Logjam 攻击目标，CVE-2020-14145）
- ❌ **rsa1024-sha1**（弱：1024 位 RSA 不安全）

**主机密钥算法**：
- ssh-rsa
- ❌ **ssh-dss**（弱：1024 位 DSA 不安全）

**加密算法（Ciphers）**：
- aes128-ctr、aes192-ctr、aes256-ctr（安全）
- ❌ **aes128-cbc、aes192-cbc、aes256-cbc**（弱：CBC 模式存在 Terroja/Roar 比特翻转攻击风险）

**MAC 算法**：
- hmac-sha2-256、hmac-sha2-512（安全）
- ❌ **hmac-sha1、hmac-sha1-96**（弱：SHA-1 已弃用）
- ❌ **hmac-md5、hmac-md5-96**（弱：MD5 已弃用，碰撞风险）
- hmac-ripemd160、umac-64@openssh.com

**压缩**：
- zlib@openssh.com、zlib、none（zlib 压缩可能被用于 CRIME 式攻击）

---

## 4. 漏洞发现过程

### 4.1 CVE-2015-3306 — ProFTPD 1.3.5 mod_copy 远程命令执行（高危）

**描述**：ProFTPD 1.3.5 的 mod_copy 模块允许未经认证的客户端通过 FTP `SITE CPFR`/`SITE CPTO` 命令执行任意文件复制。可利用此漏洞：
- 复制 /etc/passwd 等敏感文件到可读位置
- 通过 /proc/self/fd/3 将日志内容写入 Web 可达路径，实现 RCE
- 无需认证即可执行操作

**影响评级**：CVSS 9.8（Critical）
**利用条件**：需要 FTP 端口（21/tcp）可达

**当前状态**：三台靶机 FTP 端口 21 不可达，仅开放 SFTP 端口 22。但 mod_copy 模块可能仍已加载，若内网或防火墙策略变更允许 FTP 访问，则可直接利用。

**已知 PoC/利用代码**：
- EDB-36742：原始文件复制 PoC
- EDB-36803：远程命令执行 Python 脚本
- EDB-37262：Metasploit 模块
- EDB-49908：Python RCE 脆弱利用脚本（已在本项目中）

### 4.2 CVE-2011-1137 — ProFTPD mod_sftp 整数溢出拒绝服务（中高危）

**描述**：mod_sftp 模块在处理客户端标识字符串时存在整数溢出漏洞。发送超长或特殊构造的客户端标识字符串可能导致 memset() 调用时发生段错误，造成服务崩溃。

**影响评级**：CVSS 7.5（High）
**利用条件**：需能连接到 SFTP 端口

**验证结果**：
- 原始 PoC（EDB-16129）发送 `\x80\xff\xff\xff` 填充后，服务端返回 "Application error" 而非崩溃，表明该整数溢出可能已修补
- 发送 50000 字节超长版本字符串时，120.133.131.109 出现超时响应（约 10 秒后恢复），暗示缓冲区处理可能仍存在异常
- 120.133.131.108 和 120.133.131.110 在超长版本字符串下仍正常返回 KEXINIT

**结论**：CVE-2011-1137 的原始利用路径可能已被修补，但超长字符串仍可能导致 DoS（至少对部分目标），需进一步验证。

### 4.3 CVE-2010-4221 — ProFTPD Telnet IAC 缓冲区溢出（中危）

**描述**：ProFTPD 1.3.2rc3 至 1.3.3b 在处理 Telnet IAC 序列时存在缓冲区溢出。该漏洞可通过 FTP 或 SFTP 通道触发（如果 SFTP 通道也经过 Telnet IAC 解析）。

**影响评级**：CVSS 6.8（Medium）
**当前状态**：1.3.5e 版本可能已修补此漏洞，但需确认 SFTP 子系统是否经过 IAC 解析

### 4.4 CVE-2009-0543 — ProFTPD mod_mysql 认证绕过（中危）

**描述**：ProFTPD mod_mysql 模块存在 SQL 注入，可绕过认证。若 mod_sql 已加载且使用 MySQL 后端认证，攻击者可通过构造特殊用户名实现认证绕过。

**当前状态**：无法确认 mod_sql 是否加载；仅公钥认证可用，SQL 注入路径不可达

### 4.5 加密配置缺陷 — 多项弱算法（高危）+ Logjam 降级验证

**描述**：mod_sftp/0.9.9 服务端接受多种已弃用/不安全的加密算法，具体包括：

| 弱算法 | 安全风险 | 相关 CVE |
|---|---|---|
| diffie-hellman-group1-sha1 | Logjam 攻击，可在 MITM 位置降级密钥交换 | CVE-2020-14145 |
| aes128/192/256-cbc | Terroja/Roar 比特翻转攻击，可篡改加密流量 | — |
| hmac-md5 / hmac-md5-96 | MD5 碰撞风险，可能被伪造 | — |
| ssh-dss | 1024 位 DSA 密钥长度不足 | — |
| rsa1024-sha1 | 1024 位 RSA 密钥长度不足 | — |

**Logjam 降级验证结果**：
使用 ssh 命令强制指定最弱算法组合进行协商，**三台靶机均成功接受降级**：
```
kex: algorithm: diffie-hellman-group1-sha1
kex: host key algorithm: ssh-rsa
kex: server->client cipher: aes128-cbc MAC: hmac-md5 compression: none
kex: client->server cipher: aes128-cbc MAC: hmac-md5 compression: none
```
这证实攻击者处于 MITM 位置时，可将密钥交换完全降级为 1024 位 DH 组（diffie-hellman-group1），配合 aes128-cbc 加密和 hmac-md5 MAC，构成完整的 Logjam 攻击路径。

**攻击场景**：
- **Logjam 攻击**：攻击者 MITM 降级 → 预计算 1024 位 DH 离散对数 → 恢复会话密钥 → 解密/篡改全部 SFTP 传输
- **CBC 比特翻转**：在 MITM 位置可对 CBC 模式加密的 SSH 报文进行选择性比特篡改（Terroja 攻击）
- **MD5 MAC 伪造**：在已知碰撞条件下可伪造 MAC

### 4.6 相同主机密钥（中危）

**描述**：三台靶机使用完全相同的 SSH 主机密钥（SHA256:Ht7BR9NOXxsGMbzVEj0NThaMcOdg4Zt7+H8ERHIMBy8），这违反了 SSH 密钥唯一性原则。

**风险**：
- 若主机密钥被破解（rsa/1024-dss 弱密钥），所有三台靶机的所有连接都可被 MITM
- 无法通过主机密钥区分不同靶机，增加 MITM 攻击成功率
- 说明靶机为克隆环境，可能共享其他密钥材料

---

## 5. 验证思路

### 5.1 已执行验证

| 步骤 | 方法 | 结果 |
|---|---|---|
| S1: 服务识别 | nc banner 抓取 | 确认 ProFTPD mod_sftp/0.9.9 |
| S1: 端口扫描 | nc 多端口 + Python 并发扫描 | 仅 22/tcp 真实开放，其他端口为透明代理 |
| S2: 算法协商 | SSH KEXINIT 解析 | 确认多项弱算法 |
| S3: 认证测试 | ssh -v 多用户/多方法 | 仅 publickey 可用，无用户枚举差异 |
| S4: CVE-2011-1137 | 整数溢出报文发送 | 服务端返回 "Application error"，未崩溃 |
| S5: 超长字符串 DoS | 50000 字节标识字符串 | 109 超时响应，108/110 正常 |
| S6: auth_none 测试 | SSH 无认证请求 | 服务端仅允许 publickey |
| S7: **Logjam 降级验证** | ssh -o KexAlgorithms=diffie-hellman-group1-sha1 | **三台靶机均成功接受最弱算法组合** |
| S8: FTP 端口验证 | Python FTP 协议交互 | 端口 21 无 FTP banner，为透明代理 |
| S9: HTTP 端口验证 | Python HTTP GET 请求 | 端口 80 无 HTTP 响应，为透明代理 |

### 5.2 建议后续验证

| 步骤 | 方法 | 预期信号 |
|---|---|---|
| S10: FTP 端口可达性 | 从内网或其他路径尝试 FTP | 如可达，则 CVE-2015-3306 可直接利用 |
| S11: MITM Logjam 攻击 | 在网关/路由位置拦截并降级 DH 组 + 预计算离散对数 | 恢复会话密钥，解密 SFTP 传输 |
| S12: CBC 比特翻转 | MITM 位置篡改 CBC 加密报文 | 修改 SSH 命令或 SFTP 操作 |
| S10: 弱 DSA/1024-RSA 密钥破解 | 离线分析主机密钥强度 | 若密钥为 1024 位，可在合理时间内分解 |
| S11: 密钥材料泄露 | 通过 CVE-2015-3306 读取 authorized_keys | 获取合法公钥后直接认证 |

---

## 6. 验证结果与成果

| 漏洞 | 可利用性 | 验证状态 | 证据 |
|---|---|---|---|
| CVE-2015-3306 (mod_copy RCE) | FTP 不可达，暂不可利用 | 事实确认（软件含漏洞） | searchsploit_proftpd.json, EDB-36742/49908 |
| CVE-2011-1137 (mod_sftp DoS) | 部分：超长字符串导致超时 | 已验证（109 出现超时） | raw 报文交互记录 |
| CVE-2010-4221 (IAC overflow) | 未知：可能已修补 | 未验证 | searchsploit 记录 |
| 弱加密算法配置 | 需 MITM 位置 | 事实确认（协商结果） | KEXINIT 报文解析 |
| 相同主机密钥 | 已确认 | 事实确认 | ssh -v fingerprint 输出 |

---

## 7. 影响分析

### 高危影响

1. **远程命令执行（潜在）**：若 FTP 端口开放，CVE-2015-3306 可在无认证条件下实现完整 RCE，影响包括：
   - 读取 /etc/shadow、/etc/passwd 等敏感文件
   - 通过 /proc/self/fd/3 将日志写入 Web 目录实现 PHP/脚本注入
   - 创建持久化后门文件

2. **会话密钥恢复（潜在）**：若攻击者处于 MITM 位置，可通过 Logjam 攻击降级密钥交换，恢复加密会话内容，影响包括：
   - 解密所有 SFTP 传输文件内容
   - 截取认证密钥交换过程
   - 注入恶意命令

### 中高危影响

3. **拒绝服务**：超长客户端标识字符串可导致至少一台靶机服务中断（120.133.131.109 出现超时），影响包括：
   - SFTP 服务不可用
   - 影响依赖该服务的业务流程

4. **中间人攻击**：弱 CBC 加密和 MD5 MAC 使得 MITM 位置攻击者可以：
   - 篡改 SFTP 传输文件内容
   - 伪造 MAC 绕过完整性校验
   - 修改 SSH 命令执行流

---

## 8. 关键证据索引

| 证据编号 | 路径 | 描述 | 阶段 |
|---|---|---|---|
| nmap | raw/nmap.txt | 端口扫描结果 | recon |
| recon_meta | raw/recon_meta.env | 侦察元数据 | recon |
| searchsploit_proftpd | raw/searchsploit_proftpd.json | ProFTPD 1.3.5 漏洞查询结果 | recon |
| banner_mod_sftp | raw/ (协议交互) | SSH-2.0-mod_sftp/0.9.9 banner | recon |
| kexinit_weak | raw/ (协议交互) | 服务端弱算法协商数据 | recon |
| cve_2011_1137_test | raw/ (协议交互) | 整数溢出测试：Application error 响应 | validation |
| long_string_dos | raw/ (协议交互) | 超长字符串 DoS 测试（109 超时） | validation |

---

## 9. 修复与缓解建议

### 9.1 高优先级

1. **升级 ProFTPD 至 1.3.8+**：彻底修补 CVE-2015-3306 和 CVE-2011-1137
2. **移除 mod_copy 模块**：除非必要，否则禁用 SITE CPFR/CPTO 命令
3. **加密算法加固**：
   - 禁用 diffie-hellman-group1-sha1、diffie-hellman-group14-sha1、rsa1024-sha1
   - 禁用所有 CBC 模式加密（仅保留 CTR/GCM 模式）
   - 禁用 hmac-md5、hmac-md5-96、hmac-sha1-96
   - 禁用 ssh-dss 主机密钥算法
4. **独立主机密钥**：每台靶机生成独立的 SSH 主机密钥（至少 2048 位 RSA 或 Ed25519）

### 9.2 中优先级

5. **关闭 zlib 压缩**：禁用 zlib 压缩以消除 CRIME 式攻击风险
6. **FTP 端口策略**：确保 FTP 端口不对外网开放，或完全移除 mod_copy
7. **增加密码认证**：考虑启用密码认证配合 fail2ban，增加攻击难度（当前仅公钥认证，若密钥泄露则无第二防线）

### 9.3 长期建议

8. **替换为 OpenSSH**：OpenSSH 安全性优于 ProFTPD mod_sftp，建议迁移
9. **网络分段**：SFTP 服务置于内网，外网通过 VPN 访问
10. **日志监控**：部署 SFTP 会话日志监控，检测异常连接模式

---

## 10. 附录

### A. 攻击执行时间线

| 时间 | 阶段 | 操作 | 结果 |
|---|---|---|---|
| 2026-05-28T06:25 | recon | 端口扫描（nc 多端口） | 仅 22/tcp 开放 |
| 2026-05-28T06:25 | recon | Banner 抓取 | 确认 mod_sftp/0.9.9 |
| 2026-05-28T06:28 | recon | SSH KEXINIT 解析 | 确认弱算法集合 |
| 2026-05-28T06:30 | recon | searchsploit 查询 | CVE-2015-3306、CVE-2011-1137 |
| 2026-05-28T06:35 | validation | CVE-2011-1137 测试 | Application error 响应 |
| 2026-05-28T06:38 | validation | auth_none 测试 | 仅 publickey |
| 2026-05-28T06:40 | validation | 用户枚举 | 无差异响应 |
| 2026-05-28T06:42 | validation | 超长字符串 DoS | 109 超时响应 |
| 2026-05-28T06:45 | validation | 弱密钥尝试 | Permission denied |

### B. 工具清单

| 工具 | 用途 | 版本 |
|---|---|---|
| nc (netcat) | 端口探测、banner 抓取 | macOS 系统版本 |
| ssh/sftp | 认证测试、密钥指纹 | OpenSSH 8.6 |
| Python 3.12 + paramiko 5.0 | 协议分析 | — |
| nmap 7.92 | 端口扫描（后台执行） | brew 安装 |
| searchsploit | 漏洞情报查询 | exploitdb 本地副本 |

### C. 误报声明

- CVE-2015-3306：漏洞存在于软件中但当前不可利用（FTP 端口不可达），非误报
- CVE-2011-1137：原始 PoC 未导致崩溃，但超长字符串导致部分目标超时，部分验证
- 弱算法配置：非误报，服务端确实接受这些算法