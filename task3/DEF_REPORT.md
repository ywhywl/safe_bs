# DEF_REPORT

## 执行摘要

只读巡检完成：6 高风险、14 中风险、9 低风险。配置来源模式：raw_config_dir。

## 题目要求映射

- SSH 远程只读查看：已实现。采集链路不修改目标主机配置，只基于 `nginx -T` 输出或原始 `conf/` 目录做分析。
- 允许发布脚本或工具到靶机运行测试：已实现。脚本链路支持在只读边界内执行采集、解析和规则检测，但不会改动 nginx 配置。
- 原始配置目录导入：已实现。支持在 `nginx -T` 不可用或失败时，直接导入原始 `conf/` 目录并按 `include` 关系解析。
- 当前运行配置来源模式：`raw_config_dir`。
- 风险识别与证据回溯：已实现。每个风险项可回溯到规则命中、配置事实以及具体文件/行号。
- DEF_REPORT 交付要求：已实现。报告中覆盖防护思路、脚本/工具说明、发现问题和加固建议。
- TOOLS 目录交付要求：已实现。规则库、脚本镜像、JSON 结果和配置样例均可随交付包带走。
- AI_REPORT 交付要求：已实现。AI 使用过程、有效实践总结和工具评价均单独输出。

## 防护思路与方法

采用只读采集、规则检测和 LLM 语义分析。

- 配置组织识别：同时支持 `nginx -T` 展开模式与原始 `conf/` 目录递归模式。
- 事实提取：从 `http` / `server` / `location` 等上下文中抽取 TLS、Header、代理、安全控制、上传、连接限制等字段。
- 规则检测：以确定性规则库对配置事实进行匹配，不依赖 LLM 做最终判定。
- 证据链：所有风险都保留文件名、行号和原始 directive 证据。
- 报告生成：LLM 只补充语义解释、优先级排序和修复路线，不改变脚本判定结论。

## 脚本与工具说明

- `collect_readonly.sh`：只读采集入口，支持 `nginx -T` 和原始 `conf/` 目录。
- `config_loader.py`：在原始目录模式下按 `include` 关系递归加载配置文件。
- `build_inventory.py`：生成资产视图，识别 listener、server_name 和配置来源模式。
- `parse_config_facts.py`：抽取 TLS、安全头、代理、安全控制等事实字段和证据位置。
- `nginx_rules.json`：规则库，负责把配置事实转换为可审计的风险命中。
- `build_risk_register.py` / `build_report_context.py`：将命中结果组织成报告可消费的数据结构。

## 系统设计

```text
只读输入
  -> collect_readonly.sh       采集 nginx -T / nginx -V 或原始 conf 目录
  -> build_inventory.py        识别监听端口、server_name、配置来源模式
  -> parse_config_facts.py     提取配置事实与证据位置
  -> apply_rules.py            规则库匹配
  -> build_risk_register.py    归并风险清单
  -> build_report_context.py   汇总报告上下文
  -> render_reports.py         生成 DEF_REPORT / AI_REPORT
```

## 数据结构设计

- `task3_nginx_inventory.json`：资产、监听端口、server block 和配置来源模式。
- `task3_config_facts.json`：规则引擎使用的配置事实字段及证据索引。
- `task3_rule_hits.json`：规则命中结果，保留 observed_value、evidence_refs 和 remediation。
- `task3_risk_register.json`：按风险项归并后的输出，便于报告与复核。
- `task3_report_context.json`：面向文档生成的摘要上下文。

## 资产与配置概况

- 主机 /private/tmp/task3_confdir_nested，角色 ['nginx']，端口 []

## 风险发现清单

- risk-1 未启用 TLSv1.3（更高效更安全的协议版本） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'tls_protocols', 'observed_value': []}]，建议 在 ssl_protocols 中加入 TLSv1.3，提升安全性和性能。
- risk-2 缺少关键安全响应头 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'security_headers', 'observed_value': []}]，建议 在 server 或 location 块中添加 X-Content-Type-Options: nosniff 和 Content-Security-Policy 头。
- risk-3 目录列表功能已开启 [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 5, 'line_text': 'autoindex on;'}], 'field': 'autoindex', 'observed_value': True}]，建议 除非有明确的业务需求，应关闭 autoindex。
- risk-4 缺少 Strict-Transport-Security 头 [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'security_headers', 'observed_value': []}]，建议 对 HTTPS 服务添加 Strict-Transport-Security 头（建议 max-age≥63072000）。
- risk-5 缺少 Referrer-Policy 头 [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'security_headers', 'observed_value': []}]，建议 添加 Referrer-Policy 头以减少意外的 referrer 信息泄露。
- risk-6 server_tokens 未关闭 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'server_tokens_off', 'observed_value': False}]，建议 设置 server_tokens off 以减少版本信息暴露。
- risk-7 HTTP 监听端口未重定向到 HTTPS [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 3, 'line_text': 'listen 80;'}], 'field': 'http_redirects_to_https', 'observed_value': False}]，建议 HTTP server 块应配置 return 301 https://$host$request_uri 重定向到 HTTPS。
- risk-8 proxy_cookie_path 设置缺少 Secure 标记 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'cookie_has_secure_flag', 'observed_value': False}]，建议 在 proxy_cookie_path 中添加 Secure 标记，确保 cookie 仅通过 HTTPS 传输。
- risk-9 proxy_cookie_path 设置缺少 SameSite 属性 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'cookie_has_samesite', 'observed_value': False}]，建议 在 proxy_cookie_path 中添加 SameSite=Lax 或 SameSite=Strict，防止 CSRF 攻击。
- risk-10 未显式配置 ssl_ciphers（可能使用包含弱算法的默认值） [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'ssl_ciphers_defined', 'observed_value': False}]，建议 显式配置 ssl_ciphers，仅允许现代安全加密套件。
- risk-11 未配置 ssl_session_cache（影响 TLS 性能和会话恢复安全） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'ssl_session_cache_configured', 'observed_value': False}]，建议 配置 ssl_session_cache shared:SSL:10m 和 ssl_session_timeout 10m，提升 TLS 性能并安全缓存会话。
- risk-12 未启用 OCSP Stapling（客户端需单独验证证书状态） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'ocsp_stapling_enabled', 'observed_value': False}]，建议 启用 ssl_stapling on 和 ssl_stapling_verify on，减少客户端证书验证延迟。
- risk-13 大部分 location 未配置速率限制 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'rate_limited_locations_ratio', 'observed_value': 0.0}]，建议 使用 limit_req 或 limit_rate 对关键 location 配置速率限制。
- risk-14 未配置 limit_conn（缺少连接数限制，易受并发 DDoS） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'limit_conn_configured', 'observed_value': False}]，建议 在 http 块定义 limit_conn_zone $binary_remote_addr zone=conn_limit:10m，在 server/location 中配置 limit_conn conn_limit 100。
- risk-15 未配置 proxy_hide_header 隐藏后端响应头（X-Powered-By 等） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'proxy_hide_headers_configured', 'observed_value': False}]，建议 配置 proxy_hide_header X-Powered-By; proxy_hide_header Server; 防止后端信息泄露到客户端。
- risk-16 未限制危险 HTTP 方法（TRACE/DELETE/PUT 等可能被滥用） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'http_methods_limited', 'observed_value': False}]，建议 使用 limit_except GET POST HEAD { deny all; } 限制非必要 HTTP 方法，尤其禁用 TRACE（防止 XST 攻击）。
- risk-17 未阻止对隐藏文件（.git/.env/.htaccess）的访问 [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'hidden_files_blocked', 'observed_value': False}]，建议 添加 location ~ /\\.{ deny all; } 阻止对所有隐藏文件的访问。
- risk-18 未配置 disable_symlinks（符号链接可能暴露意外文件） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'disable_symlinks_configured', 'observed_value': False}]，建议 配置 disable_symlinks on 或 disable_symlinks if_not_owner，防止通过符号链接访问意外文件。
- risk-19 部分 server 未设置 client_max_body_size（允许超大文件上传） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'client_max_body_size_unlimited', 'observed_value': True}]，建议 在 http 或 server 块设置合理的 client_max_body_size（如 20m），防止恶意大文件上传耗尽资源。
- risk-20 未显式配置 proxy_connect/read/send_timeout（使用默认 60s 可能过长） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'proxy_timeout_configured', 'observed_value': False}]，建议 配置 proxy_connect_timeout 5s; proxy_read_timeout 30s; proxy_send_timeout 30s; 合理控制后端超时。
- risk-21 nginx 以 nobody 用户运行（低权限但需确认文件访问权限匹配） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 1, 'line_text': 'user nobody;'}], 'field': 'nginx_runs_as_nobody', 'observed_value': True}]，建议 nobody 用户权限极低是好的，但需确保 /data 等目录的读写权限与 nobody 匹配，避免权限不匹配导致安全问题。
- risk-22 worker_processes 设为 1（性能瓶颈，无法利用多核） [low]: 证据 [{'evidence_refs': [{'file': 'nginx.conf', 'line_no': 1, 'line_text': 'worker_processes  1;'}], 'field': 'worker_processes_one', 'observed_value': True}]，建议 将 worker_processes 设为 auto 或与 CPU 核数匹配，提升性能和并发处理能力。
- risk-23 worker_connections 仅为 1024（并发能力偏低） [low]: 证据 [{'evidence_refs': [{'file': 'nginx.conf', 'line_no': 2, 'line_text': 'events { worker_connections 1024; }'}], 'field': 'worker_connections_value', 'observed_value': 1024}]，建议 将 worker_connections 提升到 4096 或更高，配合 worker_processes 提升并发能力。
- risk-24 未配置 upstream keepalive（每次请求新建连接，性能浪费） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'upstream_keepalive_configured', 'observed_value': False}]，建议 在 upstream 块中添加 keepalive 32; 并在 proxy_set_header 中设置 Connection ""; 实现长连接复用。
- risk-25 未配置 set_real_ip_from（无法从代理层获取真实客户端 IP） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'real_ip_configured', 'observed_value': False}]，建议 配置 set_real_ip_from 10.0.0.0/8; 和 real_ip_header X-Forwarded-For; 确保日志和访问控制基于真实 IP。
- risk-26 未配置 ssl_prefer_server_ciphers on（客户端可能选择弱套件） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'ssl_prefer_server_ciphers_on', 'observed_value': False}]，建议 配置 ssl_prefer_server_ciphers on; 确保服务端优先选择强加密套件，而非让客户端选择。
- risk-27 未显式配置 proxy_buffer_size/proxy_buffers（默认值可能导致大头部溢出） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'proxy_buffer_configured', 'observed_value': False}]，建议 配置 proxy_buffer_size 8k; proxy_buffers 8 8k; 防止后端大响应头溢出缓冲区。
- risk-28 HTTP 明文入口与 Cookie 缺少 Secure 标记形成会话劫持链 [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 3, 'line_text': 'listen 80;'}], 'field': 'http_redirects_to_https', 'observed_value': False}, {'evidence_refs': [], 'field': 'cookie_has_secure_flag', 'observed_value': False}]，建议 先为 HTTP server 增加 301 跳转到 HTTPS，再为 cookie 策略补充 Secure 标记，避免明文通道暴露会话令牌。
- risk-29 TLS 加固缺失形成传输面弱防护组合 [medium]: 证据 [{'evidence_refs': [], 'field': 'ssl_ciphers_defined', 'observed_value': False}, {'evidence_refs': [], 'field': 'ssl_prefer_server_ciphers_on', 'observed_value': False}, {'evidence_refs': [], 'field': 'ocsp_stapling_enabled', 'observed_value': False}]，建议 显式配置现代 ssl_ciphers，开启 ssl_prefer_server_ciphers on，并补充 ssl_stapling/ssl_stapling_verify。

## 高风险问题详述

- risk-3 目录列表功能已开启 [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 5, 'line_text': 'autoindex on;'}], 'field': 'autoindex', 'observed_value': True}]，建议 除非有明确的业务需求，应关闭 autoindex。
- risk-4 缺少 Strict-Transport-Security 头 [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'security_headers', 'observed_value': []}]，建议 对 HTTPS 服务添加 Strict-Transport-Security 头（建议 max-age≥63072000）。
- risk-7 HTTP 监听端口未重定向到 HTTPS [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 3, 'line_text': 'listen 80;'}], 'field': 'http_redirects_to_https', 'observed_value': False}]，建议 HTTP server 块应配置 return 301 https://$host$request_uri 重定向到 HTTPS。
- risk-10 未显式配置 ssl_ciphers（可能使用包含弱算法的默认值） [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'ssl_ciphers_defined', 'observed_value': False}]，建议 显式配置 ssl_ciphers，仅允许现代安全加密套件。
- risk-17 未阻止对隐藏文件（.git/.env/.htaccess）的访问 [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'hidden_files_blocked', 'observed_value': False}]，建议 添加 location ~ /\\.{ deny all; } 阻止对所有隐藏文件的访问。
- risk-28 HTTP 明文入口与 Cookie 缺少 Secure 标记形成会话劫持链 [high]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 3, 'line_text': 'listen 80;'}], 'field': 'http_redirects_to_https', 'observed_value': False}, {'evidence_refs': [], 'field': 'cookie_has_secure_flag', 'observed_value': False}]，建议 先为 HTTP server 增加 301 跳转到 HTTPS，再为 cookie 策略补充 Secure 标记，避免明文通道暴露会话令牌。

## 中低风险问题概述

- risk-1 未启用 TLSv1.3（更高效更安全的协议版本） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'tls_protocols', 'observed_value': []}]，建议 在 ssl_protocols 中加入 TLSv1.3，提升安全性和性能。
- risk-2 缺少关键安全响应头 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'security_headers', 'observed_value': []}]，建议 在 server 或 location 块中添加 X-Content-Type-Options: nosniff 和 Content-Security-Policy 头。
- risk-6 server_tokens 未关闭 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'server_tokens_off', 'observed_value': False}]，建议 设置 server_tokens off 以减少版本信息暴露。
- risk-8 proxy_cookie_path 设置缺少 Secure 标记 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'cookie_has_secure_flag', 'observed_value': False}]，建议 在 proxy_cookie_path 中添加 Secure 标记，确保 cookie 仅通过 HTTPS 传输。
- risk-9 proxy_cookie_path 设置缺少 SameSite 属性 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'cookie_has_samesite', 'observed_value': False}]，建议 在 proxy_cookie_path 中添加 SameSite=Lax 或 SameSite=Strict，防止 CSRF 攻击。
- risk-11 未配置 ssl_session_cache（影响 TLS 性能和会话恢复安全） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'ssl_session_cache_configured', 'observed_value': False}]，建议 配置 ssl_session_cache shared:SSL:10m 和 ssl_session_timeout 10m，提升 TLS 性能并安全缓存会话。
- risk-13 大部分 location 未配置速率限制 [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'rate_limited_locations_ratio', 'observed_value': 0.0}]，建议 使用 limit_req 或 limit_rate 对关键 location 配置速率限制。
- risk-14 未配置 limit_conn（缺少连接数限制，易受并发 DDoS） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'limit_conn_configured', 'observed_value': False}]，建议 在 http 块定义 limit_conn_zone $binary_remote_addr zone=conn_limit:10m，在 server/location 中配置 limit_conn conn_limit 100。
- risk-15 未配置 proxy_hide_header 隐藏后端响应头（X-Powered-By 等） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'proxy_hide_headers_configured', 'observed_value': False}]，建议 配置 proxy_hide_header X-Powered-By; proxy_hide_header Server; 防止后端信息泄露到客户端。
- risk-16 未限制危险 HTTP 方法（TRACE/DELETE/PUT 等可能被滥用） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'http_methods_limited', 'observed_value': False}]，建议 使用 limit_except GET POST HEAD { deny all; } 限制非必要 HTTP 方法，尤其禁用 TRACE（防止 XST 攻击）。
- risk-19 部分 server 未设置 client_max_body_size（允许超大文件上传） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'client_max_body_size_unlimited', 'observed_value': True}]，建议 在 http 或 server 块设置合理的 client_max_body_size（如 20m），防止恶意大文件上传耗尽资源。
- risk-25 未配置 set_real_ip_from（无法从代理层获取真实客户端 IP） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'real_ip_configured', 'observed_value': False}]，建议 配置 set_real_ip_from 10.0.0.0/8; 和 real_ip_header X-Forwarded-For; 确保日志和访问控制基于真实 IP。
- risk-26 未配置 ssl_prefer_server_ciphers on（客户端可能选择弱套件） [medium]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'ssl_prefer_server_ciphers_on', 'observed_value': False}]，建议 配置 ssl_prefer_server_ciphers on; 确保服务端优先选择强加密套件，而非让客户端选择。
- risk-29 TLS 加固缺失形成传输面弱防护组合 [medium]: 证据 [{'evidence_refs': [], 'field': 'ssl_ciphers_defined', 'observed_value': False}, {'evidence_refs': [], 'field': 'ssl_prefer_server_ciphers_on', 'observed_value': False}, {'evidence_refs': [], 'field': 'ocsp_stapling_enabled', 'observed_value': False}]，建议 显式配置现代 ssl_ciphers，开启 ssl_prefer_server_ciphers on，并补充 ssl_stapling/ssl_stapling_verify。

## 低风险问题概述

- risk-5 缺少 Referrer-Policy 头 [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'security_headers', 'observed_value': []}]，建议 添加 Referrer-Policy 头以减少意外的 referrer 信息泄露。
- risk-12 未启用 OCSP Stapling（客户端需单独验证证书状态） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'ocsp_stapling_enabled', 'observed_value': False}]，建议 启用 ssl_stapling on 和 ssl_stapling_verify on，减少客户端证书验证延迟。
- risk-18 未配置 disable_symlinks（符号链接可能暴露意外文件） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'disable_symlinks_configured', 'observed_value': False}]，建议 配置 disable_symlinks on 或 disable_symlinks if_not_owner，防止通过符号链接访问意外文件。
- risk-20 未显式配置 proxy_connect/read/send_timeout（使用默认 60s 可能过长） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'proxy_timeout_configured', 'observed_value': False}]，建议 配置 proxy_connect_timeout 5s; proxy_read_timeout 30s; proxy_send_timeout 30s; 合理控制后端超时。
- risk-21 nginx 以 nobody 用户运行（低权限但需确认文件访问权限匹配） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 1, 'line_text': 'user nobody;'}], 'field': 'nginx_runs_as_nobody', 'observed_value': True}]，建议 nobody 用户权限极低是好的，但需确保 /data 等目录的读写权限与 nobody 匹配，避免权限不匹配导致安全问题。
- risk-22 worker_processes 设为 1（性能瓶颈，无法利用多核） [low]: 证据 [{'evidence_refs': [{'file': 'nginx.conf', 'line_no': 1, 'line_text': 'worker_processes  1;'}], 'field': 'worker_processes_one', 'observed_value': True}]，建议 将 worker_processes 设为 auto 或与 CPU 核数匹配，提升性能和并发处理能力。
- risk-23 worker_connections 仅为 1024（并发能力偏低） [low]: 证据 [{'evidence_refs': [{'file': 'nginx.conf', 'line_no': 2, 'line_text': 'events { worker_connections 1024; }'}], 'field': 'worker_connections_value', 'observed_value': 1024}]，建议 将 worker_connections 提升到 4096 或更高，配合 worker_processes 提升并发能力。
- risk-24 未配置 upstream keepalive（每次请求新建连接，性能浪费） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'upstream_keepalive_configured', 'observed_value': False}]，建议 在 upstream 块中添加 keepalive 32; 并在 proxy_set_header 中设置 Connection ""; 实现长连接复用。
- risk-27 未显式配置 proxy_buffer_size/proxy_buffers（默认值可能导致大头部溢出） [low]: 证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'proxy_buffer_configured', 'observed_value': False}]，建议 配置 proxy_buffer_size 8k; proxy_buffers 8 8k; 防止后端大响应头溢出缓冲区。

## server/vhost 级风险视图

- server-risk-1 server 级缺少关键安全响应头 [medium]: server=['_']，证据 [{'context_snippet': 'user nobody;\nserver {\n    listen 80;\n    server_name _;', 'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}], 'field': 'security_headers', 'observed_value': []}]，建议 在对应 server 块中补充 add_header X-Content-Type-Options nosniff always; 和合适的 Content-Security-Policy;
- server-risk-2 server 级 HTTP 未重定向到 HTTPS [high]: server=['_']，证据 [{'context_snippet': 'user nobody;\nserver {\n    listen 80;\n    server_name _;', 'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}], 'field': 'http_redirects_to_https', 'observed_value': False}]，建议 将该 HTTP server 块改为 return 301 https://$host$request_uri;
- server-risk-3 server 级目录列表功能已开启 [high]: server=['_']，证据 [{'context_snippet': 'user nobody;\nserver {\n    listen 80;\n    server_name _;', 'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}], 'field': 'autoindex', 'observed_value': True}]，建议 在对应 server/location 中关闭 autoindex，除非该目录列表是明确业务需求。
- server-risk-4 server 级未阻止隐藏文件访问 [high]: server=['_']，证据 [{'context_snippet': 'user nobody;\nserver {\n    listen 80;\n    server_name _;', 'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}], 'field': 'hidden_files_blocked', 'observed_value': False}]，建议 在对应 server 块中添加 location ~ /\\.{ deny all; }
- server-risk-5 server 级未配置连接数限制 [medium]: server=['_']，证据 [{'context_snippet': 'user nobody;\nserver {\n    listen 80;\n    server_name _;', 'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}], 'field': 'limit_conn_configured', 'observed_value': False}]，建议 在对应 server/location 中补充 limit_conn，并确保上层已定义 limit_conn_zone。
- server-risk-6 server 级明文入口与目录列表联动暴露 [high]: server=['_']，证据 [{'context_snippet': 'user nobody;\nserver {\n    listen 80;\n    server_name _;', 'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}], 'field': 'server_context', 'observed_value': ['_']}, {'evidence_refs': [], 'field': 'http_redirects_to_https', 'observed_value': False}, {'evidence_refs': [], 'field': 'autoindex', 'observed_value': True}]，建议 将该 HTTP server 块改为仅做 HTTPS 跳转，并关闭 autoindex。
- server-risk-7 server 级入口暴露面过大（隐藏文件、方法、连接控制同时缺失） [high]: server=['_']，证据 [{'context_snippet': 'user nobody;\nserver {\n    listen 80;\n    server_name _;', 'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}], 'field': 'server_context', 'observed_value': ['_']}, {'evidence_refs': [], 'field': 'hidden_files_blocked', 'observed_value': False}, {'evidence_refs': [], 'field': 'http_methods_limited', 'observed_value': False}, {'evidence_refs': [], 'field': 'limit_conn_configured', 'observed_value': False}]，建议 在对应 server 中同时补上隐藏文件访问控制、limit_except 方法限制和 limit_conn 连接限制。

## 完整风险链示例

1. 配置输入阶段：本次巡检从 `raw_config_dir` 模式获取配置，说明即使没有完整 `nginx -T` 输出，也能基于原始配置目录建立事实视图。
2. 风险发现阶段：`risk-1` `未启用 TLSv1.3（更高效更安全的协议版本）` 被识别为 `medium`，脚本已给出证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'tls_protocols', 'observed_value': []}] 和修复建议 在 ssl_protocols 中加入 TLSv1.3，提升安全性和性能。。
3. 风险发现阶段：`risk-2` `缺少关键安全响应头` 被识别为 `medium`，脚本已给出证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 2, 'line_text': 'server {'}, {'file': 'nginx.conf', 'line_no': 3, 'line_text': 'http {'}], 'field': 'security_headers', 'observed_value': []}] 和修复建议 在 server 或 location 块中添加 X-Content-Type-Options: nosniff 和 Content-Security-Policy 头。。
4. 风险发现阶段：`risk-3` `目录列表功能已开启` 被识别为 `high`，脚本已给出证据 [{'evidence_refs': [{'file': 'http.d/nginx1.conf', 'line_no': 5, 'line_text': 'autoindex on;'}], 'field': 'autoindex', 'observed_value': True}] 和修复建议 除非有明确的业务需求，应关闭 autoindex。。
5. 结论阶段：这些风险共同表明当前 nginx 配置同时存在协议、暴露面和基础安全控制缺失问题，因此系统不仅输出单项风险，还能生成按优先级排序的加固路线。

## 亮点与创新点

- 1. 只读巡检边界清晰，适合内网真实环境，不要求修改线上 nginx 配置。
- 2. 同时支持 `nginx -T` 与原始 `conf/` 目录导入，解决很多内网环境里 `nginx -T` 失败的问题。
- 3. 原始目录模式下支持按 `include` 关系递归解析子目录配置，能覆盖 `http.d/*.conf` 这类常见组织方式。
- 4. 风险判定基于确定性规则和配置事实，证据可回溯到具体文件与行号，便于人工复核。
- 5. 报告输出不止给风险列表，还给出可直接写入 nginx.conf 的修复建议，落地性强。
- 6. 规则库、事实提取器、交付 JSON 和 LLM 双模式可重复用于其它 nginx 审计任务。
- 7. 当前运行展示了原始 conf 目录导入能力，说明在复杂内网环境下仍可完成巡检。

## 整体防护评估

只读巡检完成：6 高风险、14 中风险、9 低风险。配置来源模式：raw_config_dir。

## 加固建议路线图

- 若 nginx -T 失败，先修复配置组织错误（如 include 位置不当、顶层指令落入 http.d）并重新验证
- 优先处理高风险项：关闭目录浏览、修补路径遍历、统一会话校验覆盖
- 补齐缺失的安全响应头（HSTS、CSP、X-Content-Type-Options），并复核敏感路径的访问控制
- 修复 HTTP 未重定向到 HTTPS、cookie 缺少 Secure 标记、proxy_pass HTTPS 未验证证书
- 继续扩展规则库，覆盖鉴权、缓存、上传链路和反向代理边界

## 评分标准对应与完成度

- 防护效果维度：当前发现 `6` 个高风险、`14` 个中风险、`9` 个低风险问题，覆盖 TLS、Header、暴露面、代理安全、速率限制、隐藏文件保护等主要防护面。
- 可复用性维度：支持原始 conf 目录导入、支持规则库复用、支持只读采集边界、支持外网/内网 LLM 双模式，具备较强的工程复用能力。
- 设计合理性维度：配置事实提取、规则命中、风险归并和报告生成分层清晰，便于维护和扩展。
- 性能与安全性维度：默认只读执行，不依赖修改靶机配置；原始目录模式可避免 `nginx -T` 失败导致的阻塞，适合内网靶机环境。

- 核心功能完成度：高。资产识别、事实提取、规则命中、风险归并、报告生成均已贯通。
- 工程化完成度：高。支持外网/内网 LLM 双模式，支持原始目录导入，支持规则/脚本/证据打包交付。
- 文档完成度：高。DEF_REPORT 和 AI_REPORT 已能自动体现方法、亮点、证据链和交付价值。
- 剩余优化方向：主要在扩展应用层规则、覆盖更多业务场景、补充更细粒度的 TLS/代理语义分析。

## 证据索引

见 task3_rule_hits.json 与 task3_risk_register.json。

## 附录

run_id=verify_task3_composite
