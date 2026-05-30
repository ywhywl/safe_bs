#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from pathlib import Path

from config_loader import load_active_configs
from lib import dump_json, make_base_record, read_text


SECURITY_HEADERS = {
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "content-security-policy": "Content-Security-Policy",
    "referrer-policy": "Referrer-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-xss-protection": "X-XSS-Protection",
    "permissions-policy": "Permissions-Policy",
}


def find_directive_values(content: str, directive: str) -> list[str]:
    pattern = re.compile(rf"^\s*{re.escape(directive)}\s+(.+?);", re.MULTILINE)
    return [match.group(1).strip() for match in pattern.finditer(content)]


def find_directive_exists(content: str, directive: str) -> bool:
    return bool(re.search(rf"^\s*{re.escape(directive)}\s+", content, re.MULTILINE))


def find_location_blocks(content: str) -> list[str]:
    matches = re.findall(r"^\s*location\s+(.+?)\s*\{", content, re.MULTILINE)
    return [match.strip() for match in matches]


def find_server_tokens_off(content: str) -> bool:
    values = find_directive_values(content, "server_tokens")
    return any(value.split()[0].lower() == "off" for value in values if value.split())


def find_deny_all(content: str) -> bool:
    values = find_directive_values(content, "deny")
    return any(value.split()[0].lower() == "all" for value in values if value.split())


def read_all_configs(raw_dir: Path) -> dict[str, str]:
    return load_active_configs(raw_dir)


def find_line_refs(content: str, patterns: list[str], filename: str) -> list[dict]:
    refs = []
    if not patterns:
        return refs
    lowered_patterns = [pattern.lower() for pattern in patterns if pattern]
    for idx, line in enumerate(content.splitlines(), start=1):
        lowered_line = line.lower()
        for pattern in lowered_patterns:
            if pattern in lowered_line:
                refs.append(
                    {
                        "file": filename,
                        "line_no": idx,
                        "line_text": line.strip(),
                    }
                )
                break
    return refs


def extract_context_snippet(content: str, line_no: int, radius: int = 2) -> str:
    lines = content.splitlines()
    if not lines or line_no < 1:
        return ""
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def extract_server_blocks(content: str) -> list[dict]:
    servers = []
    for m in re.finditer(r"server\s*\{", content):
        start = m.start()
        depth = 0
        i = start
        while i < len(content):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    block = content[start:i + 1]
                    listen_ports = re.findall(r"listen\s+(\S+);", block)
                    server_name = re.findall(r"server_name\s+(.+?);", block)
                    has_lua_access = "access_by_lua" in block
                    has_proxy_cookie = "proxy_cookie_path" in block
                    proxy_cookie_secure = bool(re.search(r"proxy_cookie_path.*Secure", block))
                    proxy_cookie_samesite = bool(re.search(r"proxy_cookie_path.*SameSite", block, re.IGNORECASE))
                    locations_in_block = find_location_blocks(block)
                    options_403 = bool(re.search(r"if\s*\(\$request_method\s*=\s*OPTIONS\)\s*\{\s*return\s+403", block))
                    has_https_redirect = bool(re.search(r"return\s+30[12]\s+https://", block))
                    has_if_in_location = bool(re.search(r"^\s*if\s*\(", block, re.MULTILINE))
                    has_access_log_off = "access_log off" in block
                    has_limit_except = "limit_except" in block
                    has_allow_deny = bool(re.search(r"allow\s+", block) or re.search(r"deny\s+", block))
                    ssl_has_ciphers = bool(re.search(r"ssl_ciphers\s+", block))
                    ssl_has_protocols = bool(re.search(r"ssl_protocols\s+", block))
                    ssl_has_prefer = bool(re.search(r"ssl_prefer_server_ciphers\s+on", block))
                    has_ssl_block = bool(re.search(r"listen\s+\S+ssl", block) or re.search(r"listen\s+\S+\s+ssl", block))
                    has_client_max_body = bool(re.search(r"client_max_body_size\s+", block))
                    servers.append({
                        "listen": listen_ports,
                        "server_name": server_name,
                        "has_lua_access": has_lua_access,
                        "locations": locations_in_block,
                        "has_proxy_cookie": has_proxy_cookie,
                        "proxy_cookie_secure": proxy_cookie_secure,
                        "proxy_cookie_samesite": proxy_cookie_samesite,
                        "options_403": options_403,
                        "has_https_redirect": has_https_redirect,
                        "has_if_in_location": has_if_in_location,
                        "has_access_log_off": has_access_log_off,
                        "has_limit_except": has_limit_except,
                        "has_allow_deny": has_allow_deny,
                        "ssl_has_ciphers": ssl_has_ciphers,
                        "ssl_has_protocols": ssl_has_protocols,
                        "ssl_has_prefer": ssl_has_prefer,
                        "has_ssl_block": has_ssl_block,
                        "has_client_max_body": has_client_max_body,
                    })
                    break
            i += 1
    return servers


def extract_server_blocks_with_meta(content: str, filename: str) -> list[dict]:
    servers = []
    lines = content.splitlines()
    line_starts = []
    cursor = 0
    for line in lines:
        line_starts.append(cursor)
        cursor += len(line) + 1
    for m in re.finditer(r"server\s*\{", content):
        start = m.start()
        depth = 0
        i = start
        while i < len(content):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    block = content[start:i + 1]
                    start_line_no = 1
                    for idx, offset in enumerate(line_starts, start=1):
                        if offset <= start:
                            start_line_no = idx
                        else:
                            break
                    end_line_no = start_line_no + block.count("\n")
                    listen_ports = re.findall(r"listen\s+(\S+);", block)
                    server_name = re.findall(r"server_name\s+(.+?);", block)
                    locations_in_block = find_location_blocks(block)
                    tls_protocols = sorted({
                        proto
                        for value in find_directive_values(block, "ssl_protocols")
                        for proto in value.split()
                    })
                    headers = []
                    for value in find_directive_values(block, "add_header"):
                        header_name = value.split()[0].strip('"').strip("'").lower()
                        if header_name in SECURITY_HEADERS:
                            headers.append(SECURITY_HEADERS[header_name])
                    autoindex = any(v.split()[0] == "on" for v in find_directive_values(block, "autoindex"))
                    server_tokens_off = find_server_tokens_off(block)
                    has_https_redirect = bool(re.search(r"return\s+30[12]\s+https://", block))
                    ssl_has_ciphers = bool(re.search(r"ssl_ciphers\s+", block))
                    ssl_session_cache_configured = find_directive_exists(block, "ssl_session_cache")
                    ocsp_stapling_enabled = bool(re.search(r"ssl_stapling\s+on", block))
                    hidden_files_blocked = bool(re.search(r"location\s+~\s*/\\\.", block)) or bool(re.search(r"location\s+~\s+/\.", block))
                    client_max_body_values = find_directive_values(block, "client_max_body_size")
                    client_max_body_size_unlimited = not client_max_body_values or any(v == "0" for v in client_max_body_values)
                    has_limit_conn = find_directive_exists(block, "limit_conn")
                    has_limit_except = "limit_except" in block
                    has_proxy_hide_header = find_directive_exists(block, "proxy_hide_header")
                    has_ssl_block = bool(re.search(r"listen\s+\S+ssl", block) or re.search(r"listen\s+\S+\s+ssl", block))
                    http_ports = {"80", "8080", "8081"}
                    is_http_server = any(listener.split()[0].split(":")[-1] in http_ports for listener in listen_ports)
                    security_headers = sorted(set(headers))
                    servers.append(
                        {
                            "server_key": f"{filename}:{start_line_no}",
                            "file": filename,
                            "start_line_no": start_line_no,
                            "end_line_no": end_line_no,
                            "server_names": server_name,
                            "listen": listen_ports,
                            "locations": locations_in_block,
                            "tls_protocols": tls_protocols,
                            "security_headers": security_headers,
                            "autoindex": autoindex,
                            "server_tokens_off": server_tokens_off,
                            "http_redirects_to_https": (not is_http_server) or has_https_redirect,
                            "ssl_ciphers_defined": ssl_has_ciphers,
                            "ssl_session_cache_configured": ssl_session_cache_configured,
                            "ocsp_stapling_enabled": ocsp_stapling_enabled,
                            "hidden_files_blocked": hidden_files_blocked,
                            "client_max_body_size_unlimited": client_max_body_size_unlimited,
                            "limit_conn_configured": has_limit_conn,
                            "http_methods_limited": has_limit_except,
                            "proxy_hide_headers_configured": has_proxy_hide_header,
                            "ssl_prefer_server_ciphers_on": bool(re.search(r"ssl_prefer_server_ciphers\s+on", block)),
                            "status_pages_without_acl": len(re.findall(r"location\s+(?:=)?\s*(/status|/vstatus|/healthcheck|/health_status|/healthcheck\.html)", block)) > 0 and not bool(re.search(r"allow\s+", block)),
                            "is_http_server": is_http_server,
                            "has_ssl_block": has_ssl_block,
                            "context_snippet": extract_context_snippet(content, start_line_no),
                        }
                    )
                    break
            i += 1
    return servers


def extract_all_facts(configs: dict[str, str]) -> dict:
    config_texts = {name: content for name, content in configs.items() if not name.endswith(".stderr")}
    combined = "\n".join(config_texts.values())
    server_blocks = extract_server_blocks(combined)
    nginx_t_stderr = configs.get("nginx_T.stderr", "")

    # --- Basic facts ---
    autoindex = any(v.split()[0] == "on" for v in find_directive_values(combined, "autoindex"))
    tls_protocols = sorted({
        proto
        for value in find_directive_values(combined, "ssl_protocols")
        for proto in value.split()
    })
    ssl_ciphers_list = find_directive_values(combined, "ssl_ciphers")
    ssl_ciphers_defined = len(ssl_ciphers_list) > 0
    ssl_ciphers = ssl_ciphers_list[0] if ssl_ciphers_list else ""

    # --- Security headers ---
    header_values = find_directive_values(combined, "add_header")
    security_headers = []
    for value in header_values:
        header_name = value.split()[0].strip('"').strip("'").lower()
        if header_name in SECURITY_HEADERS:
            security_headers.append(SECURITY_HEADERS[header_name])

    locations = find_location_blocks(combined)
    upstreams = re.findall(r"^\s*upstream\s+([^\s{]+)", combined, re.MULTILINE)

    # --- HTTP/HTTPS ---
    http_ports = {"80", "8080", "8081"}
    http_servers = []
    for server in server_blocks:
        listens = server.get("listen", [])
        if any(listener.split()[0].split(":")[-1] in http_ports for listener in listens):
            http_servers.append(server)
    http_redirects_to_https = not http_servers or all(server.get("has_https_redirect", False) for server in http_servers)

    # HTTP and HTTPS in same server block
    http_https_same_block = any(
        any(p in ["80", "8080", "8081"] for p in s["listen"]) and s["has_ssl_block"]
        for s in server_blocks
    )

    # --- Server name ---
    has_empty_server_name = bool(re.search(r"server_name\s+;", combined))

    # --- Config test failure / structural issues ---
    nginx_t_failed = "test failed" in nginx_t_stderr.lower() or "[emerg]" in nginx_t_stderr.lower()
    user_directive_misplaced = "\"user\" directive is not allowed here" in nginx_t_stderr.lower()

    # --- Cookie ---
    cookie_has_secure_flag = bool(re.search(r"proxy_cookie_path.*Secure", combined))
    cookie_has_samesite = bool(re.search(r"proxy_cookie_path.*SameSite", combined, re.IGNORECASE))
    cookie_contains_org_code = bool(re.search(r"org_code=", combined))

    # --- SSL/TLS deep ---
    weak_keywords = []
    if ssl_ciphers:
        for kw in ["RC4", "DES", "3DES", "NULL", "EXPORT", "CBC"]:
            if kw in ssl_ciphers:
                weak_keywords.append(kw)
        if "MD5" in ssl_ciphers and "!MD5" not in ssl_ciphers:
            weak_keywords.append("MD5")
        if "SHA1" in ssl_ciphers and "!SHA" not in ssl_ciphers:
            weak_keywords.append("SHA1")

    ssl_session_cache_configured = find_directive_exists(combined, "ssl_session_cache")
    ssl_prefer_server_ciphers_on = bool(re.search(r"ssl_prefer_server_ciphers\s+on", combined))
    ocsp_stapling_enabled = bool(re.search(r"ssl_stapling\s+on", combined))

    # --- Proxy ---
    proxy_pass_https_without_verify = bool(re.search(r"proxy_pass\s+https://", combined)) and not bool(re.search(r"proxy_ssl_verify\s+on", combined))
    proxy_pass_http_backend = bool(re.search(r"proxy_pass\s+http://", combined))
    proxy_hide_headers_configured = find_directive_exists(combined, "proxy_hide_header")
    proxy_timeout_configured = find_directive_exists(combined, "proxy_connect_timeout") or find_directive_exists(combined, "proxy_read_timeout")
    proxy_buffer_configured = find_directive_exists(combined, "proxy_buffer_size") or find_directive_exists(combined, "proxy_buffers")
    proxy_redirect_values = find_directive_values(combined, "proxy_redirect")
    proxy_redirect_has_invalid_value = any(v not in ["off", "default", "http:// https://"] and not re.match(r"https://\S+\s+https://\S+", v) for v in proxy_redirect_values)

    # --- Status pages ---
    status_paths = re.findall(r"location\s+(?:=)?\s*(/status|/vstatus|/healthcheck|/health_status|/healthcheck\.html)", combined)
    status_with_acl = len(re.findall(r"location.*(?:/status|/vstatus|/healthcheck).*\n.*allow\s+", combined))
    status_pages_without_acl = len(status_paths) > 0 and status_with_acl < len(status_paths)

    # --- alias + try_files ---
    alias_try_files_pairs_count = len(re.findall(r"alias\s+/[^;]+;.*?try_files", combined, re.DOTALL))

    # --- HTTP methods ---
    options_returns_403 = bool(re.search(r"if\s*\(\$request_method\s*=\s*OPTIONS\)\s*\{\s*return\s+403", combined))
    http_methods_limited = find_directive_exists(combined, "limit_except")

    # --- Hidden files ---
    hidden_files_blocked = bool(re.search(r"location\s+~\s*/\\\.", combined)) or bool(re.search(r"location\s+~\s+/\.", combined))

    # --- Upload dir execution ---
    upload_keywords = ["upload", "fileupload", "merchantupload", "attachment", "tmp"]
    upload_locations = [loc for loc in locations if any(kw in loc.lower() for kw in upload_keywords)]
    upload_dir_execution_blocked = len(upload_locations) == 0 or bool(re.search(r"location\s+~.*\.(php|jsp|py|sh|cgi)\s*\{.*deny\s+all", combined, re.DOTALL))

    # --- Client max body size ---
    client_max_body_values = find_directive_values(combined, "client_max_body_size")
    client_max_body_size_unlimited = not client_max_body_values or any(v == "0" for v in client_max_body_values)

    # --- Rate limiting ---
    rate_limited_locations = len(re.findall(r"limit_rate\s+", combined)) + len(re.findall(r"limit_req\s+", combined))
    total_locations = len(locations)
    rate_limited_locations_ratio = round(rate_limited_locations / max(total_locations, 1), 2)

    # --- Connection limiting ---
    limit_conn_configured = find_directive_exists(combined, "limit_conn_zone") or find_directive_exists(combined, "limit_conn")

    # --- disable_symlinks ---
    disable_symlinks_configured = find_directive_exists(combined, "disable_symlinks")

    # --- Logging ---
    has_access_log_off = bool(re.search(r"access_log\s+off", combined))

    # --- Error pages ---
    error_page_uses_root_html = bool(re.search(r"error_page\s+", combined)) and bool(re.search(r"root\s+html", combined))

    # --- Open redirect ---
    has_open_redirect_risk = bool(re.search(r"rewrite\s+\^\S+\s+https?://\$", combined)) or bool(re.search(r"return\s+30[12]\s+https?://\$", combined))

    # --- Nginx user ---
    nginx_runs_as_nobody = bool(re.search(r"user\s+nobody", combined))

    # --- Worker ---
    worker_processes_values = find_directive_values(combined, "worker_processes")
    worker_processes_one = any(v.strip() == "1" for v in worker_processes_values)
    worker_connections_values = find_directive_values(combined, "worker_connections")
    worker_connections_value = int(worker_connections_values[0]) if worker_connections_values else 1024

    # --- Upstream ---
    ip_hash_blocks = re.findall(r"upstream\s+[^\s{]+\s*\{[^}]*ip_hash[^}]*\}", combined, re.DOTALL)
    ip_hash_no_backup = len(ip_hash_blocks) > 0 and not any("backup" in b for b in ip_hash_blocks)
    upstream_keepalive_configured = bool(re.search(r"keepalive\s+\d+", combined))

    # Upstream duplicate server
    upstream_has_duplicate_server = False
    for m in re.finditer(r"upstream\s+[^\s{]+\s*\{([^}]+)\}", combined, re.DOTALL):
        servers_in_upstream = re.findall(r"server\s+(\S+);", m.group(1))
        if len(servers_in_upstream) != len(set(servers_in_upstream)):
            upstream_has_duplicate_server = True

    # --- Real IP ---
    real_ip_configured = find_directive_exists(combined, "set_real_ip_from")

    # --- if in location ("If Is Evil") ---
    has_if_in_location = False
    for s in server_blocks:
        if s.get("has_if_in_location"):
            has_if_in_location = True

    # --- Lua session ---
    has_lua_at_server = any(s["has_lua_access"] for s in server_blocks)
    lua_locations_covered = sum(1 for s in server_blocks if s["has_lua_access"] for _ in s["locations"])
    total_server_locations = sum(len(s["locations"]) for s in server_blocks)
    lua_session_partial = has_lua_at_server and lua_locations_covered < total_server_locations

    # --- Lua shared dict ---
    has_lua_shared_dict = find_directive_exists(combined, "lua_shared_dict")

    # --- Log format ---
    log_format_names = re.findall(r"log_format\s+(\w+)\s+", combined)
    seen_names = set()
    duplicate_log_format_count = 0
    for name in log_format_names:
        if name in seen_names:
            duplicate_log_format_count += 1
        seen_names.add(name)

    log_escape_chars = re.findall(r"log_escape_char\s+'([^']+)'\s+\"([^\"]+)\"", combined)
    escape_sources = {}
    log_escape_char_error = False
    for char, target in log_escape_chars:
        if char in escape_sources and escape_sources[char] != target:
            log_escape_char_error = True
        escape_sources[char] = target
    char_counts = {}
    for char, _ in log_escape_chars:
        char_counts[char] = char_counts.get(char, 0) + 1
    if any(c > 1 for c in char_counts.values()):
        log_escape_char_error = True

    # --- Cache-Control for sensitive content ---
    sensitive_no_cache_control = bool(re.search(r"proxy_pass\s+", combined)) and not bool(re.search(r"Cache-Control.*no-store", combined))

    # --- Per-config summaries ---
    config_summaries = {}
    evidence_catalog = {}
    server_level_facts = []
    for name, content in config_texts.items():
        cfg_servers = extract_server_blocks(content)
        server_level_facts.extend(extract_server_blocks_with_meta(content, name))
        cfg_listens = [s["listen"] for s in cfg_servers]
        cfg_tls = sorted({
            proto
            for v in find_directive_values(content, "ssl_protocols")
            for proto in v.split()
        })
        cfg_server_names = [s["server_name"] for s in cfg_servers]
        cfg_headers = []
        for v in find_directive_values(content, "add_header"):
            hn = v.split()[0].strip('"').strip("'").lower()
            if hn in SECURITY_HEADERS:
                cfg_headers.append(SECURITY_HEADERS[hn])
        cfg_locations = find_location_blocks(content)
        cfg_tokens_off = find_server_tokens_off(content)
        config_summaries[name] = {
            "listen_ports": cfg_listens,
            "tls_protocols": cfg_tls,
            "server_names": cfg_server_names,
            "security_headers": cfg_headers,
            "locations": cfg_locations,
            "server_tokens_off": cfg_tokens_off,
            "server_blocks": cfg_servers,
        }
        evidence_catalog[name] = {
            "scope_refs": find_line_refs(content, ["http {", "server {", "location "], name),
            "tls_protocols": find_line_refs(content, ["ssl_protocols"], name),
            "security_headers": find_line_refs(content, ["add_header"], name),
            "autoindex": find_line_refs(content, ["autoindex"], name),
            "server_tokens_off": find_line_refs(content, ["server_tokens"], name),
            "locations": find_line_refs(content, ["location "], name),
            "http_redirects_to_https": find_line_refs(content, ["listen 80", "listen 8080", "listen 8081", "return 301 https://", "return 302 https://"], name),
            "http_https_same_block": find_line_refs(content, ["listen 80", "listen 8080", "listen 8081", "listen 443", "ssl"], name),
            "has_empty_server_name": find_line_refs(content, ["server_name ;"], name),
            "cookie_has_secure_flag": find_line_refs(content, ["proxy_cookie_path"], name),
            "cookie_has_samesite": find_line_refs(content, ["proxy_cookie_path"], name),
            "weak_cipher_keywords": find_line_refs(content, ["ssl_ciphers"], name),
            "ssl_ciphers_defined": find_line_refs(content, ["ssl_ciphers"], name),
            "ssl_session_cache_configured": find_line_refs(content, ["ssl_session_cache"], name),
            "ocsp_stapling_enabled": find_line_refs(content, ["ssl_stapling"], name),
            "status_pages_without_acl": find_line_refs(content, ["/status", "/vstatus", "/healthcheck", "/health_status"], name),
            "alias_try_files_pairs_count": find_line_refs(content, ["alias", "try_files"], name),
            "options_returns_403": find_line_refs(content, ["$request_method", "return 403"], name),
            "cookie_contains_org_code": find_line_refs(content, ["org_code="], name),
            "rate_limited_locations_ratio": find_line_refs(content, ["limit_rate", "limit_req"], name),
            "limit_conn_configured": find_line_refs(content, ["limit_conn_zone", "limit_conn"], name),
            "duplicate_log_format_count": find_line_refs(content, ["log_format"], name),
            "log_escape_char_error": find_line_refs(content, ["log_escape_char"], name),
            "proxy_pass_https_without_verify": find_line_refs(content, ["proxy_pass https://", "proxy_ssl_verify"], name),
            "proxy_pass_http_backend": find_line_refs(content, ["proxy_pass http://"], name),
            "lua_session_partial": find_line_refs(content, ["access_by_lua", "location "], name),
            "ip_hash_no_backup": find_line_refs(content, ["ip_hash", "backup"], name),
            "upstream_has_duplicate_server": find_line_refs(content, ["upstream ", "server "], name),
            "proxy_hide_headers_configured": find_line_refs(content, ["proxy_hide_header"], name),
            "http_methods_limited": find_line_refs(content, ["limit_except"], name),
            "hidden_files_blocked": find_line_refs(content, [r"/\\.", "/."], name),
            "disable_symlinks_configured": find_line_refs(content, ["disable_symlinks"], name),
            "upload_dir_execution_blocked": find_line_refs(content, ["upload", "merchantupload", r".php", "deny all"], name),
            "client_max_body_size_unlimited": find_line_refs(content, ["client_max_body_size"], name),
            "proxy_timeout_configured": find_line_refs(content, ["proxy_connect_timeout", "proxy_read_timeout", "proxy_send_timeout"], name),
            "has_access_log_off": find_line_refs(content, ["access_log off"], name),
            "error_page_uses_root_html": find_line_refs(content, ["error_page", "root html"], name),
            "has_open_redirect_risk": find_line_refs(content, ["rewrite", "return 301", "return 302"], name),
            "nginx_runs_as_nobody": find_line_refs(content, ["user nobody"], name),
            "worker_processes_one": find_line_refs(content, ["worker_processes"], name),
            "worker_connections_value": find_line_refs(content, ["worker_connections"], name),
            "upstream_keepalive_configured": find_line_refs(content, ["keepalive"], name),
            "real_ip_configured": find_line_refs(content, ["set_real_ip_from", "real_ip_header"], name),
            "has_if_in_location": find_line_refs(content, ["if ("], name),
            "ssl_prefer_server_ciphers_on": find_line_refs(content, ["ssl_prefer_server_ciphers"], name),
            "has_lua_shared_dict": find_line_refs(content, ["lua_shared_dict"], name),
            "proxy_redirect_has_invalid_value": find_line_refs(content, ["proxy_redirect"], name),
            "proxy_buffer_configured": find_line_refs(content, ["proxy_buffer_size", "proxy_buffers"], name),
            "sensitive_no_cache_control": find_line_refs(content, ["cache-control", "proxy_pass"], name),
        }

    return {
        "autoindex": autoindex,
        "tls_protocols": tls_protocols,
        "ssl_ciphers": ssl_ciphers,
        "ssl_ciphers_defined": ssl_ciphers_defined,
        "ssl_session_cache_configured": ssl_session_cache_configured,
        "ssl_prefer_server_ciphers_on": ssl_prefer_server_ciphers_on,
        "ocsp_stapling_enabled": ocsp_stapling_enabled,
        "security_headers": sorted(set(security_headers)),
        "locations": locations,
        "upstreams": sorted(set(upstreams)),
        "server_tokens_off": find_server_tokens_off(combined),
        "deny_all_present": find_deny_all(combined),
        "http_redirects_to_https": http_redirects_to_https,
        "http_https_same_block": http_https_same_block,
        "has_empty_server_name": has_empty_server_name,
        "nginx_t_failed": nginx_t_failed,
        "user_directive_misplaced": user_directive_misplaced,
        "cookie_has_secure_flag": cookie_has_secure_flag,
        "cookie_has_samesite": cookie_has_samesite,
        "cookie_contains_org_code": cookie_contains_org_code,
        "weak_cipher_keywords": sorted(set(weak_keywords)),
        "status_pages_without_acl": status_pages_without_acl,
        "alias_try_files_pairs_count": alias_try_files_pairs_count,
        "options_returns_403": options_returns_403,
        "http_methods_limited": http_methods_limited,
        "hidden_files_blocked": hidden_files_blocked,
        "upload_dir_execution_blocked": upload_dir_execution_blocked,
        "client_max_body_size_unlimited": client_max_body_size_unlimited,
        "rate_limited_locations_ratio": rate_limited_locations_ratio,
        "limit_conn_configured": limit_conn_configured,
        "disable_symlinks_configured": disable_symlinks_configured,
        "has_access_log_off": has_access_log_off,
        "error_page_uses_root_html": error_page_uses_root_html,
        "has_open_redirect_risk": has_open_redirect_risk,
        "nginx_runs_as_nobody": nginx_runs_as_nobody,
        "worker_processes_one": worker_processes_one,
        "worker_connections_value": worker_connections_value,
        "upstream_keepalive_configured": upstream_keepalive_configured,
        "upstream_has_duplicate_server": upstream_has_duplicate_server,
        "proxy_pass_https_without_verify": proxy_pass_https_without_verify,
        "proxy_pass_http_backend": proxy_pass_http_backend,
        "proxy_hide_headers_configured": proxy_hide_headers_configured,
        "proxy_timeout_configured": proxy_timeout_configured,
        "proxy_buffer_configured": proxy_buffer_configured,
        "proxy_redirect_has_invalid_value": proxy_redirect_has_invalid_value,
        "real_ip_configured": real_ip_configured,
        "has_if_in_location": has_if_in_location,
        "lua_session_partial": lua_session_partial,
        "has_lua_shared_dict": has_lua_shared_dict,
        "ip_hash_no_backup": ip_hash_no_backup,
        "duplicate_log_format_count": duplicate_log_format_count,
        "log_escape_char_error": log_escape_char_error,
        "sensitive_no_cache_control": sensitive_no_cache_control,
        "total_locations": total_locations,
        "rate_limited_locations": rate_limited_locations,
        "config_count": len(config_texts),
        "config_summaries": config_summaries,
        "evidence_catalog": evidence_catalog,
        "server_level_facts": server_level_facts,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task3" / "json"
    raw_dir = run_dir / "task3" / "raw"

    configs = read_all_configs(raw_dir)
    facts = extract_all_facts(configs)

    record = make_base_record(run_dir.name, "task3", "parse_config_facts.py")
    record.update(facts)
    dump_json(json_dir / "task3_config_facts.json", record)


if __name__ == "__main__":
    main()
