#!/usr/bin/env python3

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator
from zlib import crc32


PIPE_SPLIT_RE = re.compile(r"\|+")
PROGRAM_LOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+"
    r"(?P<host>\S+)\s+proftpd\[(?P<pid>\d+)\]:\s+"
    r"(?P<server_ip>\S+)\s+\((?P<client_ip>[^\[]+)\[(?P<client_ip_dup>[^\]]+)\]\):\s+"
    r"(?P<message>.+)$"
)
MOD_SFTP_PREFIX_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+mod_sftp/0\.9\.9\[(?P<pid>\d+)\]:\s+(?P<message>.+)$"
)
MOD_SFTP_CONTINUATION_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\s+\[(?P<pid>\d+)\]:\s+(?P<message>.+)$"
)
MOD_SFTP_DETAIL_RE = re.compile(
    r"^(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+(?P<user>\S+)\s+(?P<message>.+)$"
)
MOD_SFTP_IP_ONLY_RE = re.compile(
    r"^(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+(?P<message>.+)$"
)


def guess_log_format(path: Path) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                if "AuthSuccess" in stripped and "publickey" in stripped:
                    return "sftp_runtime_pipe"
                if "proftpd[" in stripped and ("SSH2 session" in stripped or "Login successful" in stripped or "Login failed" in stripped):
                    return "sftp_program_proftpd"
                if "mod_sftp/0.9.9" in stripped or re.search(r"\[\d+\]:", stripped):
                    return "sftp_protocol_mod_sftp"
                if "=" in stripped and "timestamp=" in stripped:
                    return "key_value"
                return "plain_text"
    except OSError:
        return "unknown"
    return "unknown"


def normalize_timestamp(raw: str) -> str:
    if "T" in raw:
        return raw
    return raw.replace(" ", "T")


def build_event_id(source: Path, idx: int) -> str:
    source_id = crc32(str(source).encode("utf-8")) & 0xFFFFFFFF
    return f"evt-{source_id:x}-{idx}"


def make_event(source: Path, idx: int, timestamp: str, user: str, src_ip: str, session_id: str, action: str, path: str,
               result: str, bytes_in: int, bytes_out: int, event_class: str, **extra: str | int) -> dict:
    event = {
        "event_id": build_event_id(source, idx),
        "timestamp": timestamp,
        "user": user,
        "src_ip": src_ip,
        "src_subnet": "",
        "session_id": session_id,
        "action": action,
        "path": path,
        "result": result,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "event_class": event_class,
    }
    for key, value in extra.items():
        if value in ("", None, 0):
            continue
        event[key] = value
    return event


def parse_runtime_pipe_line(line: str, idx: int, source: Path) -> dict | None:
    parts = [part.strip() for part in PIPE_SPLIT_RE.split(line.strip()) if part.strip()]
    if len(parts) < 11:
        return None
    timestamp = parts[0]
    server_ip = parts[1]
    system_name = parts[2]
    session_id = parts[3]
    src_ip = parts[4]
    client_version = parts[5]
    user = parts[6]
    auth_method = parts[7]
    result_flag = parts[9]
    message = parts[10] if len(parts) > 10 else ""
    action = "AUTH"
    result_code = result_flag
    if "AuthSuccess" in result_flag:
        result_code = "ok"
    elif "AuthFail" in result_flag or "AuthFailure" in result_flag:
        result_code = "fail"
    return make_event(
        source,
        idx,
        normalize_timestamp(timestamp),
        user,
        src_ip,
        session_id,
        action,
        "",
        result_code,
        0,
        0,
        "auth",
        server_ip=server_ip,
        system_name=system_name,
        client_version=client_version,
        auth_method=auth_method,
    )


def parse_program_log_line(line: str, idx: int, source: Path) -> dict | None:
    match = PROGRAM_LOG_RE.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    message = data["message"]
    action = "PROGRAM"
    result = "unknown"
    event_class = "program"
    user = "unknown"

    lowered = message.lower()
    if "ssh2 session opened" in lowered:
        action = "SESSION_OPEN"
        result = "ok"
        event_class = "session"
    elif "ssh2 session closed" in lowered:
        action = "SESSION_CLOSE"
        result = "ok"
        event_class = "session"
    elif "login successful" in lowered:
        action = "LOGIN"
        result = "ok"
        event_class = "auth"
        user_match = re.search(r"USER\s+([^\s:]+)", message)
        if user_match:
            user = user_match.group(1)
    elif "login failed" in lowered:
        action = "LOGIN"
        result = "fail"
        event_class = "auth"
        user_match = re.search(r"USER\s+([^\s:]+)", message)
        if user_match:
            user = user_match.group(1)

    return make_event(
        source,
        idx,
        normalize_timestamp(data["ts"]),
        user,
        data["client_ip_dup"],
        data["pid"],
        action,
        "",
        result,
        0,
        0,
        event_class,
        server_ip=data["server_ip"],
        system_name=data["host"],
    )


def parse_mod_sftp_log_line(line: str, idx: int, source: Path) -> dict | None:
    match = MOD_SFTP_PREFIX_RE.match(line.strip()) or MOD_SFTP_CONTINUATION_RE.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    message = data["message"]
    lowered = message.lower()
    event = make_event(
        source,
        idx,
        normalize_timestamp(data["ts"]),
        "unknown",
        "",
        data["pid"],
        "PROTOCOL",
        "",
        "",
        0,
        0,
        "protocol",
    )

    detail_match = MOD_SFTP_DETAIL_RE.match(message)
    if detail_match:
        detail = detail_match.groupdict()
        event["src_ip"] = detail["src_ip"]
        candidate_user = detail["user"]
        if candidate_user not in {"-", "unknown", "USER"} and not candidate_user.isupper():
            event["user"] = candidate_user
        message = f"{candidate_user} {detail['message']}"
        lowered = message.lower()
    else:
        ip_only_match = MOD_SFTP_IP_ONLY_RE.match(message)
        if ip_only_match:
            detail = ip_only_match.groupdict()
            event["src_ip"] = detail["src_ip"]
            message = detail["message"]
            lowered = message.lower()

    def _val() -> str:
        return message.split(":", 1)[1].strip() if ":" in message else ""

    if "received client version" in lowered:
        event["action"] = "CLIENT_VERSION"
        version_match = re.search(r"received client version '([^']+)'", message, re.IGNORECASE)
        if version_match:
            event["client_version"] = version_match.group(1)
        event["result"] = "ok"
    elif "sent server version" in lowered:
        event["action"] = "SERVER_VERSION"
        event["result"] = "ok"
    elif "handling connection from ssh2 client" in lowered:
        event["action"] = "CLIENT_CONNECT"
        version_match = re.search(r"ssh2 client '([^']+)'", message, re.IGNORECASE)
        if version_match:
            event["client_version"] = version_match.group(1)
        event["result"] = "ok"
    elif "session key exchange:" in lowered:
        event["action"] = "KEXINIT"
        event["kex_algorithm"] = _val()
        event["result"] = "ok"
    elif "session server hostkey:" in lowered:
        event["action"] = "HOSTKEY"
        event["hostkey_algorithm"] = _val()
        event["result"] = "ok"
    elif "session client-to-server encryption:" in lowered:
        event["action"] = "CIPHER_C2S"
        event["cipher_c2s"] = _val()
        event["result"] = "ok"
    elif "session server-to-client encryption:" in lowered:
        event["action"] = "CIPHER_S2C"
        event["cipher_s2c"] = _val()
        event["result"] = "ok"
    elif "session client-to-server mac:" in lowered:
        event["action"] = "MAC_C2S"
        event["mac_c2s"] = _val()
        event["result"] = "ok"
    elif "session server-to-client mac:" in lowered:
        event["action"] = "MAC_S2C"
        event["mac_s2c"] = _val()
        event["result"] = "ok"
    elif "userauth_request" in lowered:
        event["action"] = "USERAUTH_REQUEST"
        event["event_class"] = "auth"
    elif "password required for" in lowered:
        event["action"] = "AUTH_METHOD_REQUIRED"
        event["auth_method"] = "password"
        event["result"] = "challenge"
        event["event_class"] = "auth"
        user_match = re.search(r"(?:user\s+)?(\S+)\s+password required for\s+(\S+)", message, re.IGNORECASE)
        if user_match:
            event["user"] = user_match.group(2)
    elif "sending acceptable userauth methods:" in lowered:
        event["action"] = "AUTH_METHODS"
        event["acceptable_auth_methods"] = _val()
        event["event_class"] = "auth"
    elif "sending publickey ok" in lowered:
        event["action"] = "PUBLICKEY_OK"
        event["auth_method"] = "publickey"
        event["result"] = "ok"
        event["event_class"] = "auth"
    elif "sending userauth success" in lowered or "authenticated via 'publickey' method" in lowered:
        event["action"] = "AUTH"
        event["auth_method"] = "publickey"
        event["result"] = "ok"
        user_match = re.search(r"user '([^']+)' authenticated", message, re.IGNORECASE)
        if user_match:
            event["user"] = user_match.group(1)
        event["event_class"] = "auth"
    elif "login incorrect" in lowered:
        event["action"] = "AUTH"
        event["result"] = "fail"
        event["event_class"] = "auth"
    elif "pass (hidden)" in lowered and "logged in" in lowered:
        event["action"] = "LOGIN"
        event["result"] = "ok"
        event["event_class"] = "auth"
        user_match = re.search(r"user\s+(\S+)\s+logged in", message, re.IGNORECASE)
        if user_match:
            event["user"] = user_match.group(1)
    elif "public key md5 fingerprint" in lowered:
        event["action"] = "PUBLICKEY_FINGERPRINT"
        event["publickey_fingerprint_md5"] = _val()
        event["event_class"] = "auth"
    elif "newkeys" in lowered:
        event["action"] = "NEWKEYS"
        event["event_class"] = "protocol"
        event["result"] = "ok"
    elif "'subsystem' channel request for 'sftp' subsystem" in lowered:
        event["action"] = "SUBSYSTEM_SFTP"
        event["event_class"] = "session"
        event["result"] = "ok"
    elif "using sftp protocol version" in lowered:
        event["action"] = "SFTP_PROTOCOL"
        proto_match = re.search(r"using sftp protocol version (\d+)", message, re.IGNORECASE)
        if proto_match:
            event["sftp_protocol_version"] = proto_match.group(1)
        event["event_class"] = "session"
        event["result"] = "ok"
    elif "realpath" in lowered:
        event["action"] = "REALPATH"
        path_match = re.search(r"realpath\s+(\S+)", message, re.IGNORECASE)
        if path_match:
            event["path"] = path_match.group(1)
        event["event_class"] = "generic"
        event["result"] = "ok"
    elif "requested read offset" in lowered:
        event["action"] = "READ_OFFSET_ERROR"
        path_match = re.search(r"size of '([^']+)'", message, re.IGNORECASE)
        if path_match:
            event["path"] = path_match.group(1)
        event["result"] = "error"
        event["event_class"] = "generic"
    elif "disconnecting client" in lowered:
        event["action"] = "SESSION_CLOSE"
        event["event_class"] = "session"
        event["result"] = "closed"

    return event


def iter_lines(path: Path) -> Iterator[tuple[int, str]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for idx, line in enumerate(handle, start=1):
            if line.strip():
                yield idx, line.rstrip("\n")
