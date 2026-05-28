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
    return {
        "event_id": build_event_id(source, idx),
        "timestamp": normalize_timestamp(timestamp),
        "user": user,
        "src_ip": src_ip,
        "src_subnet": "",
        "session_id": session_id,
        "action": action,
        "path": "",
        "result": result_code,
        "bytes_in": 0,
        "bytes_out": 0,
        "raw_ref": {"line_no": idx, "source": str(source)},
        "confidence": "high",
        "raw_line": line.strip(),
        "server_ip": server_ip,
        "system_name": system_name,
        "client_version": client_version,
        "auth_method": auth_method,
        "message": message,
        "event_class": "auth",
    }


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

    return {
        "event_id": build_event_id(source, idx),
        "timestamp": normalize_timestamp(data["ts"]),
        "user": user,
        "src_ip": data["client_ip_dup"],
        "src_subnet": "",
        "session_id": data["pid"],
        "action": action,
        "path": "",
        "result": result,
        "bytes_in": 0,
        "bytes_out": 0,
        "raw_ref": {"line_no": idx, "source": str(source)},
        "confidence": "high",
        "raw_line": line.strip(),
        "server_ip": data["server_ip"],
        "system_name": data["host"],
        "client_version": "",
        "auth_method": "",
        "message": message,
        "event_class": event_class,
    }


def iter_lines(path: Path) -> Iterator[tuple[int, str]]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for idx, line in enumerate(handle, start=1):
            if line.strip():
                yield idx, line.rstrip("\n")
