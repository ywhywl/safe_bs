#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
import sys
from functools import lru_cache
from ipaddress import ip_address
from pathlib import Path

from event_io import write_ndjson_line
from input_layout import iter_log_files, resolve_input_layout
from lib import dump_json, load_json, make_base_record
from log_formats import build_event_id, guess_log_format, iter_lines, parse_mod_sftp_log_line, parse_program_log_line, parse_runtime_pipe_line


KNOWN_KEYS = {
    "timestamp",
    "time",
    "user",
    "src_ip",
    "ip",
    "session_id",
    "session",
    "action",
    "path",
    "result",
    "status",
    "bytes_in",
    "bytes_out",
}


@lru_cache(maxsize=4096)
def parse_subnet(value: str) -> str:
    try:
        addr = ip_address(value)
    except ValueError:
        return ""
    if addr.version == 4:
        parts = value.split(".")
        return ".".join(parts[:3]) + ".0/24"
    groups = value.split(":")
    return ":".join(groups[:4]) + "::/64"


TIMESTAMP_TWO_FIELD_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+$")
TIMESTAMP_LOOKS_RE = re.compile(r"^\d{2}:\d{2}:\d{2}")
IP_PATTERN_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def parse_kv_line(line: str) -> dict[str, str]:
    result = {}
    for token in line.strip().split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key in KNOWN_KEYS:
            result[key] = value
    return result


def parse_line(line: str, idx: int, source_path: Path) -> dict:
    kv = parse_kv_line(line)
    if kv:
        timestamp = kv.get("timestamp") or kv.get("time", "")
        user = kv.get("user", "unknown")
        src_ip = kv.get("src_ip") or kv.get("ip", "unknown")
        session_id = kv.get("session_id") or kv.get("session", "")
        action = kv.get("action", "")
        path = kv.get("path", "")
        result = kv.get("result") or kv.get("status", "")
        bytes_in = int(kv.get("bytes_in", "0") or "0")
        bytes_out = int(kv.get("bytes_out", "0") or "0")
    else:
        parts = line.strip().split()
        # Detect timestamp spanning two space-separated parts (e.g. "2026-05-25 00:01:01,605")
        offset = 0
        if len(parts) >= 2 and TIMESTAMP_TWO_FIELD_RE.match(parts[0] + " " + parts[1]):
            timestamp = parts[0] + " " + parts[1]
            offset = 2
        else:
            timestamp = parts[0] if parts else ""

        user = parts[offset] if len(parts) > offset else "unknown"
        # Validate: a timestamp-like string (HH:MM:SS) is not a valid username
        if TIMESTAMP_LOOKS_RE.match(user):
            user = "unknown"
        src_ip = parts[offset + 1] if len(parts) > offset + 1 else "unknown"
        # Validate: src_ip should look like an IP address
        if not IP_PATTERN_RE.match(src_ip):
            src_ip = "unknown"
        session_id = parts[offset + 2] if len(parts) > offset + 2 else ""
        action = parts[offset + 3] if len(parts) > offset + 3 else ""
        path = parts[offset + 4] if len(parts) > offset + 4 else ""
        result = parts[offset + 5] if len(parts) > offset + 5 else ""
        bytes_in = int(parts[offset + 6]) if len(parts) > offset + 6 and parts[offset + 6].isdigit() else 0
        bytes_out = int(parts[offset + 7]) if len(parts) > offset + 7 and parts[offset + 7].isdigit() else 0

    return {
        "event_id": build_event_id(source_path, idx),
        "timestamp": timestamp,
        "user": user,
        "src_ip": src_ip,
        "src_subnet": parse_subnet(src_ip),
        "session_id": session_id,
        "action": action,
        "path": path,
        "result": result,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "event_class": "generic",
    }


def enrich_subnet(event: dict) -> dict:
    src_ip = event.get("src_ip", "")
    if src_ip and not event.get("src_subnet"):
        event["src_subnet"] = parse_subnet(src_ip)
    return event


BATCH_FLUSH_SIZE = 10000
PROGRESS_PRINT_INTERVAL = 100000


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--input-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    input_dir = Path(args.input_dir)
    json_dir = run_dir / "task2" / "json"
    layout = resolve_input_layout(input_dir)

    def normalize_files(paths: list[Path], ndjson_path: Path, role: str) -> tuple[int, dict[str, int], list[dict]]:
        preview = []
        format_counts: dict[str, int] = {}
        count = 0
        ndjson_path.unlink(missing_ok=True)
        if not paths:
            return count, format_counts, preview
        batch: list[str] = []
        with ndjson_path.open("w", encoding="utf-8", buffering=65536) as out:
            for path in paths:
                format_guess = guess_log_format(path)
                format_counts[format_guess] = format_counts.get(format_guess, 0) + 1
                for idx, line in iter_lines(path):
                    event = None
                    if format_guess == "sftp_runtime_pipe":
                        event = parse_runtime_pipe_line(line, idx, path)
                    elif format_guess == "sftp_program_proftpd":
                        event = parse_program_log_line(line, idx, path)
                    elif format_guess == "sftp_protocol_mod_sftp":
                        event = parse_mod_sftp_log_line(line, idx, path)
                    if event is None:
                        event = parse_line(line, idx, path)
                    event = enrich_subnet(event)
                    batch.append(json.dumps(event, ensure_ascii=False, separators=(",", ":")))
                    count += 1
                    if len(preview) < 200:
                        preview.append(event)
                    if len(batch) >= BATCH_FLUSH_SIZE:
                        out.write("\n".join(batch) + "\n")
                        batch.clear()
                    if count % PROGRESS_PRINT_INTERVAL == 0:
                        print(f"  [{role}] processed {count:,} events ...", file=sys.stderr, flush=True)
                # per-file progress
                print(f"  [{role}] finished {path.name}, total {count:,} events", file=sys.stderr, flush=True)
            if batch:
                out.write("\n".join(batch) + "\n")
        return count, format_counts, preview

    current_files = iter_log_files(layout.current_dir)
    baseline_files = iter_log_files(layout.baseline_dir) if layout.baseline_dir else []
    current_count, current_format_counts, events_preview = normalize_files(current_files, json_dir / "task2_events.ndjson", "current")
    baseline_count, baseline_format_counts, baseline_preview = normalize_files(
        baseline_files,
        json_dir / "task2_baseline_events.ndjson",
        "baseline",
    ) if baseline_files else (0, {}, [])

    record = make_base_record(run_dir.name, "task2", "normalize_events.py")
    record["dataset_mode"] = layout.mode
    record["event_count"] = current_count
    record["baseline_event_count"] = baseline_count
    record["format_counts"] = current_format_counts
    record["baseline_format_counts"] = baseline_format_counts
    record["events_preview"] = events_preview
    record["baseline_events_preview"] = baseline_preview
    dump_json(json_dir / "task2_events.json", record)


if __name__ == "__main__":
    main()
