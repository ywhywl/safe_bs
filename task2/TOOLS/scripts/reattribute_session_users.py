#!/usr/bin/env python3

"""Re-attribute session-level user identity to protocol events.

mod_sftp protocol negotiation events (CLIENT_VERSION, KEXINIT, HOSTKEY,
CIPHER_C2S, etc.) carry user="unknown" because the user identity is only
established during AUTH events. This script:

1. First pass: find real user for each session_id from AUTH/LOGIN events
2. Second pass: replace user="unknown" with inferred real user
3. Write updated events back (streaming, batch writes)

This makes build_baseline.py produce meaningful baselines for real users
instead of dumping everything into the "unknown" bucket.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from event_io import iter_ndjson
from lib import dump_json, load_json, make_base_record

BATCH_SIZE = 10000


def build_session_user_map(events_path: Path) -> dict[str, str]:
    """Phase 1: scan events to find real user for each session_id."""
    session_users: dict[str, str] = {}
    for event in iter_ndjson(events_path):
        user = event.get("user", "unknown")
        session_id = event.get("session_id", "")
        result = event.get("result", "")
        action = event.get("action", "")
        if not session_id:
            continue
        if user in {"unknown", "", "USER"}:
            continue
        if action in {"AUTH", "LOGIN"} and result in {"ok", ""}:
            current = session_users.get(session_id, "")
            if current in {"unknown", "", "USER"} or not current:
                session_users[session_id] = user
            elif result == "ok" and current != user:
                session_users[session_id] = user
    return session_users


def reattribute_file(source_path: Path, dest_path: Path, session_users: dict[str, str]) -> tuple[int, int]:
    """Phase 2: stream through source, re-attribute unknown users, write to dest."""
    dest_path.unlink(missing_ok=True)
    reattributed = 0
    total = 0
    batch: list[str] = []

    with source_path.open("r", encoding="utf-8") as reader:
        for line in reader:
            stripped = line.strip()
            if not stripped:
                continue
            event = json.loads(stripped)
            total += 1

            user = event.get("user", "unknown")
            session_id = event.get("session_id", "")
            if user in {"unknown", "", "USER"} and session_id in session_users:
                inferred = session_users[session_id]
                event["user"] = inferred
                event["user_inferred_from_session"] = True
                reattributed += 1

            batch.append(json.dumps(event, ensure_ascii=False, separators=(",", ":")))
            if len(batch) >= BATCH_SIZE:
                with dest_path.open("a", encoding="utf-8", buffering=65536) as writer:
                    writer.write("\n".join(batch) + "\n")
                batch = []

    if batch:
        with dest_path.open("a", encoding="utf-8", buffering=65536) as writer:
            writer.write("\n".join(batch) + "\n")

    return reattributed, total


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task2" / "json"
    events_path = json_dir / "task2_events.ndjson"
    baseline_path = json_dir / "task2_baseline_events.ndjson"

    # Phase 1: Build session → user map from events (and baseline if exists)
    print("  [reattribute] Phase 1: building session-user map ...", file=sys.stderr, flush=True)
    session_users = build_session_user_map(events_path)
    if baseline_path.exists():
        baseline_map = build_session_user_map(baseline_path)
        # Merge: prefer known users from either source
        for sid, user in baseline_map.items():
            if session_users.get(sid, "") in {"unknown", "", "USER"}:
                session_users[sid] = user

    print(f"  [reattribute] Found {len(session_users)} sessions with real user", file=sys.stderr, flush=True)

    # Phase 2: Re-attribute events
    print("  [reattribute] Phase 2: re-attributing events ...", file=sys.stderr, flush=True)

    total_reattributed = 0
    total_events = 0

    # Main events: source → tmp → replace
    if events_path.exists():
        tmp_path = json_dir / "task2_events.ndjson.tmp"
        r, t = reattribute_file(events_path, tmp_path, session_users)
        total_reattributed += r
        total_events += t
        import os
        os.replace(str(tmp_path), str(events_path))

    # Baseline events: source → tmp → replace
    if baseline_path.exists():
        tmp_path = json_dir / "task2_baseline_events.ndjson.tmp"
        r, t = reattribute_file(baseline_path, tmp_path, session_users)
        total_reattributed += r
        total_events += t
        import os
        os.replace(str(tmp_path), str(baseline_path))

    # Update metadata
    events_meta = load_json(json_dir / "task2_events.json", {})
    events_meta["reattributed_event_count"] = total_reattributed
    events_meta["session_user_map_size"] = len(session_users)
    events_meta["reattribution_done"] = True
    dump_json(json_dir / "task2_events.json", events_meta)

    # Write attribution record
    record = make_base_record(run_dir.name, "task2", "reattribute_session_users.py")
    record["reattributed_count"] = total_reattributed
    record["total_event_count"] = total_events
    record["session_user_map_size"] = len(session_users)
    record["session_user_map_sample"] = dict(list(session_users.items())[:20])
    dump_json(json_dir / "task2_session_user_attribution.json", record)

    pct = round(total_reattributed / max(total_events, 1) * 100, 1)
    print(f"  [reattribute] {total_reattributed:,}/{total_events:,} events re-attributed ({pct}%)", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()