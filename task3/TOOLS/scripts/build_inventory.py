#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from pathlib import Path

from lib import dump_json, make_base_record, read_text


def parse_nginx_version(raw_dir: Path) -> str:
    path = raw_dir / "nginx_V.txt"
    if not path.exists():
        return ""
    content = read_text(path)
    match = re.search(r"nginx/([^\s]+)", content)
    return match.group(1) if match else ""


def parse_listeners(raw_dir: Path) -> list[str]:
    path = raw_dir / "nginx_T.txt"
    if not path.exists():
        return []
    listeners = []
    for line in read_text(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("listen "):
            listeners.append(stripped.removesuffix(";"))
    return sorted(set(listeners))


def parse_server_names(raw_dir: Path) -> list[str]:
    path = raw_dir / "nginx_T.txt"
    if not path.exists():
        return []
    names = []
    for line in read_text(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("server_name "):
            names.append(stripped.removesuffix(";"))
    return names


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--target", default="")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task3" / "json"
    raw_dir = run_dir / "task3" / "raw"
    record = make_base_record(run_dir.name, "task3", "build_inventory.py")
    record.update(
        {
            "hosts": [{"host": args.target, "roles": ["nginx"], "ports": []}],
            "nginx_version": parse_nginx_version(raw_dir),
            "modules": [],
            "listeners": parse_listeners(raw_dir),
            "server_blocks": parse_server_names(raw_dir),
        }
    )
    dump_json(json_dir / "task3_nginx_inventory.json", record)
    host_profile = make_base_record(run_dir.name, "task3", "build_inventory.py")
    host_profile.update(
        {
            "target_host": args.target,
            "access_mode": "readonly",
            "collection_constraints": ["no remote modification", "read-only inspection"],
        }
    )
    dump_json(json_dir / "task3_host_profile.json", host_profile)


if __name__ == "__main__":
    main()
