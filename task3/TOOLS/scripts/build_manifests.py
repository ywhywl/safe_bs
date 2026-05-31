#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, make_base_record
from tooling import resolve_tool


def build_tool_manifest(run_id: str, task_id: str) -> dict:
    record = make_base_record(run_id, task_id, "build_manifests.py")
    record.update(
        {
            "tools": [
                {"name": "python3", "path": resolve_tool("python3"), "required": True},
                {"name": "ssh", "path": resolve_tool("ssh"), "required": False},
                {"name": "curl", "path": resolve_tool("curl"), "required": False},
                {"name": "openssl", "path": resolve_tool("openssl"), "required": False},
                {"name": "nmap", "path": resolve_tool("nmap"), "required": False},
                {"name": "searchsploit", "path": resolve_tool("searchsploit"), "required": False},
            ]
        }
    )
    return record


def build_ai_trace(run_id: str, task_id: str) -> dict:
    record = make_base_record(run_id, task_id, "build_manifests.py")
    record.update(
        {
            "model_runs": [],
            "policy": {
                "task1_external_llm_allowed": task_id == "task1",
                "structured_json_as_context_only": True,
                "manual_review_required_for_high_risk_sections": True,
            },
        }
    )
    return record


def build_package_manifest(run_id: str, task_id: str, output_dir: Path) -> dict:
    record = make_base_record(run_id, task_id, "build_manifests.py")
    files = []
    if output_dir.exists():
        for path in sorted(output_dir.rglob("*")):
            if path.is_file():
                files.append({"path": str(path.relative_to(output_dir)), "size": path.stat().st_size})
    record["files"] = files
    return record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--task-id", required=True, choices=["task1", "task2", "task3"])
    parser.add_argument("--mode", required=True, choices=["init", "package"])
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / args.task_id / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    run_id = run_dir.name

    if args.mode == "init":
        dump_json(json_dir / "tool_manifest.json", build_tool_manifest(run_id, args.task_id))
        dump_json(json_dir / "ai_usage_trace.json", build_ai_trace(run_id, args.task_id))
    else:
        pkg = build_package_manifest(run_id, args.task_id, json_dir.parent)
        dump_json(json_dir / "package_manifest.json", pkg)


if __name__ == "__main__":
    main()
