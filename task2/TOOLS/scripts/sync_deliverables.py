#!/usr/bin/env python3

"""Sync deliverables from run output back to the task TOOLS directory.

In the self-contained layout, scripts/skills/prompts already live inside
taskN/TOOLS/, so we only need to copy the run-generated output (json,
alerts, evidence, reports, etc.) back to TOOLS/ for easy access.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from lib import ensure_dir


def copy_tree(src: Path, dst: Path) -> None:
    ensure_dir(dst)
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src)
        target = dst / rel
        if path.is_dir():
            ensure_dir(target)
        else:
            if path.resolve() == target.resolve():
                continue
            ensure_dir(target.parent)
            shutil.copy2(path, target)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--task-id", required=True, choices=["task1", "task2", "task3"])
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    project_root = Path(args.project_root)
    task_id = args.task_id

    src_task = run_dir / task_id
    dst_tools = project_root / task_id / "TOOLS"

    # Copy run-generated JSON output
    if (src_task / "json").exists():
        copy_tree(src_task / "json", dst_tools / "json")

    # Copy task-specific run output
    if task_id == "task1":
        if (src_task / "evidence").exists():
            copy_tree(src_task / "evidence", dst_tools / "evidence")
        if (src_task / "raw").exists():
            copy_tree(src_task / "raw", dst_tools / "evidence" / "raw")
    elif task_id == "task2":
        if (src_task / "alerts").exists():
            copy_tree(src_task / "alerts", dst_tools / "alerts")
    elif task_id == "task3":
        if (src_task / "evidence").exists():
            copy_tree(src_task / "evidence", dst_tools / "evidence")
        if (src_task / "raw").exists():
            copy_tree(src_task / "raw", dst_tools / "evidence" / "raw")
        rules_src = dst_tools / "rules"
        # rules already live in TOOLS/rules/, no need to copy from elsewhere

    # Copy deliverable .md files from run dir to task root
    for md_file in ["MANUAL.md", "REPORT.md", "AI_REPORT.md"]:
        src_md = src_task / md_file
        dst_md = project_root / task_id / md_file
        if src_md.exists():
            ensure_dir(dst_md.parent)
            shutil.copy2(src_md, dst_md)


if __name__ == "__main__":
    main()