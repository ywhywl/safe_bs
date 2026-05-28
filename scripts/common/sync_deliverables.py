#!/usr/bin/env python3

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
    src_scripts = project_root / "scripts" / task_id
    dst_scripts = dst_tools / "scripts"
    src_skills = project_root / "skills"
    dst_skills = dst_tools / "skills"
    src_prompts = project_root / "common" / "prompts"
    dst_prompts = dst_tools / "prompts"

    if (src_task / "json").exists():
        copy_tree(src_task / "json", dst_tools / "json")
    if src_scripts.exists():
        copy_tree(src_scripts, dst_scripts)
    if src_skills.exists():
        copy_tree(src_skills, dst_skills)
    if src_prompts.exists():
        copy_tree(src_prompts, dst_prompts)
    if task_id == "task1":
        if (src_task / "evidence").exists():
            copy_tree(src_task / "evidence", dst_tools / "evidence")
        if (src_task / "raw").exists():
            copy_tree(src_task / "raw", dst_tools / "evidence" / "raw")
    if task_id == "task2" and (src_task / "alerts").exists():
        copy_tree(src_task / "alerts", dst_tools / "alerts")
    if task_id == "task3":
        if (src_task / "evidence").exists():
            copy_tree(src_task / "evidence", dst_tools / "evidence")
        if (src_task / "raw").exists():
            copy_tree(src_task / "raw", dst_tools / "evidence" / "raw")
        rules_src = project_root / "task3" / "TOOLS" / "rules"
        if rules_src.exists() and rules_src.resolve() != (dst_tools / "rules").resolve():
            copy_tree(rules_src, dst_tools / "rules")


if __name__ == "__main__":
    main()
