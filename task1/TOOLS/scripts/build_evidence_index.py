#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, make_base_record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    task_dir = run_dir / "task1"
    evidence_dir = task_dir / "evidence"
    json_dir = task_dir / "json"

    items = []
    for base_dir, related_phase in [(task_dir / "raw", "recon"), (evidence_dir, "validation")]:
        if not base_dir.exists():
            continue
        for path in sorted(base_dir.rglob("*")):
            if path.is_file():
                items.append(
                    {
                        "evidence_id": path.stem,
                        "type": path.suffix.lstrip(".") or "file",
                        "path": str(path.relative_to(task_dir)),
                        "captured_at": "",
                        "description": "",
                        "related_phase": related_phase,
                        "sensitivity": "unknown",
                        "hash": "",
                        "usable_in_report": True,
                    }
                )

    record = make_base_record(run_dir.name, "task1", "build_evidence_index.py")
    record["evidence_items"] = items
    dump_json(json_dir / "task1_evidence_index.json", record)


if __name__ == "__main__":
    main()
