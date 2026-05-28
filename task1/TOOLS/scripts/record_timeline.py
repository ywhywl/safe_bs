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
    json_dir = run_dir / "task1" / "json"
    record = make_base_record(run_dir.name, "task1", "record_timeline.py")
    record["events"] = [
        {
            "timestamp": record["created_at"],
            "phase": "recon",
            "action_label": "initial reconnaissance completed",
            "target": "",
            "result_summary": "Raw service artifacts collected where available.",
            "status": "completed",
            "evidence_refs": [],
            "analyst_comment": "First version records baseline execution milestones only.",
        }
    ]
    dump_json(json_dir / "task1_execution_timeline.json", record)


if __name__ == "__main__":
    main()
