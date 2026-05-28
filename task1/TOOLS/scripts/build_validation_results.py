#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, make_base_record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--status", default="not_validated")
    parser.add_argument("--summary", default="Validation has not been completed yet.")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task1" / "json"
    record = make_base_record(run_dir.name, "task1", "build_validation_results.py")
    record.update(
        {
            "overall_result": args.status,
            "validated_hypothesis": "",
            "observed_effects": [],
            "impact_summary": args.summary,
            "privilege_or_access_gained": "none recorded",
            "artifacts_created": [],
            "limitations": ["Manual validation data not yet attached."],
            "false_positive_risks": ["Service identity may still require manual confirmation."],
            "manual_review_required": True,
        }
    )
    dump_json(json_dir / "task1_validation_results.json", record)


if __name__ == "__main__":
    main()
