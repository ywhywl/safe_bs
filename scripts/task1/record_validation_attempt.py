#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, make_base_record


def append_timeline_event(run_dir: Path, event: dict) -> None:
    json_dir = run_dir / "task1" / "json"
    timeline_path = json_dir / "task1_execution_timeline.json"
    timeline = load_json(timeline_path, None)
    if timeline is None:
        timeline = make_base_record(run_dir.name, "task1", "record_timeline.py")
        timeline["events"] = []
    timeline.setdefault("events", []).append(event)
    dump_json(timeline_path, timeline)


def merge_validation_result(run_dir: Path, result_patch: dict) -> None:
    json_dir = run_dir / "task1" / "json"
    result_path = json_dir / "task1_validation_results.json"
    result = load_json(result_path, None)
    if result is None:
        result = make_base_record(run_dir.name, "task1", "build_validation_results.py")
        result.update(
            {
                "overall_result": "not_validated",
                "validated_hypothesis": "",
                "observed_effects": [],
                "impact_summary": "Validation has not been completed yet.",
                "privilege_or_access_gained": "none recorded",
                "artifacts_created": [],
                "limitations": [],
                "false_positive_risks": [],
                "manual_review_required": True,
            }
        )
    for key, value in result_patch.items():
        if key in {"observed_effects", "artifacts_created", "limitations", "false_positive_risks"}:
            existing = result.get(key, [])
            if isinstance(value, list):
                existing.extend(value)
            elif value:
                existing.append(value)
            result[key] = existing
        elif value != "":
            result[key] = value
    dump_json(result_path, result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--phase", default="validation")
    parser.add_argument("--action-label", required=True)
    parser.add_argument("--target", default="")
    parser.add_argument("--status", default="completed")
    parser.add_argument("--summary", default="")
    parser.add_argument("--comment", default="")
    parser.add_argument("--hypothesis", default="")
    parser.add_argument("--overall-result", default="")
    parser.add_argument("--impact-summary", default="")
    parser.add_argument("--privilege", default="")
    parser.add_argument("--evidence-ref", action="append", default=[])
    parser.add_argument("--observed-effect", action="append", default=[])
    parser.add_argument("--artifact", action="append", default=[])
    parser.add_argument("--limitation", action="append", default=[])
    parser.add_argument("--false-positive-risk", action="append", default=[])
    parser.add_argument("--manual-review-required", choices=["true", "false"], default="")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    base = make_base_record(run_dir.name, "task1", "record_validation_attempt.py")
    event = {
        "timestamp": base["created_at"],
        "phase": args.phase,
        "action_label": args.action_label,
        "target": args.target,
        "result_summary": args.summary,
        "status": args.status,
        "evidence_refs": args.evidence_ref,
        "analyst_comment": args.comment,
    }
    append_timeline_event(run_dir, event)

    result_patch = {
        "validated_hypothesis": args.hypothesis,
        "overall_result": args.overall_result,
        "impact_summary": args.impact_summary,
        "privilege_or_access_gained": args.privilege,
        "observed_effects": args.observed_effect,
        "artifacts_created": args.artifact,
        "limitations": args.limitation,
        "false_positive_risks": args.false_positive_risk,
    }
    if args.manual_review_required:
        result_patch["manual_review_required"] = args.manual_review_required == "true"
    merge_validation_result(run_dir, result_patch)


if __name__ == "__main__":
    main()
