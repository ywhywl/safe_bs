#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, make_base_record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task1" / "json"
    hypotheses = load_json(json_dir / "task1_vuln_hypotheses.json", {})
    facts = load_json(json_dir / "task1_recon_facts.json", {})
    vulns = hypotheses.get("candidate_vulnerabilities", [])
    sftp_ports = [item.get("port") for item in facts.get("sftp_candidate_ports", []) if item.get("port")]

    record = make_base_record(run_dir.name, "task1", "build_validation_plan.py")
    record.update(
        {
            "goal": "Validate the highest priority hypothesis within the authorized boundary.",
            "validation_sequence": [
                {
                    "step_id": "s1",
                    "objective": "Confirm target service identity and reachable protocol surface.",
                    "expected_signal": "Consistent banner, identified SSH/SFTP port, and service fingerprint alignment",
                    "stop_condition": "Identity is inconsistent with the hypothesis",
                    "evidence_to_capture": ["banner", "imported nmap output", "service response", f"sftp candidate ports: {sftp_ports}"],
                    "safety_boundary": "No destructive write or persistence",
                },
                {
                    "step_id": "s2",
                    "objective": "Perform minimal authorized validation aligned with the selected hypothesis.",
                    "expected_signal": "Observable validation evidence without exceeding scope",
                    "stop_condition": "Unexpected service behavior or scope violation risk",
                    "evidence_to_capture": ["command transcript", "response summary", "screenshots if applicable"],
                    "safety_boundary": "Stop on ambiguity and require manual review",
                },
            ],
            "decision_points": [
                {
                    "selected_hypothesis": vulns[0]["name"] if vulns else "",
                    "sftp_candidate_ports": sftp_ports,
                    "manual_review_required": True,
                }
            ],
            "rollback_or_abort_conditions": [
                "Service identity mismatch",
                "Evidence suggests out-of-scope impact",
                "Target instability or risk of destructive change",
            ],
        }
    )
    dump_json(json_dir / "task1_validation_plan.json", record)


if __name__ == "__main__":
    main()
