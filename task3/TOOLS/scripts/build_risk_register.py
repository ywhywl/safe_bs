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
    json_dir = run_dir / "task3" / "json"
    hits = load_json(json_dir / "task3_rule_hits.json", {}).get("hits", [])
    risks = []
    for idx, hit in enumerate(hits, start=1):
        risks.append(
            {
                "risk_id": f"risk-{idx}",
                "title": hit.get("title"),
                "severity": hit.get("severity"),
                "evidence": [
                    {
                        "field": hit.get("field"),
                        "observed_value": hit.get("observed_value"),
                        "evidence_refs": hit.get("evidence_refs", []),
                    }
                ],
                "impact": "Potential hardening gap identified by rule.",
                "remediation": hit.get("remediation"),
                "status": "open",
            }
        )
    record = make_base_record(run_dir.name, "task3", "build_risk_register.py")
    record["risks"] = risks
    dump_json(json_dir / "task3_risk_register.json", record)


if __name__ == "__main__":
    main()
