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
    profile = load_json(json_dir / "task1_target_profile.json", {})
    facts = load_json(json_dir / "task1_recon_facts.json", {})
    hypotheses = load_json(json_dir / "task1_vuln_hypotheses.json", {})
    searchsploit = load_json(json_dir / "task1_searchsploit_matches.json", {})
    plan = load_json(json_dir / "task1_validation_plan.json", {})
    timeline = load_json(json_dir / "task1_execution_timeline.json", {})
    results = load_json(json_dir / "task1_validation_results.json", {})
    evidence = load_json(json_dir / "task1_evidence_index.json", {})

    record = make_base_record(run_dir.name, "task1", "build_report_context.py")
    record.update(
        {
            "target_summary": {
                "target": profile.get("target_host", ""),
                "ports": profile.get("target_ports", []),
                "scope": profile.get("authorization_scope", ""),
                "recon_collection_mode": profile.get("recon_collection_mode", "active_recon"),
            },
            "service_identity_summary": {
                "candidates": facts.get("service_candidates", []),
                "versions": facts.get("version_hints", []),
                "sftp_candidate_ports": facts.get("sftp_candidate_ports", []),
            },
            "tool_intel_summary": searchsploit.get("summary", {}),
            "validated_issue_summary": hypotheses.get("candidate_vulnerabilities", []),
            "search_query_summary": searchsploit.get("search_queries", []),
            "impact_summary": results.get("impact_summary", ""),
            "evidence_summary": evidence.get("evidence_items", []),
            "remediation_summary": "Upgrade the affected service, remove vulnerable modules where possible, and restrict exposed services.",
            "validation_plan_summary": plan.get("validation_sequence", []),
            "timeline_summary": timeline.get("events", []),
            "ai_usage_summary": "Use external LLM only with sanitized report context.",
            "do_not_disclose_items": ["raw secrets", "full sensitive artifacts"],
        }
    )
    dump_json(json_dir / "task1_report_context.json", record)


if __name__ == "__main__":
    main()
