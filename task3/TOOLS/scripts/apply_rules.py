#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, load_json, make_base_record


def collect_evidence_refs(field: str, facts: dict) -> list[dict]:
    catalog = facts.get("evidence_catalog", {})
    refs = []
    for file_name, file_catalog in catalog.items():
        for ref in file_catalog.get(field, []):
            if ref not in refs:
                refs.append(ref)
    if refs:
        return refs[:20]
    for file_name, file_catalog in catalog.items():
        for ref in file_catalog.get("scope_refs", []):
            if ref not in refs:
                refs.append(ref)
            if len(refs) >= 5:
                return refs
    return refs[:20]


def hit_rule(rule: dict, facts: dict) -> bool:
    field_value = facts.get(rule.get("field"))
    match_type = rule.get("match_type")

    if match_type == "equals":
        return field_value == rule.get("value")

    if match_type == "contains_any":
        return any(value in (field_value or []) for value in rule.get("values", []))

    if match_type == "missing_any":
        current = set(field_value or [])
        return any(value not in current for value in rule.get("values", []))

    if match_type == "missing_all":
        current = set(field_value or [])
        return all(value not in current for value in rule.get("values", []))

    if match_type == "contains_substring_any":
        values = field_value or []
        return any(any(pattern in value for pattern in rule.get("values", [])) for value in values)

    if match_type == "greater_than":
        threshold = rule.get("value", 0)
        try:
            return float(field_value or 0) > float(threshold)
        except (TypeError, ValueError):
            return False

    if match_type == "less_than":
        threshold = rule.get("value", 0)
        try:
            return float(field_value or 0) < float(threshold)
        except (TypeError, ValueError):
            return False

    return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--rules", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task3" / "json"
    facts = load_json(json_dir / "task3_config_facts.json", {})
    rules = load_json(Path(args.rules), [])
    hits = []
    for rule in rules:
        if hit_rule(rule, facts):
            hits.append(
                {
                    "rule_id": rule.get("rule_id"),
                    "title": rule.get("title"),
                    "severity": rule.get("severity"),
                    "field": rule.get("field"),
                    "observed_value": facts.get(rule.get("field")),
                    "evidence_refs": collect_evidence_refs(rule.get("field"), facts),
                    "remediation": rule.get("remediation"),
                }
            )
    record = make_base_record(run_dir.name, "task3", "apply_rules.py")
    record["hits"] = hits
    dump_json(json_dir / "task3_rule_hits.json", record)


if __name__ == "__main__":
    main()
