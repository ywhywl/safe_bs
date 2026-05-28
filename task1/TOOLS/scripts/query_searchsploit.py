#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

from lib import dump_json, load_json, make_base_record, read_text


def parse_env_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for line in read_text(path).splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def summarize_results(results: list[dict]) -> list[dict]:
    summarized = []
    for item in results[:5]:
        summarized.append(
            {
                "title": item.get("Title", ""),
                "edb_id": item.get("EDB-ID", ""),
                "codes": item.get("Codes", ""),
                "path": item.get("Path", ""),
                "verified": item.get("Verified", ""),
                "type": item.get("Type", ""),
            }
        )
    return summarized


def run_searchsploit(binary: str, query: str) -> dict:
    try:
        proc = subprocess.run(
            [binary, "--json", query],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except Exception as exc:
        return {"query": query, "available": False, "results": [], "error": str(exc)}

    if not proc.stdout.strip():
        return {"query": query, "available": True, "results": [], "stderr": proc.stderr.strip()}

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"query": query, "available": True, "results": [], "parse_error": True, "stderr": proc.stderr.strip()}

    return {
        "query": query,
        "available": True,
        "results": data.get("RESULTS_EXPLOIT", []),
        "stderr": proc.stderr.strip(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    raw_dir = run_dir / "task1" / "raw"
    json_dir = run_dir / "task1" / "json"
    facts = load_json(json_dir / "task1_recon_facts.json", {})
    meta = parse_env_file(raw_dir / "recon_meta.env")
    configured_binary = meta.get("searchsploit_bin", "")
    binary = configured_binary if configured_binary and Path(configured_binary).exists() else shutil.which("searchsploit") or ""
    queries = facts.get("recommended_search_queries", [])

    matches = []
    for query in queries:
        if binary:
            matches.append(run_searchsploit(binary, query))
        else:
            matches.append({"query": query, "available": False, "results": [], "error": "searchsploit not available"})

    record = make_base_record(run_dir.name, "task1", "query_searchsploit.py")
    record.update(
        {
            "searchsploit_available": bool(binary),
            "searchsploit_bin": binary,
            "search_queries": queries,
            "matches": matches,
            "summary": {item["query"]: summarize_results(item.get("results", [])) for item in matches},
        }
    )
    dump_json(json_dir / "task1_searchsploit_matches.json", record)


if __name__ == "__main__":
    main()
