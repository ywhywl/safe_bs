#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, make_base_record
from input_layout import iter_log_files, resolve_input_layout
from log_formats import guess_log_format


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--input-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    input_dir = Path(args.input_dir)
    json_dir = run_dir / "task2" / "json"
    layout = resolve_input_layout(input_dir)

    def describe_files(paths: list[Path], role: str) -> list[dict]:
        described = []
        for path in paths:
            described.append(
                {
                    "path": str(path),
                    "role": role,
                    "format_guess": guess_log_format(path),
                    "line_count": sum(1 for _ in path.open(encoding="utf-8", errors="replace")),
                }
            )
        return described

    current_sources = describe_files(iter_log_files(layout.current_dir), "current")
    baseline_sources = describe_files(iter_log_files(layout.baseline_dir), "baseline") if layout.baseline_dir else []
    files = current_sources + baseline_sources

    record = make_base_record(run_dir.name, "task2", "ingest_logs.py")
    record.update(
        {
            "dataset_mode": layout.mode,
            "input_root": str(layout.root_dir),
            "current_input_dir": str(layout.current_dir),
            "baseline_input_dir": str(layout.baseline_dir) if layout.baseline_dir else "",
            "policy_path": str(layout.policy_path) if layout.policy_path else "",
            "log_sources": files,
            "current_log_sources": current_sources,
            "baseline_log_sources": baseline_sources,
            "parse_errors": [],
            "normalization_rules": [
                "runtime pipe parser",
                "proftpd program log parser",
                "key=value parser",
                "space-split fallback",
            ],
        }
    )
    dump_json(json_dir / "task2_log_ingest_manifest.json", record)


if __name__ == "__main__":
    main()
