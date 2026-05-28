#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import dump_json, make_base_record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--ports", default="22")
    parser.add_argument("--scope", default="authorized testing only")
    parser.add_argument("--window", default="")
    parser.add_argument("--network-path", default="external")
    parser.add_argument("--recon-input-dir", default="")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    json_dir = run_dir / "task1" / "json"
    json_dir.mkdir(parents=True, exist_ok=True)

    record = make_base_record(run_dir.name, "task1", "init_target_profile.py")
    record.update(
        {
            "target_id": args.target,
            "target_host": args.target,
            "target_ip": "",
            "target_ports": [p.strip() for p in args.ports.split(",") if p.strip()],
            "network_path": args.network_path,
            "recon_collection_mode": "imported_scan" if args.recon_input_dir else "active_recon",
            "recon_input_dir": args.recon_input_dir,
            "authorization_scope": args.scope,
            "out_of_scope_actions": ["destructive changes", "persistence", "unauthorized lateral movement"],
            "test_window_start": args.window,
            "test_window_end": args.window,
            "success_definition": "Authorized validation result with evidence chain",
            "screenshot_policy": "Capture only relevant result screens and redact sensitive data when exporting",
        }
    )
    dump_json(json_dir / "task1_target_profile.json", record)


if __name__ == "__main__":
    main()
