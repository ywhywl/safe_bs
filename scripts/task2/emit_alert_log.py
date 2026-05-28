#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import load_json, write_text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    alerts = load_json(run_dir / "task2" / "json" / "task2_alerts.json", {}).get("alerts", [])
    lines = []
    for alert in alerts:
        lines.append(
            f"severity={alert.get('severity')} user={alert.get('user')} session={alert.get('session_id')} type={alert.get('trigger_type')} reasons={','.join(alert.get('trigger_reasons', []))}"
        )
    write_text(run_dir / "task2" / "alerts" / "alert_output.log", "\n".join(lines) + ("\n" if lines else ""))


if __name__ == "__main__":
    main()
