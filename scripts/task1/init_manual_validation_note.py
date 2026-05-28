#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from lib import write_text


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", required=True)
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    note = """# Manual Validation Note

Use this file to record authorized manual validation results for task1.

Suggested fields:

- validated_hypothesis:
- validation_time:
- operator:
- commands_or_steps_summary:
- observed_effects:
- artifacts_created:
- screenshots:
- cleanup_status:
- impact_assessment:
- limitations:
"""
    write_text(run_dir / "task1" / "evidence" / "manual_validation_note.md", note)


if __name__ == "__main__":
    main()
