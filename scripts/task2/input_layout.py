#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


CURRENT_DIR_NAMES = ("current", "detect", "analysis")
BASELINE_DIR_NAMES = ("baseline", "history", "historical")


@dataclass(frozen=True)
class InputLayout:
    root_dir: Path
    current_dir: Path
    baseline_dir: Path | None
    policy_path: Path | None
    mode: str


def _first_existing_dir(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = root / name
        if candidate.is_dir():
            return candidate
    return None


def resolve_input_layout(input_dir: Path) -> InputLayout:
    root_dir = input_dir
    current_dir = _first_existing_dir(root_dir, CURRENT_DIR_NAMES) or root_dir
    baseline_dir = _first_existing_dir(root_dir, BASELINE_DIR_NAMES)

    policy_candidates = [root_dir / "noise_policy.json"]
    if current_dir != root_dir:
        policy_candidates.append(current_dir / "noise_policy.json")
    policy_path = next((path for path in policy_candidates if path.exists()), None)

    mode = "historical_split" if baseline_dir else "single_dataset"
    return InputLayout(
        root_dir=root_dir,
        current_dir=current_dir,
        baseline_dir=baseline_dir,
        policy_path=policy_path,
        mode=mode,
    )


def iter_log_files(directory: Path) -> list[Path]:
    files = []
    for path in sorted(directory.glob("*")):
        if path.is_file() and path.suffix.lower() != ".json":
            files.append(path)
    return files
