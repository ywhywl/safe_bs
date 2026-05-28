#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

from lib import dump_json, ensure_dir, make_base_record, read_text


NMAP_HEADER_RE = re.compile(r"^Nmap scan report for (?P<label>.+)$")
OPEN_PORT_RE = re.compile(r"^(?P<port>\d+)\/tcp\s+open\b")
IP_IN_PARENS_RE = re.compile(r"\((?P<ip>[0-9a-fA-F:.]+)\)")
RAW_IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")


def discover_nmap_path(input_dir: Path) -> Path:
    direct = input_dir / "nmap.txt"
    if direct.exists():
        return direct
    candidates = sorted(input_dir.glob("*nmap*.txt"))
    if candidates:
        return candidates[0]
    raise FileNotFoundError(f"no nmap text file found in {input_dir}")


def extract_target_id(label: str) -> str:
    label = label.strip()
    paren_match = IP_IN_PARENS_RE.search(label)
    if paren_match:
        return paren_match.group("ip")
    if RAW_IP_RE.match(label):
        return label
    return label.split()[0]


def parse_nmap_sections(path: Path) -> list[dict]:
    lines = read_text(path).splitlines()
    sections: list[dict] = []
    current: dict | None = None
    for line in lines:
        header_match = NMAP_HEADER_RE.match(line)
        if header_match:
            if current is not None:
                sections.append(current)
            label = header_match.group("label")
            current = {
                "label": label,
                "target": extract_target_id(label),
                "lines": [line],
                "ports": [],
            }
            continue
        if current is None:
            continue
        current["lines"].append(line)
        port_match = OPEN_PORT_RE.match(line.strip())
        if port_match:
            current["ports"].append(port_match.group("port"))
    if current is not None:
        sections.append(current)
    return sections


def sanitize_target(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)


def build_recon_dirs(input_dir: Path, output_dir: Path, targets_filter: set[str] | None) -> list[dict]:
    nmap_path = discover_nmap_path(input_dir)
    sections = parse_nmap_sections(nmap_path)
    results = []
    for section in sections:
        target = section["target"]
        if targets_filter and target not in targets_filter:
            continue
        recon_dir = output_dir / sanitize_target(target)
        ensure_dir(recon_dir)
        (recon_dir / "nmap.txt").write_text("\n".join(section["lines"]).rstrip() + "\n", encoding="utf-8")
        ports = sorted(set(section["ports"]), key=lambda item: int(item))
        results.append(
            {
                "target": target,
                "label": section["label"],
                "ports": ports,
                "recon_dir": str(recon_dir),
                "source_nmap_file": str(nmap_path),
            }
        )
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--run-prefix", required=True)
    parser.add_argument("--targets", default="")
    parser.add_argument("--scope", default="authorized testing only")
    parser.add_argument("--window", default="")
    parser.add_argument("--network-path", default="external")
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()

    project_root = Path(args.project_root)
    input_dir = Path(args.input_dir)
    work_dir = Path(args.work_dir)
    targets_filter = {item.strip() for item in args.targets.split(",") if item.strip()} or None
    ensure_dir(work_dir)

    items = build_recon_dirs(input_dir, work_dir, targets_filter)
    if not items:
        raise SystemExit("no matching targets found in imported nmap result")

    runs = []
    run_script = project_root / "bin" / "run_task1.sh"
    for item in items:
        target = item["target"]
        ports = ",".join(item["ports"]) if item["ports"] else "22"
        run_id = f"{args.run_prefix}_{sanitize_target(target)}"
        env = os.environ.copy()
        env["RECON_INPUT_DIR"] = item["recon_dir"]
        env["PORTS"] = ports
        env["RUN_ID"] = run_id
        env["SCOPE"] = args.scope
        env["WINDOW"] = args.window
        env["NETWORK_PATH"] = args.network_path
        subprocess.run([str(run_script), target], check=True, cwd=project_root, env=env)
        runs.append(
            {
                "target": target,
                "label": item["label"],
                "ports": item["ports"],
                "recon_dir": item["recon_dir"],
                "run_id": run_id,
                "run_dir": str(project_root / "runs" / run_id),
            }
        )

    batch_dir = project_root / "runs" / f"{args.run_prefix}__batch"
    ensure_dir(batch_dir)
    record = make_base_record(args.run_prefix, "task1", "run_batch_import.py")
    record.update(
        {
            "input_dir": str(input_dir),
            "source_nmap_file": items[0]["source_nmap_file"],
            "targets_requested": sorted(targets_filter) if targets_filter else [],
            "run_count": len(runs),
            "runs": runs,
        }
    )
    dump_json(batch_dir / "task1_batch_runs.json", record)


if __name__ == "__main__":
    main()
