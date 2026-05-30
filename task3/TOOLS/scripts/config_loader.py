#!/usr/bin/env python3

from __future__ import annotations

import glob
import re
from pathlib import Path

from lib import read_text


IGNORED_FILE_NAMES = {"readonly_meta.env", "nginx_T.stderr", "nginx_V.txt"}


def load_collection_meta(raw_dir: Path) -> dict[str, str]:
    meta_path = raw_dir / "readonly_meta.env"
    if not meta_path.exists():
        return {}
    meta = {}
    for line in read_text(meta_path).splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        meta[key] = value
    return meta


def has_expanded_nginx_t(raw_dir: Path) -> bool:
    nginx_t = raw_dir / "nginx_T.txt"
    return nginx_t.exists() and nginx_t.stat().st_size > 0


def _relative_name(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _is_probably_text(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return b"\x00" not in head


def _read_text_lossy(path: Path) -> str:
    try:
        return read_text(path)
    except UnicodeDecodeError:
        return path.read_text(encoding="utf-8", errors="ignore")


def find_config_root(raw_dir: Path) -> Path:
    if (raw_dir / "nginx.conf").exists():
        return raw_dir
    matches = sorted(raw_dir.rglob("nginx.conf"))
    if matches:
        return matches[0].parent
    return raw_dir


def parse_include_patterns(content: str) -> list[str]:
    patterns = []
    for match in re.finditer(r"^\s*include\s+(.+?);", content, re.MULTILINE):
        value = match.group(1).strip().strip('"').strip("'")
        if value:
            patterns.append(value)
    return patterns


def _candidate_include_patterns(include_pattern: str, current_file: Path, raw_dir: Path, target_root: str) -> list[str]:
    candidates = []
    if include_pattern.startswith("/"):
        stripped = include_pattern.lstrip("/")
        if stripped:
            candidates.append(str(raw_dir / stripped))
            parts = Path(stripped).parts
            for idx in range(1, len(parts)):
                candidates.append(str(raw_dir / Path(*parts[idx:])))
        normalized_target = target_root.rstrip("/")
        if normalized_target:
            if include_pattern == normalized_target or include_pattern.startswith(normalized_target + "/"):
                suffix = include_pattern[len(normalized_target):].lstrip("/")
                candidates.append(str(raw_dir / suffix) if suffix else str(raw_dir))
            target_name = Path(normalized_target).name
            marker = f"/{target_name}/" if target_name else ""
            if marker and marker in include_pattern:
                suffix = include_pattern.split(marker, 1)[1]
                candidates.append(str(raw_dir / suffix))
            elif target_name and include_pattern.endswith("/" + target_name):
                candidates.append(str(raw_dir))
    else:
        candidates.append(str(current_file.parent / include_pattern))

    seen = set()
    ordered = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        ordered.append(candidate)
    return ordered


def resolve_include_paths(include_pattern: str, current_file: Path, raw_dir: Path, target_root: str) -> list[Path]:
    matches = []
    seen = set()
    for candidate in _candidate_include_patterns(include_pattern, current_file, raw_dir, target_root):
        for value in sorted(glob.glob(candidate)):
            path = Path(value)
            if not path.is_file() or not _is_within_root(path, raw_dir) or path.name in IGNORED_FILE_NAMES:
                continue
            resolved = path.resolve()
            if resolved in seen or not _is_probably_text(path):
                continue
            seen.add(resolved)
            matches.append(path)
    return matches


def load_active_configs(raw_dir: Path, include_stderr: bool = True) -> dict[str, str]:
    configs = {}
    if has_expanded_nginx_t(raw_dir):
        nginx_t = raw_dir / "nginx_T.txt"
        configs["nginx_T.txt"] = _read_text_lossy(nginx_t)
        stderr_path = raw_dir / "nginx_T.stderr"
        if include_stderr and stderr_path.exists():
            configs["nginx_T.stderr"] = _read_text_lossy(stderr_path)
        return configs

    meta = load_collection_meta(raw_dir)
    target_root = meta.get("target", "")
    config_root = find_config_root(raw_dir)
    seed_files = []
    main_conf = config_root / "nginx.conf"
    if main_conf.exists():
        seed_files.append(main_conf)
    else:
        seed_files.extend(sorted(path for path in config_root.iterdir() if path.is_file() and path.suffix == ".conf"))

    visited = set()
    stack = list(reversed(seed_files))
    while stack:
        path = stack.pop()
        if not path.is_file() or path.name in IGNORED_FILE_NAMES or not _is_within_root(path, raw_dir) or not _is_probably_text(path):
            continue
        resolved = path.resolve()
        if resolved in visited:
            continue
        visited.add(resolved)
        content = _read_text_lossy(path)
        configs[_relative_name(path, raw_dir)] = content
        for include_pattern in parse_include_patterns(content):
            stack.extend(reversed(resolve_include_paths(include_pattern, path, raw_dir, target_root)))

    if not configs:
        for path in sorted(raw_dir.rglob("*.conf")):
            if not path.is_file() or not _is_probably_text(path):
                continue
            configs[_relative_name(path, raw_dir)] = _read_text_lossy(path)

    stderr_path = raw_dir / "nginx_T.stderr"
    if include_stderr and stderr_path.exists():
        configs["nginx_T.stderr"] = _read_text_lossy(stderr_path)

    return configs
