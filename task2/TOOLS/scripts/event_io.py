#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from lib import ensure_dir


def write_ndjson_line(path: Path, record: dict, handle=None) -> None:
    payload = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    if handle is not None:
        handle.write(payload)
        return
    ensure_dir(path.parent)
    with path.open("a", encoding="utf-8") as out:
        out.write(payload)


def iter_ndjson(path: Path) -> Iterator[dict]:
    if not path.exists():
        return
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            yield json.loads(stripped)
