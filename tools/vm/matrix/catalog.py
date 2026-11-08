"""Snapshot the existing TSV contract without translating evidence categories."""

import hashlib
import json
from pathlib import Path

LINUX_ROOT = Path(__file__).resolve().parent.parent / "linux"
SUITES = {
    "linux-l2": "scenarios.tsv",
    "linux-l3": "scenarios-l3.tsv",
    "linux-l4": "scenarios-l4.tsv",
    "linux-l5": "scenarios-l5.tsv",
    "linux-proxy": "scenarios-proxy.tsv",
}
FIELDS = ("id", "required", "evidence", "group", "detail", "title")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def validate_snapshot(rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError("catalog must be a nonempty array")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != set(FIELDS):
            raise ValueError("invalid catalog fields")
        if type(row["required"]) is not bool:
            raise ValueError("catalog required must be boolean")
        if any(not isinstance(row[key], str) or not row[key].strip()
               for key in FIELDS if key != "required"):
            raise ValueError("catalog text fields must be nonempty strings")
        key = row["id"].casefold()
        if key in seen:
            raise ValueError("duplicate catalog scenario id")
        seen.add(key)
    return rows


def read_catalog(path):
    lines = [line for line in Path(path).read_text(encoding="utf-8-sig").splitlines()
             if line.strip()]
    if not lines or lines[0].split("\t") != list(FIELDS):
        raise ValueError("unexpected catalog header")
    rows = []
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) != len(FIELDS) or parts[1] not in ("yes", "no"):
            raise ValueError("malformed catalog row")
        row = dict(zip(FIELDS, parts))
        row["required"] = parts[1] == "yes"
        rows.append(row)
    return validate_snapshot(rows)
