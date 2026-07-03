from __future__ import annotations

import json


def load(path: str) -> set:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return set()
    if isinstance(data, dict):
        data = data.get("suppressed", [])
    if not isinstance(data, list):
        return set()
    ids = set()
    for item in data:
        if isinstance(item, str):
            ids.add(item)
        elif isinstance(item, dict) and item.get("id"):
            ids.add(item["id"])
    return ids


def save(path: str, result) -> int:
    entries = [
        {
            "id": finding.key(),
            "title": finding.title,
            "severity": finding.severity.value,
            "location": finding.location,
        }
        for finding in result.findings
    ]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"suppressed": entries}, handle, indent=2)
    return len(entries)


def apply(result, ids: set) -> int:
    if not ids:
        return 0
    kept = [f for f in result.findings if f.key() not in ids]
    removed = len(result.findings) - len(kept)
    result.findings = kept
    return removed
