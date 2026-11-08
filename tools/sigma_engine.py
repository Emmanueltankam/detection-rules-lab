"""Minimal offline test engine for Sigma rules.

Each rule is converted to SQL with pySigma's SQLite backend, then executed against
synthetic events loaded into an in-memory SQLite table. This lets us prove that a rule
fires on known-bad activity and stays quiet on known-good activity, without a SIEM.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

TABLE = "logs"


@dataclass
class CompiledRule:
    path: Path
    rule: SigmaRule
    query: str
    fields: set[str]


def _collect_fields(node: SigmaDetection | SigmaDetectionItem, fields: set[str]) -> None:
    if isinstance(node, SigmaDetectionItem):
        if node.field:
            fields.add(node.field)
        return
    for item in node.detection_items:
        _collect_fields(item, fields)


def rule_fields(rule: SigmaRule) -> set[str]:
    """Return every field name referenced by the rule's detection logic."""
    fields: set[str] = set()
    for detection in rule.detection.detections.values():
        _collect_fields(detection, fields)
    return fields


def compile_rule(path: Path) -> CompiledRule:
    collection = SigmaCollection.load_ruleset([str(path)])
    rule = collection.rules[0]
    queries = sqliteBackend().convert(collection)
    if len(queries) != 1:
        raise ValueError(f"{path}: expected exactly one query, got {len(queries)}")
    return CompiledRule(path=path, rule=rule, query=queries[0], fields=rule_fields(rule))


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def matches(compiled: CompiledRule, event: dict[str, Any]) -> bool:
    """Return True if the rule fires on this single event."""
    columns = sorted(compiled.fields | set(event))
    db = sqlite3.connect(":memory:")
    try:
        db.execute(f"CREATE TABLE {TABLE} ({', '.join(_quote(c) for c in columns)})")
        db.execute(
            f"INSERT INTO {TABLE} ({', '.join(_quote(c) for c in event)}) "
            f"VALUES ({', '.join('?' for _ in event)})",
            list(event.values()),
        )
        return db.execute(compiled.query).fetchone() is not None
    finally:
        db.close()
