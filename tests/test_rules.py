"""Quality gate for every Sigma rule in rules/.

- each rule fires on all of its known-bad samples (true positives)
- each rule stays quiet on all of its known-good samples (true negatives)
- each rule carries the metadata an analyst needs (ATT&CK mapping, level, false positives...)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from sigma_engine import compile_rule, matches  # noqa: E402

RULE_FILES = sorted((ROOT / "rules").rglob("*.yml"))
EVENTS_DIR = ROOT / "tests" / "events"
NAMES = yaml.safe_load((ROOT / "tools" / "attack_techniques.yml").read_text(encoding="utf-8"))
ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
FILENAME_PREFIX = {
    ("windows", "process_creation", None): "proc_creation_win_",
    ("linux", "process_creation", None): "proc_creation_lnx_",
    ("windows", None, "security"): "win_security_",
    (None, "webserver", None): "web_",
}
IDS = [p.stem for p in RULE_FILES]


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_events(rule_path: Path) -> dict:
    events_file = EVENTS_DIR / f"{rule_path.stem}.yml"
    assert events_file.exists(), f"missing test events: tests/events/{events_file.name}"
    return load_yaml(events_file)


def strip(event: dict) -> dict:
    return {k: v for k, v in event.items() if k != "description"}


def test_rules_exist():
    assert RULE_FILES, "no rules found"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=IDS)
def test_true_positives(rule_path):
    compiled = compile_rule(rule_path)
    events = load_events(rule_path).get("match") or []
    assert events, "at least one 'match' event is required"
    missed = [e.get("description", e) for e in events if not matches(compiled, strip(e))]
    assert not missed, f"rule did not fire on: {missed}\nSQL: {compiled.query}"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=IDS)
def test_true_negatives(rule_path):
    compiled = compile_rule(rule_path)
    events = load_events(rule_path).get("no_match") or []
    assert events, "at least one 'no_match' event is required"
    noisy = [e.get("description", e) for e in events if matches(compiled, strip(e))]
    assert not noisy, f"rule fired on benign events: {noisy}\nSQL: {compiled.query}"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=IDS)
def test_metadata(rule_path):
    rule = load_yaml(rule_path)
    for key in ("title", "id", "status", "description", "references", "author", "date",
                "tags", "logsource", "falsepositives", "level"):
        assert rule.get(key), f"missing '{key}'"
    assert rule["level"] in ALLOWED_LEVELS

    tags = rule["tags"]
    techniques = [t for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
    tactics = [t for t in tags if t.split(".", 1)[1] in NAMES["tactics"]]
    assert techniques, "at least one ATT&CK technique tag is required"
    assert tactics, "at least one ATT&CK tactic tag is required"
    for t in techniques:
        tid = t.split(".", 1)[1].upper()
        assert tid in NAMES["techniques"], f"add {tid} to tools/attack_techniques.yml"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=IDS)
def test_filename_convention(rule_path):
    ls = load_yaml(rule_path)["logsource"]
    key = (ls.get("product"), ls.get("category"), ls.get("service"))
    assert key in FILENAME_PREFIX, f"no naming convention defined for logsource {key}"
    assert rule_path.name.startswith(FILENAME_PREFIX[key])


def test_unique_ids_and_titles():
    rules = [load_yaml(p) for p in RULE_FILES]
    ids = [r["id"] for r in rules]
    titles = [r["title"] for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule id"
    assert len(titles) == len(set(titles)), "duplicate rule title"


def test_no_orphan_event_files():
    stems = {p.stem for p in RULE_FILES}
    orphans = [p.name for p in EVENTS_DIR.glob("*.yml") if p.stem not in stems]
    assert not orphans, f"event files without a rule: {orphans}"
