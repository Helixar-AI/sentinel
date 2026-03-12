"""Rule registry — loads and indexes rules.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

import yaml

from sentinel.core import Severity

_RULES_PATH = Path(__file__).parent / "rules.yaml"


class Rule:
    def __init__(self, data: dict) -> None:
        self.id: str = data["id"]
        self.module: str = data["module"]
        self.severity: Severity = Severity.from_string(data["severity"])
        self.check_key: str = data["check_key"]
        self.title: str = data["title"]
        self.rationale: str = data.get("rationale", "").strip()
        self.remediation: str = data.get("remediation", "").strip()
        self.reference: str = data.get("reference", "")

    def __repr__(self) -> str:
        return f"<Rule {self.id} [{self.severity.value}] {self.title!r}>"


class RuleRegistry:
    def __init__(self, path: Optional[Path] = None) -> None:
        self._rules: List[Rule] = []
        self._by_id: Dict[str, Rule] = {}
        self._by_check_key: Dict[str, Rule] = {}
        self._load(path or _RULES_PATH)

    def _load(self, path: Path) -> None:
        with open(path, "r") as fh:
            data = yaml.safe_load(fh)
        for item in data.get("rules", []):
            rule = Rule(item)
            self._rules.append(rule)
            self._by_id[rule.id] = rule
            self._by_check_key[rule.check_key] = rule

    @property
    def all_rules(self) -> List[Rule]:
        return list(self._rules)

    def by_id(self, rule_id: str) -> Optional[Rule]:
        return self._by_id.get(rule_id)

    def by_check_key(self, check_key: str) -> Optional[Rule]:
        return self._by_check_key.get(check_key)

    def by_module(self, module: str) -> List[Rule]:
        return [r for r in self._rules if r.module == module]

    def __len__(self) -> int:
        return len(self._rules)
