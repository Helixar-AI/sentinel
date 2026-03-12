"""11 tests for RuleRegistry."""

from sentinel.core import Severity
from sentinel.rules import RuleRegistry


class TestRuleRegistry:
    def setup_method(self):
        self.registry = RuleRegistry()

    def test_registry_loads_rules(self):
        assert len(self.registry) > 0

    def test_registry_total_rule_count(self):
        assert len(self.registry) == 26

    def test_by_id_found(self):
        rule = self.registry.by_id("CFG-001")
        assert rule is not None
        assert rule.id == "CFG-001"

    def test_by_id_not_found(self):
        rule = self.registry.by_id("DOES-NOT-EXIST")
        assert rule is None

    def test_by_check_key_found(self):
        rule = self.registry.by_check_key("no_auth")
        assert rule is not None
        assert rule.check_key == "no_auth"

    def test_by_check_key_not_found(self):
        rule = self.registry.by_check_key("nonexistent_key")
        assert rule is None

    def test_by_module_config(self):
        config_rules = self.registry.by_module("config")
        assert len(config_rules) == 10
        assert all(r.module == "config" for r in config_rules)

    def test_by_module_probe(self):
        probe_rules = self.registry.by_module("probe")
        assert len(probe_rules) == 8
        assert all(r.module == "probe" for r in probe_rules)

    def test_by_module_container(self):
        container_rules = self.registry.by_module("container")
        assert len(container_rules) == 8
        assert all(r.module == "container" for r in container_rules)

    def test_rule_has_required_fields(self):
        for rule in self.registry.all_rules:
            assert rule.id, f"Rule missing id: {rule}"
            assert rule.module, f"Rule missing module: {rule}"
            assert isinstance(rule.severity, Severity), f"Rule {rule.id} has bad severity"
            assert rule.check_key, f"Rule {rule.id} missing check_key"
            assert rule.title, f"Rule {rule.id} missing title"

    def test_all_check_keys_unique(self):
        check_keys = [r.check_key for r in self.registry.all_rules]
        assert len(check_keys) == len(set(check_keys)), "Duplicate check_keys found"
