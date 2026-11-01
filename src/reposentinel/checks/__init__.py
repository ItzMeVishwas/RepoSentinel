"""Native checks and the rule catalogue."""

from __future__ import annotations

from reposentinel.checks.base import Check, CheckOutput, CheckSkipped
from reposentinel.checks.hygiene import HygieneCheck
from reposentinel.checks.secrets import SecretsCheck
from reposentinel.checks.workflows import WorkflowCheck
from reposentinel.models import Rule

__all__ = [
    "Check",
    "CheckOutput",
    "CheckSkipped",
    "HygieneCheck",
    "SecretsCheck",
    "WorkflowCheck",
    "all_rules",
    "default_checks",
]


def default_checks() -> list[Check]:
    """The native checks that run on every scan, in reporting order."""
    return [HygieneCheck(), SecretsCheck(), WorkflowCheck()]


def all_rules() -> list[Rule]:
    """Every native rule, sorted by rule ID."""
    rules = [rule for check in default_checks() for rule in check.rules]
    return sorted(rules, key=lambda rule: rule.id)
