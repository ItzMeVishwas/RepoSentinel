"""The interface every check implements.

A check is a small class with a stable ``id``, a list of the ``rules`` it can
report, and a ``run`` method that inspects a ``ScanContext`` and returns a
``CheckOutput``. The engine runs each check in isolation: if ``run`` raises,
that check is reported as *failed* and the others still run.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import ClassVar

from reposentinel.context import ScanContext
from reposentinel.models import Confidence, Finding, Rule, Severity


class CheckSkipped(Exception):
    """Raised by ``Check.run`` when the check cannot run at all.

    The message should tell the user why and what to do about it, for example
    ``"gitleaks was not found on PATH"``. A skipped check makes the scan
    *incomplete*: RepoSentinel never reports success for checks that did not run.
    """


@dataclass(frozen=True, slots=True)
class CheckOutput:
    findings: list[Finding] = field(default_factory=list)
    examined: int | None = 0  # items (usually files) inspected; None if not known
    message: str = ""  # optional note shown next to the check's status
    # The relative paths of the files the check actually examined. Comparisons
    # only call a finding "not detected on re-check" for files listed here.
    # None means "not reported", which makes every absence a "not re-checked".
    examined_paths: tuple[str, ...] | None = None


class Check(abc.ABC):
    id: ClassVar[str]
    name: ClassVar[str]
    description: ClassVar[str]
    rules: ClassVar[tuple[Rule, ...]]

    @abc.abstractmethod
    def run(self, context: ScanContext) -> CheckOutput:
        """Inspect the repository and return findings. Must not modify anything."""

    def finding(
        self,
        rule: Rule,
        *,
        summary: str,
        evidence: str,
        path: str | None = None,
        line: int | None = None,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        identity: tuple[str, ...] = (),
    ) -> Finding:
        """Create a finding for ``rule``, using the rule's defaults unless overridden.

        ``identity`` holds the rule-specific fingerprint inputs (in addition to
        the rule ID and path). Only RepoSentinel vocabulary or structural
        identifiers may be used; never secret values or free repository text.
        """
        if rule not in self.rules:
            raise ValueError(f"{rule.id} is not declared by check {self.id}")
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=severity or rule.severity,
            confidence=confidence or rule.confidence,
            summary=summary,
            evidence=evidence,
            remediation=rule.remediation,
            check_id=self.id,
            path=path,
            line=line,
            identity=identity,
            rule_version=rule.version,
        )
