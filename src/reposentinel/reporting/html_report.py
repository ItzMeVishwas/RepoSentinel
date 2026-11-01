"""Self-contained HTML report.

Security properties:

* Jinja2 autoescaping is on for the whole template, so every value from the
  scanned repository is HTML-escaped (``<`` becomes ``&lt;`` and so on).
* The page contains no JavaScript and loads nothing from the network; a
  Content-Security-Policy meta tag enforces that even if escaping failed.
* No link (``href``) is ever built from repository data, so a value such as
  ``javascript:...`` can never become a clickable link.
"""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, StrictUndefined

from reposentinel.models import SEVERITY_ORDER, CheckStatus, ScanReport
from reposentinel.reporting.common import (
    DISCLAIMER,
    OUTCOME_HEADLINES,
    clean,
    excluded_paths,
    report_notes,
)


def template_environment() -> Environment:
    env = Environment(
        loader=PackageLoader("reposentinel", "reporting/templates"),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["clean"] = clean
    return env


def render_html(report: ScanReport) -> str:
    template = template_environment().get_template("report.html.j2")
    remediation: dict[str, tuple[str, str]] = {}
    for finding in report.findings:
        remediation.setdefault(finding.rule_id, (finding.title, finding.remediation))
    return template.render(
        report=report,
        outcome=report.outcome.value,
        headline=OUTCOME_HEADLINES[report.outcome],
        disclaimer=DISCLAIMER,
        severity_order=SEVERITY_ORDER,
        severity_counts=report.severity_counts(),
        status_counts={
            status.value: sum(1 for c in report.checks if c.status is status)
            for status in CheckStatus
        },
        remediation=remediation,
        notes=report_notes(report),
        excluded=excluded_paths(report),
    )
