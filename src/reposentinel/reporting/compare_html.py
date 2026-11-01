"""Self-contained HTML comparison page.

It uses the same environment as the scan report (``html_report``): Jinja2
autoescaping for every value, the ``clean`` filter for report-derived text,
and the shared Content-Security-Policy meta tags (no JavaScript, nothing
loaded from the network). No link is ever built from report data.
"""

from __future__ import annotations

from reposentinel.compare import (
    CREDENTIAL_REMINDER,
    SCOPE_STATEMENT,
    ComparisonResult,
    exit_explanation,
    headline,
    summary_sentences,
)
from reposentinel.models import SEVERITY_ORDER
from reposentinel.reporting import compare_common
from reposentinel.reporting.html_report import template_environment


def render_compare_html(result: ComparisonResult) -> str:
    env = template_environment()
    env.filters["status_text"] = compare_common.status_text
    env.filters["location_text"] = compare_common.location_text
    template = env.get_template("compare.html.j2")
    return template.render(
        result=result,
        headline=headline(result),
        scope=SCOPE_STATEMENT,
        summary=summary_sentences(result),
        disclaimer=compare_common.COMPARE_DISCLAIMER,
        reminder=CREDENTIAL_REMINDER,
        exit_explanation=exit_explanation(result),
        severity_order=SEVERITY_ORDER,
        detected=compare_common.detected(result),
        unknown=compare_common.unknown(result),
        reminders=compare_common.reminders(result),
        no_longer=compare_common.no_longer_detected(result),
        sections={
            "detected": compare_common.SECTION_DETECTED,
            "unknown": compare_common.SECTION_UNKNOWN,
            "not_examined": compare_common.SECTION_NOT_EXAMINED,
            "reminders": compare_common.SECTION_REMINDERS,
            "no_longer": compare_common.SECTION_NO_LONGER,
        },
    )
