"""Report renderers. Each takes a ``ScanReport`` and never modifies it."""

from reposentinel.reporting.html_report import render_html
from reposentinel.reporting.json_report import SCHEMA_VERSION, render_json, report_to_dict
from reposentinel.reporting.terminal import make_console, render_terminal

__all__ = [
    "SCHEMA_VERSION",
    "make_console",
    "render_html",
    "render_json",
    "render_terminal",
    "report_to_dict",
]
