"""Fingerprints for tracked findings.

A fingerprint lets a comparison recognise "the same finding" in two scans
without depending on line numbers. It is computed from a small list of
*identity inputs*, never from secret values or free repository text.

Allowed identity inputs (see docs/product-strategy.md, section 6.5):

* **RepoSentinel vocabulary:** values chosen from lists defined in
  RepoSentinel's own code, such as a rule ID, a private-key type label, the
  normalised name of a GitHub Actions context, or the kind of script.
* **Structural identifiers** from the repository: a relative path, a workflow
  job ID, or an action's ``owner/repo``.

Every input passes through the same credential-pattern redaction that the
engine applies to report text, so a fingerprint can never encode a value that
matches a supported credential pattern. Workflow expressions, script text,
step names, YAML values, matched secrets and file contents are never inputs.

The fingerprint is ``rs1:`` followed by the SHA-256 of a canonical JSON array,
so identical inputs give identical fingerprints on every platform.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable

from reposentinel.checks.secrets import redact_known_secrets

FINGERPRINT_SCHEME = "rs1"
FINGERPRINT_PREFIX = FINGERPRINT_SCHEME + ":"


def _canonical(value: str) -> str:
    # NFC so that the same file name gives the same fingerprint whether the
    # file system stores it composed or decomposed (macOS can do the latter).
    return redact_known_secrets(unicodedata.normalize("NFC", value))


def fingerprint(rule_id: str, path: str | None, parts: Iterable[str] = ()) -> str:
    """Return the fingerprint for a tracked finding.

    ``parts`` are the rule-specific identity inputs, written as ``name=value``
    strings so that, for example, a job called ``workflow`` cannot be confused
    with the workflow-level scope.
    """
    inputs = [FINGERPRINT_SCHEME, rule_id, path or "", *parts]
    payload = json.dumps([_canonical(value) for value in inputs], separators=(",", ":"))
    # ensure_ascii (the json default) makes the payload plain ASCII, including
    # escaped lone surrogates from undecodable POSIX file names.
    return FINGERPRINT_PREFIX + hashlib.sha256(payload.encode("ascii")).hexdigest()


def is_valid_fingerprint(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(FINGERPRINT_PREFIX)
        and len(value) == len(FINGERPRINT_PREFIX) + 64
        and all(c in "0123456789abcdef" for c in value[len(FINGERPRINT_PREFIX) :])
    )
