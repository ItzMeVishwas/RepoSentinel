"""Risky files in the repository tree (rules RS-HYG-001 to RS-HYG-003).

These rules look at file *names*, which makes them fast and predictable but
also limited: a name suggests what a file contains, it does not prove it.
The content-based credential rules live in ``reposentinel.checks.secrets``.

RepoSentinel never runs Git (running Git inside an untrusted repository can
execute commands configured by that repository), so these rules cannot tell
whether a file is tracked. They report what is present in the directory.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from dataclasses import dataclass

from reposentinel.checks.base import Check, CheckOutput
from reposentinel.context import ScanContext
from reposentinel.models import Confidence, Finding, Rule, Severity
from reposentinel.walker import FileEntry

ENV_FILE = Rule(
    id="RS-HYG-001",
    title="Environment (.env) file present",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description=(
        "A dotenv-style file (.env, .env.local, production.env, ...) exists in the repository "
        "tree. These files conventionally hold API keys, passwords and connection strings for "
        "local use, and are often committed by mistake."
    ),
    severity_rationale=(
        "Medium when the root .gitignore does not appear to ignore the file, because it is then "
        "easy to commit (or already committed). Reported as info when a root .gitignore pattern "
        "matches, because the file is then probably a local, untracked copy."
    ),
    remediation=(
        "Make sure the file is not tracked ('git ls-files <path>' prints nothing) and is listed "
        "in .gitignore. Commit a .env.example with placeholder values instead. If the file was "
        "ever committed, rotate every secret in it: it remains in Git history."
    ),
    limitations=(
        "RepoSentinel does not run Git, so it cannot tell whether the file is tracked. Only the "
        "root .gitignore is consulted, with simplified matching (nested .gitignore files, global "
        "excludes and .git/info/exclude are not read). Template files such as .env.example, "
        ".env.sample and .env.template are not reported."
    ),
    recheck_limits=(
        "The rule checks file names only. A renamed file (for example settings.cfg) can still "
        "hold the same secrets, and a file deleted now is still in Git history."
    ),
)

KEY_FILE = Rule(
    id="RS-HYG-002",
    title="Private key or keystore file",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description=(
        "A file with a name conventionally used for private keys or keystores was found: SSH "
        "private keys (id_rsa, id_ed25519, ...), PKCS#12 bundles (.p12, .pfx), Java keystores "
        "(.jks, .keystore) or PuTTY private keys (.ppk)."
    ),
    severity_rationale=(
        "Medium: the name strongly suggests key material, but the file may be a test fixture. "
        "When the content is a recognisable PEM private key, RS-SEC-001 also reports it at high "
        "severity."
    ),
    remediation=(
        "Remove the file from the repository and from Git history, replace the key or "
        "certificate if it was real, and keep key material in a secret manager or outside the "
        "repository."
    ),
    limitations=(
        "Name-based only. Keys stored under other names, including *.pem and *.key (which are "
        "also used for certificates and unrelated formats), are not reported by this rule; PEM "
        "private keys are covered by RS-SEC-001 whatever their name. Android debug keystores are "
        "a common, usually harmless, match."
    ),
    recheck_limits=(
        "The rule checks file names only. Key material under another name is not detected, and a "
        "removed key file stays in Git history and stays valid until the key is replaced."
    ),
)

CREDENTIAL_STORE = Rule(
    id="RS-HYG-003",
    title="Plain-text credential store file",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description=(
        "A file whose purpose is to store credentials in plain text was found: .git-credentials "
        "(Git's credential store), .netrc or _netrc (logins for curl, FTP and Git) or .pgpass "
        "(PostgreSQL passwords)."
    ),
    severity_rationale=(
        "High: these files exist to hold reusable passwords or tokens in clear text. Confidence "
        "is medium because the file could be a deliberately fake fixture."
    ),
    remediation=(
        "Remove the file from the repository and from Git history, change every password or token "
        "it contained, and keep such files in your home directory, where these tools look for "
        "them by default."
    ),
    limitations=(
        "Name-based; empty files are ignored. Other credential files (cloud CLI configuration, "
        ".npmrc or .pypirc containing tokens, application configuration) are not covered."
    ),
    recheck_limits=(
        "The rule checks file names only. Credentials kept under another name are not detected, "
        "and removed credentials stay in Git history and stay valid until they are changed."
    ),
)

RULES: tuple[Rule, ...] = (ENV_FILE, KEY_FILE, CREDENTIAL_STORE)

# Name parts that mark a dotenv file as a template rather than real configuration.
_ENV_TEMPLATE_MARKERS = frozenset(
    {"example", "examples", "sample", "template", "tmpl", "tpl", "dist", "default", "defaults"}
)
_SSH_PRIVATE_KEY_NAMES = frozenset(
    {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk"}
)
_KEYSTORE_SUFFIXES = (".p12", ".pfx", ".jks", ".keystore", ".ppk")
_CREDENTIAL_STORE_NAMES = frozenset({".git-credentials", ".netrc", "_netrc", ".pgpass"})


def is_env_file(name: str) -> bool:
    lowered = name.lower()
    if not (lowered == ".env" or lowered.startswith(".env.") or lowered.endswith(".env")):
        return False
    return not _ENV_TEMPLATE_MARKERS.intersection(lowered.split("."))


def is_key_file(name: str) -> bool:
    lowered = name.lower()
    return lowered in _SSH_PRIVATE_KEY_NAMES or lowered.endswith(_KEYSTORE_SUFFIXES)


@dataclass(frozen=True, slots=True)
class _IgnorePattern:
    text: str  # the pattern as written, for messages
    glob: str
    negated: bool
    anchored: bool  # contains a slash: matched against the path, not just a name
    dir_only: bool  # ends with a slash: matches directories only


def _parse_gitignore(text: str) -> list[_IgnorePattern]:
    patterns = []
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        body = line[1:] if negated else line
        dir_only = body.endswith("/")
        body = body.rstrip("/")
        if body.startswith("**/"):
            body = body[3:]
        anchored = "/" in body
        body = body.lstrip("/")
        if body:
            patterns.append(_IgnorePattern(line, body, negated, anchored, dir_only))
    return patterns


def _pattern_matches(pattern: _IgnorePattern, path: str) -> bool:
    """Does ``pattern`` match the file at ``path`` or one of its parent directories?"""
    parts = path.split("/")
    for depth in range(1, len(parts) + 1):
        is_directory = depth < len(parts)
        if pattern.dir_only and not is_directory:
            continue
        candidate = "/".join(parts[:depth]) if pattern.anchored else parts[depth - 1]
        if fnmatch.fnmatchcase(candidate, pattern.glob):
            return True
    return False


def root_gitignore_matcher(context: ScanContext) -> Callable[[str], str | None]:
    """Return a function giving the root .gitignore pattern that ignores a path, if any.

    This is an approximation of Git's rules, good enough to lower the
    severity of a probably-local file; it is never used to hide a finding.
    """
    entry = context.get(".gitignore")
    text = context.read_text(entry) if entry else None
    patterns = _parse_gitignore(text or "")

    def matcher(path: str) -> str | None:
        decision: str | None = None
        for pattern in patterns:  # the last matching pattern wins, as in Git
            if _pattern_matches(pattern, path):
                decision = None if pattern.negated else pattern.text
        return decision

    return matcher


class HygieneCheck(Check):
    id = "hygiene"
    name = "Risky files in the repository"
    description = "Looks for dotenv files, private key files and credential stores by name."
    rules = RULES

    def run(self, context: ScanContext) -> CheckOutput:
        ignored_by = root_gitignore_matcher(context)
        findings: list[Finding] = []
        for entry in context.files:
            findings.extend(self._check_file(entry, ignored_by))
        # These rules look at file names, so every in-scope file is examined.
        return CheckOutput(
            findings=findings,
            examined=len(context.files),
            examined_paths=tuple(entry.path for entry in context.files),
        )

    def _check_file(
        self, entry: FileEntry, ignored_by: Callable[[str], str | None]
    ) -> list[Finding]:
        name = entry.name
        if is_env_file(name):
            pattern = ignored_by(entry.path)
            if pattern is None:
                return [
                    self.finding(
                        ENV_FILE,
                        summary="Environment file is present and the root .gitignore does not "
                        "appear to ignore it.",
                        evidence=f"file name: {name}",
                        path=entry.path,
                    )
                ]
            return [
                self.finding(
                    ENV_FILE,
                    summary="Environment file is present; it appears to be ignored by the root "
                    f".gitignore (pattern '{pattern}'), so it is probably a local copy.",
                    evidence=f"file name: {name}",
                    path=entry.path,
                    severity=Severity.INFO,
                )
            ]
        if is_key_file(name):
            return [
                self.finding(
                    KEY_FILE,
                    summary="File name suggests private key or keystore material.",
                    evidence=f"file name: {name}",
                    path=entry.path,
                )
            ]
        if name.lower() in _CREDENTIAL_STORE_NAMES and entry.size > 0:
            return [
                self.finding(
                    CREDENTIAL_STORE,
                    summary="File name matches a plain-text credential store.",
                    evidence=f"file name: {name}",
                    path=entry.path,
                )
            ]
        return []
