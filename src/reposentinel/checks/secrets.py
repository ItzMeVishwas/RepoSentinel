"""Selected hard-coded credential patterns (rules RS-SEC-001 to RS-SEC-005).

This is deliberately **not** a general-purpose secret scanner. It looks for a
handful of credential formats that are distinctive enough to match with few
false positives. For broad coverage, use a dedicated tool such as Gitleaks
(see ``reposentinel.integrations.gitleaks``).

Matched values are redacted *before* a finding is created, so a secret can
never reach a report, a log line, or an error message through this check.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from reposentinel.checks.base import Check, CheckOutput
from reposentinel.context import ScanContext
from reposentinel.models import Confidence, Finding, Rule, Severity
from reposentinel.redact import REDACTED, mask

PRIVATE_KEY = Rule(
    id="RS-SEC-001",
    title="Private key block",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description=(
        "A PEM, OpenSSH or PGP private key header was found. Whoever holds a private key can "
        "impersonate the server, user or signing identity it belongs to."
    ),
    severity_rationale=(
        "High: a real private key usually grants direct access or signing ability. It is not "
        "rated higher because the key may be a test key or already revoked, which RepoSentinel "
        "cannot determine."
    ),
    remediation=(
        "Remove the key from the repository and from Git history, then treat it as compromised: "
        "revoke or replace it and store the new key outside the repository (a secret manager, "
        "CI secret, or a local file listed in .gitignore)."
    ),
    limitations=(
        "Detects the header line only and does not check that a valid key follows. Keys in other "
        "encodings (PKCS#12, Java keystores, base64 blobs) are not detected by this rule. Test "
        "fixtures in cryptography projects are a common false positive."
    ),
    recheck_limits=(
        "A key that was re-encoded (for example base64) or moved to a file that was not "
        "examined is not detected. A removed key stays in Git history and stays usable until "
        "it is replaced."
    ),
)

AWS_ACCESS_KEY_ID = Rule(
    id="RS-SEC-002",
    title="AWS access key ID",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description=(
        "A value in the format of an AWS access key ID was found (AKIA... for long-term keys, "
        "ASIA... for temporary ones)."
    ),
    severity_rationale=(
        "Medium: the key ID alone does not grant access, but it identifies an AWS credential and "
        "is rarely committed without its secret access key nearby (see RS-SEC-003)."
    ),
    remediation=(
        "Look for the matching secret access key. If the key is real, deactivate and delete it "
        "in AWS IAM, review CloudTrail for unexpected use, and obtain credentials at runtime "
        "instead (IAM roles, IAM Identity Center, or CI-provided secrets)."
    ),
    limitations=(
        "Matches the documented key-ID format only and does not check that the key exists. "
        "Values containing 'EXAMPLE' (used throughout AWS documentation) and placeholders whose "
        "last 16 characters are one repeated character (AKIAXXXXXXXXXXXXXXXX) are ignored."
    ),
    references=(
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    ),
    recheck_limits=(
        "A key ID that was split, encoded or moved to a file that was not examined is not "
        "detected. A removed key stays valid until it is deactivated in AWS."
    ),
)

AWS_SECRET_ACCESS_KEY = Rule(
    id="RS-SEC-003",
    title="AWS secret access key assignment",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    description=(
        "A 40-character value assigned to a name such as aws_secret_access_key or "
        "SecretAccessKey was found."
    ),
    severity_rationale=(
        "High: together with its key ID, a secret access key grants whatever AWS permissions the "
        "key has. Confidence is medium because the rule relies on the variable name."
    ),
    remediation=(
        "Deactivate and delete the key pair in AWS IAM, review CloudTrail for unexpected use, "
        "and obtain credentials at runtime instead of storing them in files."
    ),
    limitations=(
        "Only detects values assigned to a recognisable name on the same line. Secrets stored "
        "under other names, split across lines, or encoded are missed. Values containing "
        "'EXAMPLE' are ignored."
    ),
    recheck_limits=(
        "Renaming the variable stops this name-based rule from matching. The key stays valid "
        "until it is deactivated in AWS, and stays in Git history."
    ),
)

GITHUB_TOKEN = Rule(
    id="RS-SEC-004",
    title="GitHub token",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description=(
        "A value in a documented GitHub token format was found: personal access tokens "
        "(ghp_, github_pat_), OAuth tokens (gho_), user-to-server (ghu_), server-to-server (ghs_) "
        "or refresh tokens (ghr_)."
    ),
    severity_rationale=(
        "High: a valid token acts as the user or app it was issued to, often with write access "
        "to repositories."
    ),
    remediation=(
        "Revoke the token in GitHub (Settings > Developer settings, or the organisation's token "
        "management page), review the account's security log, and supply tokens through CI "
        "secrets or a credential helper instead of source files."
    ),
    limitations=(
        "Matches token formats only; it does not validate the checksum or contact GitHub. "
        "Legacy 40-character hexadecimal tokens are not detected. Placeholders whose random part "
        "is one repeated character (ghp_xxxx...) are ignored."
    ),
    references=(
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats",
    ),
    recheck_limits=(
        "A token split into pieces or encoded is not detected. A removed token stays valid "
        "until it is revoked, and stays in Git history."
    ),
)

URL_CREDENTIALS = Rule(
    id="RS-SEC-005",
    title="Credentials embedded in a URL",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    description=(
        "A URL of the form scheme://user:password@host was found, for example a database "
        "connection string with an inline password."
    ),
    severity_rationale=(
        "Medium: such URLs often point at development databases, but they are copied into logs, "
        "error messages and shell history, and production values do end up committed."
    ),
    remediation=(
        "Move the password out of the URL into an environment variable or secret store and build "
        "the URL at runtime. Change the password if it was ever used for a real system."
    ),
    limitations=(
        "Obvious placeholders (such as 'password', 'changeme', '${DB_PASSWORD}', '<password>' or "
        "'****') are ignored, which also hides real passwords that happen to equal a placeholder. "
        "Passwords containing spaces, quotes or an unescaped '/', '?' or '#' are not matched. "
        "The evidence never shows the user name, password or host name (host names can reveal "
        "internal systems); open the file at the reported line to see which system it is."
    ),
    recheck_limits=(
        "A password written in another form, or moved to a file that was not examined, is not "
        "detected. Change the password if it was ever used for a real system."
    ),
)

RULES: tuple[Rule, ...] = (
    PRIVATE_KEY,
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    GITHUB_TOKEN,
    URL_CREDENTIALS,
)

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA|DSA|EC|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----"
)
_AWS_KEY_ID_RE = re.compile(r"(?<![A-Z0-9])(?P<secret>(?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])")
_AWS_SECRET_RE = re.compile(
    r"(?i)\b(?:aws_?)?secret_?access_?key\b[\"']?\s*[:=]\s*[\"']?"
    r"(?P<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
)
_GITHUB_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<secret>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}"
    r"|github_pat_[A-Za-z0-9_]{82})(?![A-Za-z0-9_])"
)
# The password may contain "@" (people often forget to percent-encode it), so it
# is matched greedily up to the LAST "@" before the host, as browsers do.
_URL_CREDENTIALS_RE = re.compile(
    r"\b(?P<scheme>[A-Za-z][A-Za-z0-9+.-]{1,19})://"
    r"(?P<user>[^\s:/?#@'\"<>]+):(?P<secret>[^\s/?#'\"<>]+)@(?P<host>[A-Za-z0-9.-]+)"
)
# URL schemes shown in evidence; any other scheme is free repository text.
_KNOWN_URL_SCHEMES = frozenset(
    {
        "amqp",
        "amqps",
        "ftp",
        "ftps",
        "git",
        "http",
        "https",
        "ldap",
        "ldaps",
        "mongodb",
        "mongodb+srv",
        "mssql",
        "mysql",
        "postgres",
        "postgresql",
        "redis",
        "rediss",
        "sftp",
        "smtp",
        "smtps",
        "ssh",
    }
)

_PLACEHOLDER_PASSWORDS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "pwd",
        "secret",
        "changeme",
        "change_me",
        "changeit",
        "redacted",
        "example",
        "token",
        "user",
        "username",
    }
)


def _is_repeated_character(value: str) -> bool:
    """True for obvious placeholders such as ghp_xxxx... or AKIAXXXX..."""
    return len(set(value) - {"_"}) <= 1


def _is_placeholder_password(value: str) -> bool:
    lowered = value.lower()
    return (
        lowered in _PLACEHOLDER_PASSWORDS
        or value[0] in "$%<{[*"  # ${VAR}, $VAR, %s, <password>, {{ x }}, [x], ****
        or len(set(value)) == 1  # xxxxxx
        or "example" in lowered
    )


# A describer turns a regex match into (summary, redacted evidence), or returns
# None when the match should be ignored (placeholder, documentation example).
_Describer = Callable[[re.Match[str]], tuple[str, str] | None]


def _describe_private_key(match: re.Match[str]) -> tuple[str, str]:
    kind = (match.group("kind") or "").strip()
    label = {"": "PKCS#8", "ENCRYPTED": "encrypted PKCS#8"}.get(kind, kind)
    summary = f"File contains a private key header ({label})."
    if kind == "ENCRYPTED":
        summary += " The key is passphrase-protected, but can still be attacked offline."
    return summary, f"private key header (type: {label})"


def _describe_aws_key_id(match: re.Match[str]) -> tuple[str, str] | None:
    value = match.group("secret")
    if "EXAMPLE" in value or _is_repeated_character(value[4:]):
        return None
    kind = "long-term" if value.startswith("AKIA") else "temporary"
    return f"Possible {kind} AWS access key ID.", mask(value, keep_prefix=4)


def _describe_aws_secret(match: re.Match[str]) -> tuple[str, str] | None:
    if "EXAMPLE" in match.group("secret"):
        return None
    return (
        "Possible AWS secret access key assigned in plain text.",
        f"secret access key = {REDACTED}",
    )


def _describe_github_token(match: re.Match[str]) -> tuple[str, str] | None:
    value = match.group("secret")
    prefix = "github_pat_" if value.startswith("github_pat_") else value[:4]
    if _is_repeated_character(value[len(prefix) :]):
        return None
    return "Possible GitHub token.", mask(value, keep_prefix=len(prefix))


def _describe_url_credentials(match: re.Match[str]) -> tuple[str, str] | None:
    if _is_placeholder_password(match.group("secret")):
        return None
    # Only a known scheme is shown; the host is never shown, because an
    # internal host name can itself be sensitive, and when the password
    # contains "@" the apparent host may even be part of the password.
    scheme = match.group("scheme").lower()
    if scheme not in _KNOWN_URL_SCHEMES:
        return (
            "A URL contains an inline username and password.",
            f"{REDACTED}://{REDACTED}@{REDACTED}",
        )
    return (
        f"A {scheme} URL contains an inline username and password.",
        f"{scheme}://{REDACTED}@{REDACTED}",
    )


def _no_identity(match: re.Match[str]) -> tuple[str, ...]:
    """Default: the rule ID and path are the whole identity (secret values never are)."""
    return ()


def _private_key_identity(match: re.Match[str]) -> tuple[str, ...]:
    # The key type comes from the regex's fixed list (RSA, DSA, EC, OPENSSH,
    # ENCRYPTED, PGP or none), so it is RepoSentinel vocabulary, not file text.
    return ("key_type=" + ((match.group("kind") or "").strip() or "PKCS8"),)


@dataclass(frozen=True, slots=True)
class _Detector:
    rule: Rule
    regex: re.Pattern[str]
    describe: _Describer
    identity: Callable[[re.Match[str]], tuple[str, ...]] = _no_identity


_DETECTORS: tuple[_Detector, ...] = (
    _Detector(PRIVATE_KEY, _PRIVATE_KEY_RE, _describe_private_key, _private_key_identity),
    _Detector(AWS_ACCESS_KEY_ID, _AWS_KEY_ID_RE, _describe_aws_key_id),
    _Detector(AWS_SECRET_ACCESS_KEY, _AWS_SECRET_RE, _describe_aws_secret),
    _Detector(GITHUB_TOKEN, _GITHUB_TOKEN_RE, _describe_github_token),
    _Detector(URL_CREDENTIALS, _URL_CREDENTIALS_RE, _describe_url_credentials),
)

# Redaction of free text (used as a last line of defence for every finding,
# message and error). Private key headers are not secret themselves.
_REDACTABLE = (_AWS_KEY_ID_RE, _AWS_SECRET_RE, _GITHUB_TOKEN_RE)
# For URLs the whole user:password@host part, and the rest of the URL if it
# contains another "@", is replaced, so no password fragment can survive.
_URL_IN_TEXT_RE = re.compile(_URL_CREDENTIALS_RE.pattern + r"(?P<rest>[^\s'\"<>]*)")


def _redact_secret_group(match: re.Match[str]) -> str:
    """Keep the text around the "secret" group, replace the group itself."""
    offset = match.start()
    start, end = match.span("secret")
    return match.group()[: start - offset] + REDACTED + match.group()[end - offset :]


def _redact_url(match: re.Match[str]) -> str:
    rest = match.group("rest")
    return f"{match.group('scheme')}://{REDACTED}" + ("" if "@" in rest else rest)


def redact_known_secrets(text: str) -> str:
    """Replace anything matching a credential pattern in ``text`` with a marker."""
    for regex in _REDACTABLE:
        text = regex.sub(_redact_secret_group, text)
    return _URL_IN_TEXT_RE.sub(_redact_url, text)


class SecretsCheck(Check):
    id = "secrets"
    name = "Hard-coded credential patterns"
    description = "Looks for a small set of distinctive credential formats in text files."
    rules = RULES

    def run(self, context: ScanContext) -> CheckOutput:
        findings: list[Finding] = []
        examined: list[str] = []
        for entry in context.files:
            text = context.read_text(entry)
            if text is None:
                continue  # recorded as a coverage issue (binary, unreadable, ...)
            examined.append(entry.path)
            findings.extend(self.scan_text(entry.path, text))
        return CheckOutput(
            findings=findings, examined=len(examined), examined_paths=tuple(examined)
        )

    def scan_text(self, path: str, text: str) -> Iterator[Finding]:
        for line_number, line in enumerate(text.split("\n"), start=1):
            for detector in _DETECTORS:
                for match in detector.regex.finditer(line):
                    described = detector.describe(match)
                    if described is None:
                        continue
                    summary, evidence = described
                    yield self.finding(
                        detector.rule,
                        summary=summary,
                        evidence=evidence,
                        path=path,
                        line=line_number,
                        identity=detector.identity(match),
                    )
