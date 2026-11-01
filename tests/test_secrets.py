"""Credential-pattern rules RS-SEC-001 to RS-SEC-005, including redaction."""

from __future__ import annotations

import pytest

from reposentinel.checks.secrets import SecretsCheck, redact_known_secrets
from reposentinel.models import Finding, Severity
from reposentinel.redact import REDACTED
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import rule_ids, scan


def findings_for(text: str) -> list[Finding]:
    return list(SecretsCheck().scan_text("file.txt", text))


def ids_for(text: str) -> list[str]:
    return [finding.rule_id for finding in findings_for(text)]


def assert_no_secret_leaks(findings: list[Finding]) -> None:
    for finding in findings:
        for value in synthetic.SECRET_VALUES:
            for field in (finding.summary, finding.evidence, finding.title, finding.remediation):
                assert value not in field, f"{finding.rule_id} leaked a secret into a report field"


# --- RS-SEC-001 private keys --------------------------------------------------


@pytest.mark.parametrize(
    ("header", "label"),
    [
        (synthetic.PEM_RSA_HEADER, "RSA"),
        (synthetic.PEM_OPENSSH_HEADER, "OPENSSH"),
        (synthetic.PEM_ENCRYPTED_HEADER, "encrypted PKCS#8"),
        ("-----BEGIN " + "PRIVATE KEY-----", "PKCS#8"),
        ("-----BEGIN " + "PGP PRIVATE KEY BLOCK-----", "PGP"),
    ],
)
def test_private_key_headers(header: str, label: str) -> None:
    (finding,) = findings_for(f"line one\n{header}\nMIIB...\n")
    assert finding.rule_id == "RS-SEC-001"
    assert finding.line == 2
    assert finding.evidence == f"private key header (type: {label})"
    assert finding.severity is Severity.HIGH


def test_encrypted_key_summary_mentions_offline_attack() -> None:
    (finding,) = findings_for(synthetic.PEM_ENCRYPTED_HEADER)
    assert "offline" in finding.summary


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN " + "PUBLIC KEY-----",
        "-----BEGIN " + "CERTIFICATE-----",
        "The docs mention a BEGIN PRIVATE KEY marker without dashes.",
    ],
)
def test_public_material_is_not_reported(text: str) -> None:
    assert findings_for(text) == []


# --- RS-SEC-002 / RS-SEC-003 AWS ------------------------------------------------


def test_aws_access_key_id_long_term_and_temporary() -> None:
    long_term, temporary = findings_for(f"{synthetic.AWS_KEY_ID}\n{synthetic.AWS_TEMP_KEY_ID}")
    assert (long_term.rule_id, long_term.evidence) == ("RS-SEC-002", "AKIA" + REDACTED)
    assert "long-term" in long_term.summary
    assert (temporary.evidence, temporary.line) == ("ASIA" + REDACTED, 2)
    assert "temporary" in temporary.summary


@pytest.mark.parametrize(
    "text",
    [
        synthetic.AWS_DOCS_EXAMPLE_KEY_ID,  # the example key from AWS documentation
        "AKIA" + "SHORT",  # too short
        "XAKIA" + "TESTONLY" + "0" * 8,  # part of a longer word
        "akia" + "testonly" + "0" * 8,  # lower case is not a key ID
    ],
)
def test_aws_key_id_negatives(text: str) -> None:
    assert ids_for(text) == []


@pytest.mark.parametrize(
    "template",
    [
        'aws_secret_access_key = "{}"',
        "AWS_SECRET_ACCESS_KEY={}",
        '"SecretAccessKey": "{}"',
        "aws_secret_access_key: {}",
    ],
)
def test_aws_secret_access_key_assignments(template: str) -> None:
    (finding,) = findings_for(template.format(synthetic.AWS_SECRET))
    assert finding.rule_id == "RS-SEC-003"
    assert finding.evidence == f"secret access key = {REDACTED}"


@pytest.mark.parametrize(
    "text",
    [
        "aws_secret_access_key = " + synthetic.AWS_DOCS_EXAMPLE_SECRET,  # AWS docs example
        "aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']",
        "secret = " + synthetic.AWS_SECRET,  # 40 characters, but no recognisable name
        "aws_secret_access_key = " + synthetic.AWS_SECRET + "MORE",  # longer than 40
    ],
)
def test_aws_secret_negatives(text: str) -> None:
    assert "RS-SEC-003" not in ids_for(text)


# --- RS-SEC-004 GitHub tokens -------------------------------------------------


def test_github_classic_token() -> None:
    (finding,) = findings_for(f'token = "{synthetic.GITHUB_TOKEN}"')
    assert (finding.rule_id, finding.evidence) == ("RS-SEC-004", "ghp_" + REDACTED)


def test_github_fine_grained_token() -> None:
    (finding,) = findings_for(synthetic.GITHUB_FINE_GRAINED_TOKEN)
    assert finding.evidence == "github_pat_" + REDACTED


@pytest.mark.parametrize("prefix", ["gho_", "ghu_", "ghs_", "ghr_"])
def test_other_github_token_prefixes(prefix: str) -> None:
    assert ids_for(prefix + synthetic.GITHUB_TOKEN[4:]) == ["RS-SEC-004"]


@pytest.mark.parametrize(
    "text",
    [
        "ghp_" + "tooShort",
        "ghx_" + synthetic.GITHUB_TOKEN[4:],  # unknown prefix
        synthetic.GITHUB_TOKEN + "X",  # longer than the format allows
        "my_ghp_" + synthetic.GITHUB_TOKEN[4:],  # embedded in an identifier
    ],
)
def test_github_token_negatives(text: str) -> None:
    assert ids_for(text) == []


# --- RS-SEC-005 credentials in URLs -------------------------------------------


def test_credentials_in_url() -> None:
    (finding,) = findings_for(f"DB=postgres://admin:{synthetic.URL_PASSWORD}@db.internal.test/app")
    assert finding.rule_id == "RS-SEC-005"
    # User name, password and host are all hidden: an internal host name can
    # itself be sensitive, and the file and line already locate the finding.
    assert finding.evidence == f"postgres://{REDACTED}@{REDACTED}"
    assert "admin" not in finding.evidence and "internal" not in finding.evidence
    assert "internal" not in finding.summary


def test_unknown_url_scheme_is_not_shown() -> None:
    scheme = "corp" + "vault"  # free repository text, not RepoSentinel vocabulary
    (finding,) = findings_for(f"X={scheme}://svc:{synthetic.URL_PASSWORD}@host.example.test/")
    assert finding.evidence == f"{REDACTED}://{REDACTED}@{REDACTED}"
    assert scheme not in finding.summary and scheme not in finding.evidence


@pytest.mark.parametrize(
    "password",
    [
        "password",
        "PASSWORD",
        "changeme",
        "${DB_PASSWORD}",
        "$DB_PASSWORD",
        "<password>",
        "{{ db_password }}".replace(" ", ""),
        "%s",
        "****",
        "xxxxxx",
        "example-pass",
    ],
)
def test_placeholder_passwords_are_ignored(password: str) -> None:
    assert ids_for(f"postgres://user:{password}@localhost:5432/db") == []


def test_url_without_password_is_not_reported() -> None:
    assert ids_for("https://user@example.test/repo.git and https://example.test:8080/") == []


# --- general behaviour ----------------------------------------------------------


def test_every_pattern_in_one_file_with_line_numbers(make_repo: RepoFactory) -> None:
    report = scan(make_repo({"config/settings.py": synthetic.credential_file()}))
    found = sorted((f.rule_id, f.line) for f in report.findings)
    assert found == [
        ("RS-SEC-001", 6),
        ("RS-SEC-002", 3),
        ("RS-SEC-003", 4),
        ("RS-SEC-004", 2),
        ("RS-SEC-005", 5),
    ]
    assert_no_secret_leaks(list(report.findings))


def test_utf16_file_is_scanned(make_repo: RepoFactory) -> None:
    # PowerShell 5.1 writes UTF-16 files by default; they must not be skipped as binary.
    text = f"GITHUB_TOKEN={synthetic.GITHUB_TOKEN}\n"
    report = scan(make_repo({"settings.cfg": text.encode("utf-16")}))
    assert rule_ids(report) == ["RS-SEC-004"]


def test_binary_files_are_not_scanned(make_repo: RepoFactory) -> None:
    data = b"\x00\x01" + synthetic.GITHUB_TOKEN.encode()
    report = scan(make_repo({"blob.bin": data}))
    assert rule_ids(report) == []
    assert [i.reason.value for i in report.coverage] == ["binary"]


def test_clean_text_has_no_findings() -> None:
    assert findings_for("import os\nTOKEN = os.environ['GITHUB_TOKEN']\n") == []


def test_redact_known_secrets_in_free_text() -> None:
    text = (
        f"failed with {synthetic.GITHUB_TOKEN} and {synthetic.AWS_KEY_ID} "
        f"at postgres://u:{synthetic.URL_PASSWORD}@db.test"
    )
    redacted = redact_known_secrets(text)
    for value in synthetic.SECRET_VALUES:
        assert value not in redacted
    assert redacted.endswith(f"at postgres://{REDACTED}")  # user, password and host hidden
    assert redacted.startswith("failed with " + REDACTED)


# --- regressions found in the October 2026 security audit --------------------


@pytest.mark.parametrize(
    ("password", "host"),
    [
        ("Pa" + "@" + "ssw0rdTail", "localhost"),  # unencoded "@" inside the password
        ("a@b@cTail", "db.internal.test"),
    ],
)
def test_password_containing_at_sign_is_not_shown_as_host(password: str, host: str) -> None:
    (finding,) = findings_for(f"mysql://root:{password}@{host}/db")
    assert finding.evidence == f"mysql://{REDACTED}@{REDACTED}"
    assert "Tail" not in finding.evidence and host not in finding.evidence


# URLs are assembled at run time so this file does not trigger the rule itself.
AMBIGUOUS_URL = "https://user:" + "Qz@Wv/Xy" + "@host.example.test"
AT_SIGN_URL = "mysql://root:" + "Pa@ssTail" + "@localhost/db"


def test_ambiguous_url_split_hides_the_host() -> None:
    # A password with both "@" and "/" cannot be split reliably; the apparent
    # host ("Wv") is really part of the password and must not be shown.
    (finding,) = findings_for(AMBIGUOUS_URL)
    assert finding.evidence == f"https://{REDACTED}@{REDACTED}"
    assert "Wv" not in finding.evidence and "Xy" not in finding.evidence


def test_free_text_redaction_never_keeps_password_fragments() -> None:
    assert redact_known_secrets(f"see {AMBIGUOUS_URL} now") == f"see https://{REDACTED} now"
    assert redact_known_secrets(f"db {AT_SIGN_URL}") == f"db mysql://{REDACTED}/db"


@pytest.mark.parametrize(
    "text",
    [
        "ghp_" + "x" * 36,
        "ghs_" + "X" * 36,
        "github_pat_" + "X" * 22 + "_" + "X" * 59,
        "AKIA" + "X" * 16,
        "ASIA" + "0" * 16,
    ],
)
def test_obvious_placeholder_tokens_are_ignored(text: str) -> None:
    assert ids_for(f"token: {text}") == []
