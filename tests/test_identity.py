"""Tracked-finding fingerprints: stability, portability, safety (AC-01 to AC-05, AC-12, AC-13)."""

from __future__ import annotations

import hashlib
import json
import string
import textwrap
import unicodedata

import pytest

from reposentinel.checks.secrets import redact_known_secrets
from reposentinel.checks.workflows import mask_literals, normalise_context
from reposentinel.identity import fingerprint, is_valid_fingerprint
from reposentinel.reporting import render_json
from tests import synthetic
from tests.conftest import RepoFactory
from tests.helpers import scan

# A second synthetic token (reversed alphabet), assembled at run time.
OTHER_TOKEN = "ghp_" + string.ascii_lowercase[::-1] + string.digits

# --- golden values (AC-13): these must be identical on Windows, Linux and macOS ---

GOLDEN = [
    (
        ("RS-SEC-004", "config.py", ()),
        "rs1:3b276aed862b0acfdfe3a91fb3512a7aca5328f1d0b30fb24c6cd1ddf44251ed",
    ),
    (
        (
            "RS-GHA-001",
            ".github/workflows/ci.yml",
            ("job=build", "context=github.event.issue.title", "sink=run"),
        ),
        "rs1:3acb6569f7bbf0a3c083e19b820c97caa5d772fca0593de1c5e22d0a954cc90a",
    ),
    (
        ("RS-HYG-001", "caf" + chr(0xE9) + "/.env", ()),
        "rs1:531f11cb321117e72375a155ce8eec872ece7c38146b4a600a5c215b6890763c",
    ),
    (
        ("RS-GHA-004", ".github/workflows/ci.yml", ("scope=workflow",)),
        "rs1:8be07b36266ad236e752b7a12ef58531f052489924fc83dd8f3281d3667ad25e",
    ),
    (
        ("gitleaks:generic-api-key", "a.txt", ()),
        "rs1:6a5612df7c1c97fa857b90bd5f426360a4d8d1ad62c80cb85081473f1727960d",
    ),
]


@pytest.mark.parametrize(("inputs", "expected"), GOLDEN)
def test_golden_fingerprints(inputs: tuple[str, str, tuple[str, ...]], expected: str) -> None:
    rule_id, path, parts = inputs
    assert fingerprint(rule_id, path, parts) == expected


def test_fingerprint_is_sha256_of_the_documented_canonical_form() -> None:
    payload = json.dumps(["rs1", "RS-SEC-004", "config.py"], separators=(",", ":"))
    expected = "rs1:" + hashlib.sha256(payload.encode("ascii")).hexdigest()
    assert fingerprint("RS-SEC-004", "config.py") == expected


def test_composed_and_decomposed_names_match() -> None:
    composed = "caf" + chr(0xE9) + "/.env"
    decomposed = "cafe" + chr(0x301) + "/.env"
    assert unicodedata.normalize("NFC", decomposed) == composed
    assert fingerprint("RS-HYG-001", composed) == fingerprint("RS-HYG-001", decomposed)


def test_inputs_cannot_run_together() -> None:
    # JSON array encoding keeps ("a", "bc") and ("ab", "c") apart.
    assert fingerprint("R", "p", ("a", "bc")) != fingerprint("R", "p", ("ab", "c"))
    assert fingerprint("R", None) == fingerprint("R", "")


def test_is_valid_fingerprint() -> None:
    good = fingerprint("RS-SEC-004", "x")
    assert is_valid_fingerprint(good)
    for bad in (None, 5, "", good.upper(), good[:-1], "rs2:" + good[4:], good + "0"):
        assert not is_valid_fingerprint(bad)


# --- AC-12(d): structural identifiers are redacted before hashing ---------------


def test_path_with_a_synthetic_token_uses_its_redacted_form() -> None:
    raw = f"keys/{synthetic.GITHUB_TOKEN}.txt"
    redacted = redact_known_secrets(raw)
    assert synthetic.GITHUB_TOKEN not in redacted
    assert fingerprint("RS-HYG-002", raw) == fingerprint("RS-HYG-002", redacted)


def test_job_id_and_action_with_a_synthetic_token_use_their_redacted_form() -> None:
    job = f"job=deploy-{synthetic.GITHUB_TOKEN}"
    action = f"action=org/{synthetic.AWS_KEY_ID.lower()}"
    for part in (job, action):
        assert fingerprint("RS-GHA-001", "w.yml", (part,)) == fingerprint(
            "RS-GHA-001", "w.yml", (redact_known_secrets(part),)
        )


# --- AC-12(b), (c): expression text is never an identity input -----------------


def _gha001(make_repo: RepoFactory, expression: str) -> str:
    workflow = textwrap.dedent(
        f"""\
        on: issues
        jobs:
          greet:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{{{ {expression} }}}}"
        """
    )
    report = scan(make_repo({".github/workflows/ci.yml": workflow}))
    (finding,) = [f for f in report.findings if f.rule_id == "RS-GHA-001"]
    return finding.fingerprint


def test_text_around_the_context_does_not_change_the_fingerprint(
    make_repo: RepoFactory,
) -> None:
    alpha = _gha001(make_repo, "github.event.issue.title || 'alpha'")
    beta = _gha001(make_repo, "github.event.issue.title || 'beta'")
    with_secret = _gha001(make_repo, f"github.event.issue.title || '{synthetic.URL_PASSWORD}'")
    plain = _gha001(make_repo, "github.event.issue.title")
    assert alpha == beta == with_secret == plain


@pytest.mark.parametrize("index", ["[0]", "[1]", "[*]", ".*", "['x']"])
def test_array_index_does_not_change_the_fingerprint(make_repo: RepoFactory, index: str) -> None:
    expected = fingerprint(
        "RS-GHA-001",
        ".github/workflows/ci.yml",
        ("job=greet", "context=github.event.commits[*].message", "sink=run"),
    )
    assert _gha001(make_repo, f"github.event.commits{index}.message") == expected


def test_normalise_context_and_mask_literals() -> None:
    assert normalise_context("github.event.commits[0].message") == (
        "github.event.commits[*].message"
    )
    assert normalise_context("github.event.pages.*.page_name") == (
        "github.event.pages[*].page_name"
    )
    assert mask_literals("${{ a || 'hunter2' }}") == "${{ a || '***' }}"
    assert mask_literals("${{ a || '' }}") == "${{ a || '' }}"
    assert mask_literals("${{ a || 'it''s' }}") == "${{ a || '***' }}"


def test_evidence_never_shows_quoted_literals(make_repo: RepoFactory) -> None:
    workflow = textwrap.dedent(
        """\
        on: issues
        jobs:
          greet:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.issue.title || 'Pa55-unrecognised-word' }}"
        """
    )
    report = scan(make_repo({".github/workflows/ci.yml": workflow}))
    (finding,) = [f for f in report.findings if f.rule_id == "RS-GHA-001"]
    assert "Pa55-unrecognised-word" not in finding.evidence
    assert finding.evidence == "${{ ... github.event.issue.title ... }}"
    assert "Pa55-unrecognised-word" not in render_json(report)


# --- AC-01 to AC-05: behaviour of fingerprints across edits ---------------------


def test_unchanged_repository_gives_identical_fingerprints(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": synthetic.credential_file(), ".env": "A=1\n"})
    first, second = scan(root), scan(root)
    assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]
    assert all(is_valid_fingerprint(f.fingerprint) for f in first.findings)


def test_inserted_lines_keep_the_fingerprint(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": f'TOKEN = "{synthetic.GITHUB_TOKEN}"\n'})
    (before,) = scan(root).findings
    (root / "config.py").write_text(f'# a\n# b\nTOKEN = "{synthetic.GITHUB_TOKEN}"\n')
    (after,) = scan(root).findings
    assert (before.line, after.line) == (1, 3)
    assert before.fingerprint == after.fingerprint


def test_occurrences_in_one_file_share_a_fingerprint(make_repo: RepoFactory) -> None:
    other = OTHER_TOKEN
    root = make_repo({"config.py": f'A = "{synthetic.GITHUB_TOKEN}"\nB = "{other}"\n'})
    findings = [f for f in scan(root).findings if f.rule_id == "RS-SEC-004"]
    assert len(findings) == 2
    assert len({f.fingerprint for f in findings}) == 1


def test_same_value_in_two_files_gives_two_tracked_findings(make_repo: RepoFactory) -> None:
    line = f'TOKEN = "{synthetic.GITHUB_TOKEN}"\n'
    findings = scan(make_repo({"a.py": line, "b.py": line})).findings
    assert len({f.fingerprint for f in findings}) == 2


def test_value_changed_in_place_keeps_the_fingerprint(make_repo: RepoFactory) -> None:
    root = make_repo({"config.py": f'TOKEN = "{synthetic.GITHUB_TOKEN}"\n'})
    (before,) = scan(root).findings
    (root / "config.py").write_text(f'TOKEN = "{OTHER_TOKEN}"\n')
    (after,) = scan(root).findings
    assert before.fingerprint == after.fingerprint


def test_private_key_type_is_part_of_identity(make_repo: RepoFactory) -> None:
    rsa = scan(make_repo({"k.pem": synthetic.PEM_RSA_HEADER + "\n"})).findings
    (rsa_finding,) = [f for f in rsa if f.rule_id == "RS-SEC-001"]
    assert rsa_finding.fingerprint == fingerprint("RS-SEC-001", "k.pem", ("key_type=RSA",))


# --- AC-12(a): no secret and no unkeyed SHA-256 of one appears anywhere ---------


def test_no_secret_or_hash_of_a_secret_in_reports(make_repo: RepoFactory) -> None:
    password = synthetic.URL_PASSWORD
    root = make_repo(
        {
            "config.py": synthetic.credential_file(),
            ".github/workflows/ci.yml": textwrap.dedent(
                f"""\
                on: issues
                jobs:
                  greet:
                    runs-on: ubuntu-latest
                    steps:
                      - run: echo "${{{{ github.event.issue.title || '{password}' }}}}"
                """
            ),
        }
    )
    output = render_json(scan(root))
    for value in synthetic.SECRET_VALUES:
        assert value not in output
        assert hashlib.sha256(value.encode()).hexdigest() not in output
