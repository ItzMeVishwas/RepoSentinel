"""Risky-file rules RS-HYG-001 to RS-HYG-003."""

from __future__ import annotations

import pytest

from reposentinel.checks.hygiene import is_env_file, is_key_file
from reposentinel.models import Finding, Severity
from tests.conftest import RepoFactory
from tests.helpers import scan


def hygiene_findings(make_repo: RepoFactory, files: dict[str, str | bytes]) -> list[Finding]:
    return [f for f in scan(make_repo(files)).findings if f.check_id == "hygiene"]


@pytest.mark.parametrize(
    "name", [".env", ".env.local", ".env.production", "production.env", ".ENV", "prod.env"]
)
def test_env_file_names(name: str) -> None:
    assert is_env_file(name)


@pytest.mark.parametrize(
    "name",
    [
        ".env.example",
        ".env.sample",
        ".env.template",
        "example.env",
        ".env.dist",
        ".envrc",
        "environment.py",
        "env",
        "dotenv.txt",
    ],
)
def test_not_env_file_names(name: str) -> None:
    assert not is_env_file(name)


def test_env_file_without_gitignore_is_medium(make_repo: RepoFactory) -> None:
    (finding,) = hygiene_findings(make_repo, {".env": "DEBUG=1\n"})
    assert (finding.rule_id, finding.severity, finding.path) == (
        "RS-HYG-001",
        Severity.MEDIUM,
        ".env",
    )
    assert finding.line is None


@pytest.mark.parametrize(
    ("gitignore", "path"),
    [
        (".env\n", ".env"),
        ("/.env\n", ".env"),
        (".env*\n", ".env.local"),
        ("**/.env\n", "services/api/.env"),
        ("services/\n", "services/api/.env"),  # parent directory ignored
        ("*.env\n", "prod.env"),
    ],
)
def test_env_file_ignored_by_root_gitignore_is_info(
    make_repo: RepoFactory, gitignore: str, path: str
) -> None:
    (finding,) = hygiene_findings(make_repo, {".gitignore": gitignore, path: "X=1\n"})
    assert finding.severity is Severity.INFO
    assert "appears to be ignored" in finding.summary


@pytest.mark.parametrize(
    ("gitignore", "path"),
    [
        (".env\n!.env\n", ".env"),  # re-included by a negation
        ("/.env\n", "services/.env"),  # anchored pattern only matches at the root
        ("# .env\n", ".env"),  # a comment, not a pattern
        (".env/\n", ".env"),  # a directory-only pattern does not match a file
    ],
)
def test_env_file_not_ignored(make_repo: RepoFactory, gitignore: str, path: str) -> None:
    (finding,) = hygiene_findings(make_repo, {".gitignore": gitignore, path: "X=1\n"})
    assert finding.severity is Severity.MEDIUM


def test_env_template_is_not_reported(make_repo: RepoFactory) -> None:
    assert hygiene_findings(make_repo, {".env.example": "TOKEN=changeme\n"}) == []


@pytest.mark.parametrize(
    "name", ["id_rsa", "id_ed25519", "ID_ECDSA", "cert.p12", "bundle.pfx", "app.jks", "key.ppk"]
)
def test_key_file_names(name: str) -> None:
    assert is_key_file(name)


@pytest.mark.parametrize(
    "name", ["id_rsa.pub", "id_ed25519.pub", "cert.pem", "slides.key", "rsa.py"]
)
def test_not_key_file_names(name: str) -> None:
    assert not is_key_file(name)


def test_key_file_is_reported(make_repo: RepoFactory) -> None:
    (finding,) = hygiene_findings(make_repo, {"deploy/id_ed25519": "not a real key\n"})
    assert (finding.rule_id, finding.path, finding.severity) == (
        "RS-HYG-002",
        "deploy/id_ed25519",
        Severity.MEDIUM,
    )


@pytest.mark.parametrize("name", [".git-credentials", ".netrc", "_netrc", ".pgpass"])
def test_credential_store_is_high(make_repo: RepoFactory, name: str) -> None:
    (finding,) = hygiene_findings(make_repo, {name: "synthetic content\n"})
    assert (finding.rule_id, finding.severity) == ("RS-HYG-003", Severity.HIGH)


def test_empty_credential_store_is_ignored(make_repo: RepoFactory) -> None:
    assert hygiene_findings(make_repo, {".netrc": ""}) == []


def test_ordinary_repository_has_no_hygiene_findings(make_repo: RepoFactory) -> None:
    files: dict[str, str | bytes] = {
        "README.md": "# app",
        "src/app.py": "",
        ".gitignore": ".env\n",
    }
    assert hygiene_findings(make_repo, files) == []
