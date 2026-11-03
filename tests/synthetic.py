"""Fake credentials for tests.

Every value is synthetic and assembled at run time from harmless pieces, so
this file contains nothing that a secret scanner (including RepoSentinel's own
self-scan test) would flag. None of these values has ever been a real
credential.
"""

from __future__ import annotations

import string

GITHUB_TOKEN = "ghp_" + string.digits + string.ascii_lowercase  # ghp_ + 36 characters
# Gitleaks 8.30 does not report GITHUB_TOKEN above (a run of letters), but reports this.
GITLEAKS_GITHUB_TOKEN = "ghp_" + "0123456789" * 3 + "abcdef"
GITHUB_FINE_GRAINED_TOKEN = "github_pat_" + "A1" * 11 + "_" + "b2" * 29 + "c"  # 82 after prefix
AWS_KEY_ID = "AKIA" + "TESTONLY" + "0" * 8
AWS_TEMP_KEY_ID = "ASIA" + "TESTONLY" + "1" * 8
AWS_SECRET = ("testOnlySecret" * 3)[:40]
URL_PASSWORD = "s3cr3t-" + "test-value"
# The example values printed in AWS documentation (they contain "EXAMPLE").
AWS_DOCS_EXAMPLE_KEY_ID = "AKIAIOSFODNN7" + "EXAMPLE"
AWS_DOCS_EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
PEM_RSA_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_ENCRYPTED_HEADER = "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----"
PEM_OPENSSH_HEADER = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"

# Values that must never appear in any report, log or error message.
SECRET_VALUES = (
    GITHUB_TOKEN,
    GITLEAKS_GITHUB_TOKEN,
    GITHUB_FINE_GRAINED_TOKEN,
    AWS_KEY_ID,
    AWS_TEMP_KEY_ID,
    AWS_SECRET,
    URL_PASSWORD,
)


def credential_file() -> str:
    """A small config file containing one of every credential pattern."""
    return "\n".join(
        [
            "# synthetic test configuration",
            f'GITHUB_TOKEN = "{GITHUB_TOKEN}"',
            f'AWS_ACCESS_KEY_ID = "{AWS_KEY_ID}"',
            f'aws_secret_access_key = "{AWS_SECRET}"',
            f"DATABASE_URL = postgres://admin:{URL_PASSWORD}@db.internal.test:5432/app",
            PEM_RSA_HEADER,
            "",
        ]
    )
