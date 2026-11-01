"""Validate RepoSentinel's SARIF output against the official SARIF 2.1.0 schema.

The SARIF files are produced by the real command line
(`reposentinel scan PATH --format sarif`) for synthetic repositories built
here: an empty folder, a clean project, the demo repository (every rule),
repeated credentials, unusual file names, and an incomplete scan. Every
credential-shaped value is assembled at run time from harmless pieces.

Two separate checks are reported:

1. **Schema validity**: each file against the OASIS SARIF 2.1.0 JSON Schema
   (errata 01), using the third-party `jsonschema` package. The schema file is
   not bundled; pass its path with --schema. Its SHA-256 must match
   SCHEMA_SHA256 (the file published by OASIS, fetched on 2026-10-31).
2. **GitHub code scanning subset**: the properties GitHub's "SARIF support for
   code scanning" page lists as required or limited. This is a reading of
   the documentation, not an upload: nothing is sent anywhere.

Plus privacy checks: no synthetic secret, no absolute scanned path and no
source snippet appears in any file.

Usage (the validator is a development tool, not a RepoSentinel dependency):

    python -m pip install "jsonschema==4.25.1"
    python scripts/validate_sarif.py --schema sarif-schema-2.1.0.json [--keep DIR]

Exit code 0 when every schema and privacy check passes; 1 otherwise.
GitHub-subset notes are printed and are failures only when marked FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import shutil
import string
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"
SCHEMA_URL = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
PROJECT = Path(__file__).resolve().parents[1]

TOKEN = "ghp_" + string.digits + string.ascii_lowercase
AWS_KEY_ID = "AKIA" + "TESTONLY" + "0" * 8
SECRETS = (TOKEN, AWS_KEY_ID)


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def fixtures(work: Path) -> dict[str, Path]:
    """Synthetic repositories, each exercising a different part of the output."""
    demo = work / "demo"
    subprocess.run(  # noqa: S603 - fixed arguments, this interpreter
        [sys.executable, str(PROJECT / "scripts" / "create_demo_repo.py"), str(demo)],
        check=True,
        capture_output=True,
    )
    empty = work / "empty"
    empty.mkdir()
    return {
        "empty folder": empty,
        "clean project": write(work / "clean", {"app.py": "x = 1\n", "README.md": "# app\n"}),
        "demo (every rule)": demo,
        "repeated credentials": write(
            work / "repeated",
            {
                "a.py": f'T1 = "{TOKEN}"\nT2 = "{TOKEN}"\n',
                "b/c.py": f'KEY = "{AWS_KEY_ID}"\nT = "{TOKEN}"\n',
            },
        ),
        "unusual file names": write(
            work / "names",
            {
                "dir with space/n" + chr(0xFC) + "m #1%.py": f'T = "{TOKEN}"\n',
                "deploy/.git-credentials": "https://user:" + "pw@example.invalid\n",
            },
        ),
        "incomplete scan": write(
            work / "incomplete",
            {".github/workflows/broken.yml": "on: push\njobs: *undefined_alias\n", "x.py": "x=1\n"},
        ),
    }


def scan_to_sarif(root: Path, out: Path) -> tuple[int, str]:
    result = subprocess.run(  # noqa: S603 - fixed arguments, this interpreter
        [sys.executable, "-m", "reposentinel", "scan", str(root), "-f", "sarif", "-o", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, out.read_text(encoding="utf-8")


def github_subset(log: dict[str, Any]) -> list[tuple[str, str]]:
    """(level, message) notes for GitHub's documented SARIF requirements and limits."""
    notes: list[tuple[str, str]] = []
    if log.get("version") != "2.1.0" or "$schema" not in log:
        notes.append(("FAIL", "version 2.1.0 and $schema are required"))
    runs = log.get("runs", [])
    if not 1 <= len(runs) <= 20:
        notes.append(("FAIL", f"{len(runs)} runs (GitHub accepts 1 to 20 per file)"))
    for run in runs:
        driver = run["tool"]["driver"]
        if not driver.get("name"):
            notes.append(("FAIL", "tool.driver.name is required"))
        rules = driver.get("rules", [])
        if len(rules) > 25_000 or len(run.get("results", [])) > 25_000:
            notes.append(("FAIL", "more than 25,000 rules or results in a run"))
        for rule in rules:
            for key in ("shortDescription", "fullDescription", "help"):
                if not rule.get(key, {}).get("text"):
                    notes.append(("FAIL", f"rule {rule['id']}: {key}.text is required"))
            if len(rule.get("name", "")) > 255:
                notes.append(("FAIL", f"rule {rule['id']}: name longer than 255 characters"))
            props = rule.get("properties", {})
            if len(props.get("tags", [])) > 20:
                notes.append(("FAIL", f"rule {rule['id']}: more than 20 tags"))
            if props.get("precision") not in (None, "very-high", "high", "medium", "low"):
                notes.append(("FAIL", f"rule {rule['id']}: precision value not recognised"))
            score = props.get("security-severity")
            if score is not None and not (isinstance(score, str) and 0.0 <= float(score) <= 10.0):
                notes.append(
                    ("FAIL", f"rule {rule['id']}: security-severity must be a 0-10 string")
                )
        no_line = 0
        for result in run.get("results", []):
            if not result.get("message", {}).get("text"):
                notes.append(("FAIL", "result without message.text"))
            locations = result.get("locations", [])
            if not 1 <= len(locations) <= 10:
                notes.append(("FAIL", f"result {result['ruleId']}: {len(locations)} locations"))
            for location in locations:
                artifact = location["physicalLocation"]["artifactLocation"]
                uri = artifact.get("uri", "")
                if not uri or uri.startswith("/") or ":" in uri.split("/")[0]:
                    notes.append(("FAIL", f"location URI is not a relative path: {uri!r}"))
                if "region" not in location["physicalLocation"]:
                    no_line += 1
            if "primaryLocationLineHash" in result.get("partialFingerprints", {}):
                notes.append(("FAIL", "unexpected primaryLocationLineHash"))
        if no_line:
            notes.append(
                (
                    "NOTE",
                    f"{no_line} file-level result(s) have no region.startLine (GitHub's table "
                    "lists it as required; RepoSentinel does not invent a line)",
                )
            )
        if run.get("results"):
            notes.append(
                (
                    "NOTE",
                    "no primaryLocationLineHash: GitHub's upload-sarif action computes it; "
                    "the REST API upload does not, so duplicate alerts are possible there",
                )
            )
    return notes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--schema", type=Path, required=True, help=f"the schema file ({SCHEMA_URL})"
    )
    parser.add_argument("--keep", type=Path, help="copy the generated SARIF files to this folder")
    args = parser.parse_args(argv)

    try:
        # A development tool, not a RepoSentinel dependency: imported only here.
        jsonschema: Any = importlib.import_module("jsonschema")
    except ImportError:
        print('error: install the validator first: python -m pip install "jsonschema==4.25.1"')
        return 2
    raw = args.schema.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != SCHEMA_SHA256:
        print(f"error: {args.schema} has SHA-256 {digest}, expected {SCHEMA_SHA256}")
        return 2
    schema = json.loads(raw)
    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema, format_checker=validator_class.FORMAT_CHECKER)
    version = importlib.metadata.version("jsonschema")
    print(f"schema: {schema.get('id')} ({validator_class.__name__}, jsonschema {version})")
    # The validator must reject an invalid log, or a pass would mean nothing.
    broken = {
        "version": "2.0.0",
        "runs": [{"tool": {"driver": {}}, "results": [{"level": "fatal"}]}],
    }
    if len(list(validator.iter_errors(broken))) < 3:
        print("error: the validator accepted a deliberately invalid SARIF log")
        return 2
    print("self-test: a deliberately invalid log is rejected")

    failures = 0
    with tempfile.TemporaryDirectory(prefix="reposentinel-sarif-") as tmp:
        work = Path(tmp)
        for label, root in fixtures(work).items():
            out = work / f"{root.name}.sarif"
            code, text = scan_to_sarif(root, out)
            log = json.loads(text)
            errors = sorted(validator.iter_errors(log), key=lambda e: list(e.absolute_path))
            privacy = [s for s in SECRETS if s in text]
            privacy += [
                p for p in (str(root), root.as_posix(), json.dumps(str(root))[1:-1]) if p in text
            ]
            privacy += [k for k in ('"snippet"', '"contextRegion"') if k in text]
            if not text.isascii():
                privacy.append("non-ASCII output")
            run = log["runs"][0]
            ok = not errors and not privacy
            failures += not ok
            print(
                f"{'PASS' if ok else 'FAIL'}  {label}: exit {code}, {len(run['results'])} results, "
                f"{len(run['tool']['driver']['rules'])} rules, "
                f"executionSuccessful={run['invocations'][0]['executionSuccessful']}, "
                f"schema errors {len(errors)}, privacy problems {len(privacy)}"
            )
            for error in errors[:5]:
                path = "/".join(str(p) for p in error.absolute_path)
                print(f"      schema: at {path or '(root)'}: {error.message[:200]}")
            for problem in privacy:
                print(
                    "      privacy: output contains a forbidden value"
                    if problem in SECRETS
                    else f"      privacy: {problem[:80]}"
                )
            for level, note in github_subset(log):
                failures += level == "FAIL"
                print(f"      github {level}: {note}")
            if args.keep:
                args.keep.mkdir(parents=True, exist_ok=True)
                shutil.copy2(out, args.keep / out.name)
    print(
        "SARIF validation passed" if failures == 0 else f"SARIF validation: {failures} failure(s)"
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
