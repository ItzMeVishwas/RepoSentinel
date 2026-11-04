# ruff: noqa: S101 - plain asserts, as in tests/ (see pyproject.toml)
"""Tests for .github/workflows/publish.yml (the trusted-publishing workflow).

They are in .github/workflow-tests on purpose. The source archive includes
every file or folder named like an entry of the sdist `include` list in
pyproject.toml (such as "tests"), at any depth, so a new file in tests/ or in
.github/tests/ would change the release archives and their SHA-256. CI runs
them with `python -m pytest .github/workflow-tests`.

The scripts of the workflow steps are read from the YAML file and run with
bash the way GitHub Actions runs them (bash --noprofile --norc -eo pipefail),
so the tests check the exact code that runs during a release.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "publish.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8")
DATA: dict[Any, Any] = yaml.safe_load(TEXT)
JOBS: dict[str, Any] = DATA["jobs"]

INPUTS_STEP = "Check and normalise the version and the SHA-256 values"
BUILD_STEP = "Check that dist/ holds exactly the two expected archives"
PUBLISH_STEP = "Copy exactly the two verified archives into a new folder and check them again"

WHEEL = "reposentinel_scanner-0.1.0-py3-none-any.whl"
SDIST = "reposentinel_scanner-0.1.0.tar.gz"
LOWER = "0123456789abcdef" * 4
UPPER = LOWER.upper()


def find_bash() -> str | None:
    """Git's bash on Windows (as on GitHub's Windows runners), else bash on PATH."""
    if os.name != "nt":
        return shutil.which("bash")
    git = shutil.which("git")
    for folder in Path(git).parents if git else ():
        if (folder / "bin" / "bash.exe").is_file() and (folder / "usr" / "bin").is_dir():
            return str(folder / "bin" / "bash.exe")
    return None


BASH = find_bash()
# Locally the script tests are skipped without bash; in CI they must run.
if BASH is None and os.environ.get("GITHUB_ACTIONS") == "true":
    raise RuntimeError("bash is needed to test the publish workflow")
needs_bash = pytest.mark.skipif(BASH is None, reason="bash is not available")


def step(job: str, name: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = [s for s in JOBS[job]["steps"] if s.get("name") == name]
    assert len(matches) == 1, f"{job}: expected one step named {name!r}"
    return matches[0]


def run_step(
    job: str, name: str, env: dict[str, str], cwd: Path, runner: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a step's script with values for exactly its env keys (and runner variables)."""
    definition = step(job, name)
    assert set(env) == set(definition["env"]), "give a value for every env key of the step"
    script = cwd.parent / f"{cwd.name}-step.sh"
    script.write_text(definition["run"], encoding="utf-8", newline="\n")
    environment = {**os.environ, **(runner or {}), **env}
    assert BASH is not None
    return subprocess.run(  # noqa: S603 - fixed arguments, no shell
        [BASH, "--noprofile", "--norc", "-eo", "pipefail", script.as_posix()],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------- structure ---


def test_only_a_manual_trigger_with_the_expected_inputs() -> None:
    triggers = DATA[True]  # PyYAML reads the key `on` as True
    assert list(triggers) == ["workflow_dispatch"]
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert inputs["index"]["options"] == ["testpypi", "pypi"]
    assert inputs["index"]["default"] == "testpypi"
    for name in ("version", "wheel-sha256", "sdist-sha256"):
        assert inputs[name]["required"] is True
        assert "default" not in inputs[name]
    for forbidden in ("pull_request_target", "issue_comment", "workflow_call", "workflow_run"):
        assert forbidden not in TEXT


def test_least_privilege_permissions() -> None:
    assert DATA["permissions"] == {"contents": "read"}
    assert JOBS["inputs"]["permissions"] == {}
    assert "permissions" not in JOBS["build"]  # inherits contents: read
    assert JOBS["publish"]["permissions"] == {"id-token": "write"}
    assert TEXT.count("id-token: write") == 2  # the publish job and one comment


def test_job_order_and_the_branch_or_tag_condition() -> None:
    assert JOBS["inputs"]["if"] == (
        "github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')"
    )
    assert JOBS["build"]["needs"] == "inputs"
    assert JOBS["publish"]["needs"] == ["inputs", "build"]
    # Jobs that need a skipped or failed job are skipped: nothing may override it.
    for job in JOBS.values():
        assert "always()" not in str(job.get("if", ""))
        assert "continue-on-error" not in job
        for item in job["steps"]:
            assert "continue-on-error" not in item


def test_every_action_is_pinned_to_a_full_commit_sha() -> None:
    uses = re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)(.*)$", TEXT, re.MULTILINE)
    assert len(uses) == 7
    for target, comment in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", target), target
        assert re.fullmatch(r"\s*# v\d+\.\d+\.\d+", comment), target


def test_inputs_never_appear_inside_a_script() -> None:
    for job in JOBS.values():
        for item in job["steps"]:
            assert "${{" not in item.get("run", "")


def test_the_reference_build_environment_is_pinned() -> None:
    build = JOBS["build"]
    assert build["runs-on"] == "windows-2025"
    assert step("build", "Set up Python")["with"]["python-version"] == "3.13.17"
    assert step("build", "Set up Node.js")["with"]["node-version"] == "24.21.0"
    assert step("build", "Check out the repository")["with"]["persist-credentials"] is False
    check = step("build", "Check the reference build environment")["run"]
    assert "(3, 13, 17)" in check
    assert '"1.3.1"' in check
    assert '"v24.21.0"' in check
    install = step("build", "Install the release tools")["run"]
    assert '"build==1.3.0"' in install


def test_publish_job_uploads_only_the_verified_folder() -> None:
    publish = JOBS["publish"]
    assert publish["runs-on"] == "ubuntu-24.04"
    assert publish["environment"]["name"] == "${{ inputs.index }}"
    names = [s["name"] for s in publish["steps"]]
    assert names == [
        "Download the archives from the build job",
        PUBLISH_STEP,
        "Upload to TestPyPI",
        "Upload to PyPI",
    ]
    download = step("publish", "Download the archives from the build job")
    assert download["with"]["path"] == "${{ runner.temp }}/downloaded"
    testpypi = step("publish", "Upload to TestPyPI")
    pypi = step("publish", "Upload to PyPI")
    assert testpypi["if"] == "inputs.index == 'testpypi'"
    assert pypi["if"] == "inputs.index == 'pypi'"
    assert testpypi["with"] == {
        "repository-url": "https://test.pypi.org/legacy/",
        "packages-dir": "verified-dist/",
    }
    assert pypi["with"] == {"packages-dir": "verified-dist/"}  # PyPI is the default index
    # Check the download, copy only the two files into a new folder, make them
    # read-only, and check the copies (which are uploaded) last.
    commands = [
        line.strip()
        for line in step("publish", PUBLISH_STEP)["run"]
        .split("# End of the checks shared")[1]
        .splitlines()[1:]
        if line.strip() and not line.strip().startswith("#")
    ]
    assert commands == [
        "check_expected_values",
        'check_folder "$RUNNER_TEMP/downloaded"',
        "mkdir -- verified-dist",
        'cp -- "$RUNNER_TEMP/downloaded/$WHEEL_NAME" "$RUNNER_TEMP/downloaded/$SDIST_NAME"'
        " verified-dist/",
        'chmod a-w -- "verified-dist/$WHEEL_NAME" "verified-dist/$SDIST_NAME"',
        "check_folder verified-dist",
    ]
    build_commands = step("build", BUILD_STEP)["run"].split("# End of the checks shared")[1]
    assert build_commands.split()[-2:] == ["check_folder", "dist"]


def test_build_and_publish_jobs_share_the_same_checks() -> None:
    def shared(script: str) -> str:
        return script.split("# End of the checks shared with the")[0]

    build = step("build", BUILD_STEP)
    publish = step("publish", PUBLISH_STEP)
    assert shared(build["run"]) == shared(publish["run"])
    assert build["env"] == publish["env"]


def test_nothing_under_dot_github_goes_into_the_source_archive() -> None:
    # hatchling reads each sdist `include` entry like a .gitignore line: an
    # entry without a slash matches a file or folder of that name at any depth.
    root = WORKFLOW.parents[2]
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    include = set(config["tool"]["hatch"]["build"]["targets"]["sdist"]["include"])
    assert all("/" not in entry and "*" not in entry for entry in include)
    for path in (root / ".github").rglob("*"):
        assert not include & set(path.relative_to(root).parts), path


# ------------------------------------------------------- inputs (D3) ---


def run_inputs(
    tmp_path: Path, version: str, wheel: str, sdist: str
) -> tuple[int, str, dict[str, str]]:
    work = tmp_path / "work"
    work.mkdir()
    output = tmp_path / "github_output"
    output.write_text("", encoding="utf-8")
    env = {"RAW_VERSION": version, "RAW_WHEEL": wheel, "RAW_SDIST": sdist}
    result = run_step("inputs", INPUTS_STEP, env, work, {"GITHUB_OUTPUT": output.as_posix()})
    values = dict(
        line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines() if line
    )
    return result.returncode, result.stdout + result.stderr, values


@needs_bash
@pytest.mark.parametrize(
    ("wheel", "sdist"),
    [
        (LOWER, LOWER[::-1]),  # lower case
        (UPPER, LOWER[::-1].upper()),  # upper case, as PowerShell's Get-FileHash prints it
        (LOWER[:32] + UPPER[32:], LOWER[::-1]),  # mixed case
        (f"  {UPPER}  ", f"\t{LOWER[::-1]}\r\n"),  # surrounding white space
    ],
)
def test_valid_hashes_are_normalised_to_lower_case(tmp_path: Path, wheel: str, sdist: str) -> None:
    code, log, values = run_inputs(tmp_path, " 0.1.0 ", wheel, sdist)
    assert code == 0, log
    assert values == {
        "wheel-name": WHEEL,
        "sdist-name": SDIST,
        "wheel-sha256": LOWER,
        "sdist-sha256": LOWER[::-1],
    }


@needs_bash
@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        LOWER[:63],  # too short
        LOWER + "0",  # too long
        LOWER[:63] + "g",  # not hexadecimal
        LOWER[:32] + " " + LOWER[32:63],  # space inside
        LOWER[:32] + "\n" + LOWER[32:63],  # line break inside
        "sha256:" + LOWER,  # prefix
        LOWER[:63] + chr(0xFF21),  # full-width A
        LOWER[:63] + chr(0xE9),  # accented letter
        "::warning::injected" + LOWER[:45],  # a workflow command
    ],
)
def test_malformed_hashes_are_rejected_without_printing_them(tmp_path: Path, bad: str) -> None:
    for wheel, sdist in ((bad, LOWER), (LOWER, bad)):
        case = tmp_path / ("wheel" if wheel is bad else "sdist")
        case.mkdir()
        code, log, values = run_inputs(case, "0.1.0", wheel, sdist)
        assert code != 0
        assert "must be a SHA-256: 64 hexadecimal characters" in log
        assert values == {}  # nothing reaches the later jobs
        if bad.strip():
            assert bad.strip() not in log
        assert "injected" not in log


@needs_bash
@pytest.mark.parametrize("version", ["0.1.0", "1.2.3rc1", "2.0.0.post1", "1.0.dev3", "10"])
def test_valid_versions(tmp_path: Path, version: str) -> None:
    code, log, values = run_inputs(tmp_path, version, LOWER, LOWER)
    assert code == 0, log
    assert values["wheel-name"] == f"reposentinel_scanner-{version}-py3-none-any.whl"
    assert values["sdist-name"] == f"reposentinel_scanner-{version}.tar.gz"


@needs_bash
@pytest.mark.parametrize(
    "version",
    ["", "v0.1.0", "0.1.0-1", "0.1.0/../x", "../0.1.0", "0.1.0 0.2.0", "0.1.0*", "0.1.0\n1"],
)
def test_invalid_versions_are_rejected(tmp_path: Path, version: str) -> None:
    code, log, values = run_inputs(tmp_path, version, LOWER, LOWER)
    assert code != 0
    assert "The version must be a normalised version" in log
    assert values == {}


# ------------------------------------------ build and publish checks (D1) ---

ARCHIVES = {WHEEL: b"wheel bytes\n", SDIST: b"sdist bytes\n"}


def folder_env(**overrides: str) -> dict[str, str]:
    env = {
        "WHEEL_NAME": WHEEL,
        "SDIST_NAME": SDIST,
        "EXPECTED_WHEEL": sha256(ARCHIVES[WHEEL]),
        "EXPECTED_SDIST": sha256(ARCHIVES[SDIST]),
    }
    env.update(overrides)
    return env


def make_archives(folder: Path, extra: dict[str, bytes] | None = None) -> None:
    folder.mkdir(parents=True)
    for name, data in {**ARCHIVES, **(extra or {})}.items():
        (folder / name).write_bytes(data)


def run_build_check(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return run_step("build", BUILD_STEP, env, tmp_path / "workspace")


def run_publish_check(tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    runner = {"RUNNER_TEMP": (tmp_path / "runner_temp").as_posix()}
    return run_step("publish", PUBLISH_STEP, env, tmp_path / "workspace", runner)


def source_folder(tmp_path: Path, job: str) -> Path:
    """Where each job's check reads the archives from (the folder is not created)."""
    (tmp_path / "workspace").mkdir(exist_ok=True)
    if job == "build":
        return tmp_path / "workspace" / "dist"
    return tmp_path / "runner_temp" / "downloaded"


def run_check(job: str, tmp_path: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return (run_build_check if job == "build" else run_publish_check)(tmp_path, env)


BOTH = pytest.mark.parametrize("job", ["build", "publish"])


@needs_bash
@BOTH
def test_exactly_the_two_expected_archives_pass(tmp_path: Path, job: str) -> None:
    make_archives(source_folder(tmp_path, job))
    result = run_check(job, tmp_path, folder_env())
    assert result.returncode == 0, result.stdout + result.stderr
    assert sha256(ARCHIVES[WHEEL]) in result.stdout


@needs_bash
def test_publish_stages_only_the_two_archives_read_only(tmp_path: Path) -> None:
    make_archives(source_folder(tmp_path, "publish"))
    result = run_publish_check(tmp_path, folder_env())
    assert result.returncode == 0, result.stdout + result.stderr
    staged = tmp_path / "workspace" / "verified-dist"
    assert sorted(p.name for p in staged.iterdir()) == sorted(ARCHIVES)
    for name, data in ARCHIVES.items():
        assert (staged / name).read_bytes() == data
        assert not (staged / name).stat().st_mode & stat.S_IWUSR


@needs_bash
def test_publish_refuses_an_existing_staging_folder(tmp_path: Path) -> None:
    make_archives(source_folder(tmp_path, "publish"))
    (tmp_path / "workspace" / "verified-dist").mkdir()
    result = run_publish_check(tmp_path, folder_env())
    assert result.returncode != 0


@needs_bash
@BOTH
@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"EXPECTED_WHEEL": "0" * 64}, "The wheel's SHA-256 is not the expected value."),
        ({"EXPECTED_SDIST": "0" * 64}, "The source archive's SHA-256 is not the expected value."),
        # These jobs receive normalised values only; anything else is refused.
        ({"EXPECTED_WHEEL": sha256(ARCHIVES[WHEEL]).upper()}, "not 64 lower-case hexadecimal"),
        ({"EXPECTED_SDIST": ""}, "not 64 lower-case hexadecimal"),
        ({"WHEEL_NAME": "../" + WHEEL}, "The expected file names are not valid."),
        ({"SDIST_NAME": ""}, "The expected file names are not valid."),
    ],
)
def test_wrong_hashes_or_names_block_the_upload(
    tmp_path: Path, job: str, overrides: dict[str, str], message: str
) -> None:
    make_archives(source_folder(tmp_path, job))
    result = run_check(job, tmp_path, folder_env(**overrides))
    assert result.returncode != 0
    assert message in result.stdout
    assert "Nothing will be uploaded." in result.stdout
    assert not (tmp_path / "workspace" / "verified-dist").exists()


@needs_bash
@BOTH
@pytest.mark.parametrize(
    "extra",
    [
        {"Reposentinel_Scanner-9.9.9-py3-none-any.whl": b"other\n"},  # PyPI normalises names
        {"reposentinel_scanner-0.1.0-cp313-win_amd64.whl": b"other\n"},
        {".hidden": b"other\n"},
        {"notes.txt": b"other\n"},
    ],
)
def test_any_additional_file_blocks_the_upload(
    tmp_path: Path, job: str, extra: dict[str, bytes]
) -> None:
    make_archives(source_folder(tmp_path, job), extra)
    result = run_check(job, tmp_path, folder_env())
    assert result.returncode != 0
    assert "must hold exactly the two archives; it holds 3 entries." in result.stdout
    assert not (tmp_path / "workspace" / "verified-dist").exists()


@needs_bash
@BOTH
def test_an_additional_folder_blocks_the_upload(tmp_path: Path, job: str) -> None:
    folder = source_folder(tmp_path, job)
    make_archives(folder)
    (folder / "sub").mkdir()
    result = run_check(job, tmp_path, folder_env())
    assert result.returncode != 0
    assert "it holds 3 entries" in result.stdout


@needs_bash
@BOTH
@pytest.mark.parametrize("missing", [WHEEL, SDIST])
def test_a_missing_or_renamed_archive_blocks_the_upload(
    tmp_path: Path, job: str, missing: str
) -> None:
    folder = source_folder(tmp_path, job)
    make_archives(folder)
    (folder / missing).unlink()
    result = run_check(job, tmp_path, folder_env())
    assert result.returncode != 0
    assert "it holds 1 entries" in result.stdout
    # The same file under another spelling of its name is not accepted either.
    (folder / missing.upper()).write_bytes(ARCHIVES[missing])
    result = run_check(job, tmp_path, folder_env())
    assert result.returncode != 0
    assert f"does not hold exactly {WHEEL} and {SDIST}." in result.stdout


@needs_bash
@BOTH
def test_an_empty_or_missing_folder_blocks_the_upload(tmp_path: Path, job: str) -> None:
    source_folder(tmp_path, job)  # the folder itself is never created
    result = run_check(job, tmp_path, folder_env())
    assert result.returncode != 0
    assert "it holds 0 entries" in result.stdout


@needs_bash
@BOTH
def test_a_symbolic_link_instead_of_an_archive_blocks_the_upload(tmp_path: Path, job: str) -> None:
    folder = source_folder(tmp_path, job)
    make_archives(folder)
    target = tmp_path / "elsewhere.whl"
    target.write_bytes(ARCHIVES[WHEEL])
    (folder / WHEEL).unlink()
    try:
        (folder / WHEEL).symlink_to(target)
    except OSError:
        pytest.skip("cannot create symbolic links here")
    if not (folder / WHEEL).is_symlink():
        pytest.skip("the link is not seen as a symbolic link here")
    result = run_check(job, tmp_path, folder_env())
    assert result.returncode != 0
    assert f"{WHEEL} is missing from" in result.stdout
