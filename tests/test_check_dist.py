"""scripts/check_dist.py against valid and deliberately broken archives."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from tests.test_project import load_script

check_dist = load_script("check_dist")

INDEX = (
    '<!doctype html><script type="module" src="./assets/app.js"></script>'
    '<link rel="stylesheet" href="./assets/app.css">'
)
METADATA = (
    "Metadata-Version: 2.4\nName: reposentinel\nVersion: 0.1.0\n"
    "Requires-Python: >=3.12\nLicense-Expression: MIT\n"
)


def wheel_files() -> dict[str, str]:
    files = {name: "" for name in check_dist.REQUIRED_IN_WHEEL}
    files["reposentinel-0.1.0.dist-info/METADATA"] = METADATA
    files["reposentinel-0.1.0.dist-info/entry_points.txt"] = "[console_scripts]\n"
    files["reposentinel-0.1.0.dist-info/licenses/LICENSE"] = "MIT License\n"
    files["reposentinel/webui/static/index.html"] = INDEX
    files["reposentinel/webui/static/assets/app.js"] = "1"
    files["reposentinel/webui/static/assets/app.css"] = "a{}"
    return files


def sdist_files() -> dict[str, str]:
    files = {name: "" for name in check_dist.REQUIRED_IN_SDIST}
    files["src/reposentinel/webui/static/index.html"] = INDEX
    files["src/reposentinel/webui/static/assets/app.js"] = "1"
    files["src/reposentinel/webui/static/assets/app.css"] = "a{}"
    return files


def make_wheel(path: Path, files: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return path


def make_sdist(path: Path, files: dict[str, str]) -> Path:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"reposentinel-0.1.0/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def test_valid_archives_pass(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    make_wheel(tmp_path / "reposentinel-0.1.0-py3-none-any.whl", wheel_files())
    make_sdist(tmp_path / "reposentinel-0.1.0.tar.gz", sdist_files())
    assert check_dist.main([str(tmp_path)]) == 0
    assert "OK" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda f: f.pop("reposentinel/webui/static/index.html"), "missing reposentinel/webui"),
        (lambda f: f.pop("reposentinel/webui/static/assets/app.js"), "refers to missing file"),
        (lambda f: f.pop("reposentinel/cli.py"), "wheel is missing reposentinel/cli.py"),
        (
            lambda f: f.update({"reposentinel/webui/static/index.html": "<p>no script</p>"}),
            "loads no script",
        ),
        (
            lambda f: f.update(
                {"reposentinel/webui/static/index.html": '<script src="/assets/app.js"></script>'}
            ),
            "must be ./assets/",
        ),
        (
            lambda f: f.update(
                {
                    "reposentinel/webui/static/index.html": INDEX.replace(
                        "./assets/app.css", "https://cdn.example/x.css"
                    )
                }
            ),
            "must be ./assets/",
        ),
        (lambda f: f.update({"reposentinel/node_modules/x/index.js": ""}), "contains"),
        (lambda f: f.update({"reposentinel/.claude-flow/state.json": ""}), "contains"),
        (lambda f: f.update({"reposentinel/.env": "A=1"}), "contains"),
        (lambda f: f.update({"reposentinel/__pycache__/x.pyc": ""}), "contains"),
        (lambda f: f.update({"reposentinel/a.tsbuildinfo": ""}), "contains"),
        (lambda f: f.pop("reposentinel-0.1.0.dist-info/entry_points.txt"), "entry_points"),
        (lambda f: f.pop("reposentinel-0.1.0.dist-info/licenses/LICENSE"), "LICENSE file"),
        (
            lambda f: f.update(
                {
                    "reposentinel-0.1.0.dist-info/METADATA": METADATA.replace(
                        "License-Expression: MIT", "License-Expression: GPL-3.0-only"
                    )
                }
            ),
            "License-Expression",
        ),
    ],
)
def test_broken_wheels_fail(tmp_path: Path, change: object, problem: str) -> None:
    files = wheel_files()
    change(files)  # type: ignore[operator]
    problems = check_dist.check_wheel(make_wheel(tmp_path / "w.whl", files))
    assert any(problem in item for item in problems), problems


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (lambda f: f.pop("src/reposentinel/webui/static/index.html"), "missing src/reposentinel"),
        (lambda f: f.pop("frontend/package-lock.json"), "missing frontend/package-lock.json"),
        (lambda f: f.pop("LICENSE"), "sdist is missing LICENSE"),
        (lambda f: f.update({"frontend/node_modules/vite/index.js": ""}), "contains"),
        (lambda f: f.update({"frontend/.claude-flow/x.json": ""}), "contains"),
        (lambda f: f.update({"tests/reposentinel-report.json": "{}"}), "contains"),
    ],
)
def test_broken_sdists_fail(tmp_path: Path, change: object, problem: str) -> None:
    files = sdist_files()
    change(files)  # type: ignore[operator]
    problems = check_dist.check_sdist(make_sdist(tmp_path / "s.tar.gz", files))
    assert any(problem in item for item in problems), problems


def test_no_ui_option_allows_a_build_without_the_interface(tmp_path: Path) -> None:
    wheel, sdist = wheel_files(), sdist_files()
    for files in (wheel, sdist):
        for name in [n for n in files if "webui/static" in n]:
            files.pop(name)
    make_wheel(tmp_path / "reposentinel-0.1.0-py3-none-any.whl", wheel)
    make_sdist(tmp_path / "reposentinel-0.1.0.tar.gz", sdist)
    assert check_dist.main([str(tmp_path)]) == 1
    assert check_dist.main([str(tmp_path), "--no-ui"]) == 0


def test_requires_exactly_one_of_each(tmp_path: Path) -> None:
    assert check_dist.main([str(tmp_path)]) == 1
