"""Display sanitising and masking helpers."""

from __future__ import annotations

import pytest

from reposentinel.redact import REDACTED, mask, sanitize_text

# Characters are built with chr() so this test file stays plain ASCII.
INVISIBLE_OR_CONTROL = {
    "escape (terminal sequences)": chr(0x1B),
    "newline": chr(0x0A),
    "tab": chr(0x09),
    "C1 control CSI": chr(0x9B),
    "right-to-left override": chr(0x202E),
    "zero-width space": chr(0x200B),
    "zero-width joiner": chr(0x200D),
    "line separator": chr(0x2028),
    "paragraph separator": chr(0x2029),
    "byte-order mark": chr(0xFEFF),
    "soft hyphen": chr(0xAD),
    "no-break space": chr(0xA0),
    "lone surrogate": chr(0xDCFF),
    "private use": chr(0xE000),
    "astral private use": chr(0xF0000),
}


@pytest.mark.parametrize("char", INVISIBLE_OR_CONTROL.values(), ids=INVISIBLE_OR_CONTROL.keys())
def test_invisible_and_control_characters_become_visible(char: str) -> None:
    cleaned = sanitize_text(f"a{char}.env")
    assert char not in cleaned
    assert cleaned.startswith("a\\") and cleaned.endswith(".env")
    assert cleaned.isprintable()


def test_escape_formats() -> None:
    assert sanitize_text(chr(0x1B) + "[2J") == "\\x1b[2J"
    assert sanitize_text(chr(0x202E)) == "\\u202e"
    assert sanitize_text(chr(0xF0000)) == "\\U000f0000"


@pytest.mark.parametrize(
    "text",
    [
        "plain ascii.txt",
        "caf" + chr(0xE9) + ".py",  # Latin letter with accent
        chr(0x65E5) + chr(0x672C) + ".md",  # CJK characters
        "notes " + chr(0x1F512) + ".txt",  # emoji
        "Tom & Jerry's [draft] <v2>.env",  # punctuation is not hidden
    ],
)
def test_visible_text_is_unchanged(text: str) -> None:
    assert sanitize_text(text) == text


def test_long_text_is_truncated() -> None:
    assert sanitize_text("x" * 600, max_length=50) == "x" * 47 + "..."


@pytest.mark.parametrize(
    ("value", "keep", "expected"),
    [
        ("ghp_abcdef", 4, "ghp_" + REDACTED),
        ("secret", 0, REDACTED),
        ("abc", 3, REDACTED),  # never keep the whole value
        ("abc", 10, REDACTED),
    ],
)
def test_mask(value: str, keep: int, expected: str) -> None:
    assert mask(value, keep_prefix=keep) == expected
