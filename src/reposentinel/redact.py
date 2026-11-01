"""Helpers that keep secrets and hostile text out of reports.

Two different problems are handled here:

* **Secrets** must never be copied into a report. ``mask`` replaces a
  matched value with a fixed marker, optionally keeping a short prefix that
  only identifies the *type* of credential (for example ``ghp_``).
* **Untrusted text** (file names, workflow snippets, error messages) can
  contain control characters. Printed raw, an ESC character can start a
  terminal escape sequence that rewrites what the user sees, and Unicode
  bidirectional overrides can make a file name *look* different from what it
  is ("Trojan Source"). ``sanitize_text`` makes both visible instead.
"""

from __future__ import annotations

REDACTED = "[REDACTED]"


def mask(value: str, *, keep_prefix: int = 0) -> str:
    """Return a redacted stand-in for ``value``.

    ``keep_prefix`` characters are kept only when they identify the kind of
    credential rather than any part of the secret itself (``AKIA``, ``ghp_``).
    The length of the secret is deliberately not revealed.
    """
    if keep_prefix <= 0 or keep_prefix >= len(value):
        return REDACTED
    return value[:keep_prefix] + REDACTED


def _escape_char(char: str) -> str:
    code = ord(char)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def sanitize_text(text: str, *, max_length: int = 500) -> str:
    """Make untrusted text safe to display on one line.

    Every character Python does not consider printable is replaced by a
    visible escape code: control characters (ESC becomes the four characters
    ``\\x1b``), tab and newline, bidirectional overrides, zero-width and other
    invisible format characters, line and paragraph separators, non-breaking
    and other unusual spaces, lone surrogates, and private-use or unassigned
    code points. The ordinary space and all visible letters, digits, symbols
    and emoji in any script are kept. Very long text is truncated.
    """
    if text.isprintable():  # fast path for ordinary text
        cleaned = text
    else:
        cleaned = "".join(char if char.isprintable() else _escape_char(char) for char in text)
    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 3] + "..."
    return cleaned
