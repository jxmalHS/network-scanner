"""Tests for textsafe.py - clean_text() turns untrusted server text into one safe printable line."""
import unicodedata

import pytest

from textsafe import clean_text


def test_clean_text_none_returns_none() -> None:
    """None means 'no banner' and must stay None, not become ''."""
    assert clean_text(None) is None


def test_clean_text_plain_ascii_unchanged() -> None:
    """Ordinary single-line text passes through untouched."""
    assert clean_text("SSH-2.0-OpenSSH_9.6") == "SSH-2.0-OpenSSH_9.6"


def test_clean_text_non_english_text_unchanged() -> None:
    """Printable non-ASCII (Chinese, symbols) is kept - only control/format chars are removed."""
    assert clean_text("SSH-2.0 中文 ✓") == "SSH-2.0 中文 ✓"


@pytest.mark.parametrize("newline", ["\r\n", "\n", "\r"])
def test_clean_text_line_breaks_become_separator(newline: str) -> None:
    """Windows, Unix and old-Mac line endings all become ' | '."""
    assert clean_text(f"A{newline}B") == "A | B"


def test_clean_text_blank_lines_give_no_empty_segments() -> None:
    """Blank lines in the middle are skipped, so there is no 'A |  | B'."""
    assert clean_text("A\n\n   \nB") == "A | B"


def test_clean_text_trailing_crlf_pairs_dropped() -> None:
    """An HTTP-style ending '\\r\\n\\r\\n' leaves no trailing separator."""
    assert clean_text("HTTP/1.0 200 OK\r\n\r\n") == "HTTP/1.0 200 OK"


@pytest.mark.parametrize("brk", ["\x85", "\u2028", "\u2029"])
def test_clean_text_unicode_line_breaks_act_as_breaks(brk: str) -> None:
    """NEL (U+0085), LINE SEPARATOR and PARAGRAPH SEPARATOR also split lines."""
    assert clean_text(f"A{brk}B") == "A | B"


def test_clean_text_removes_ansi_escape_char() -> None:
    """ESC (\\x1b) is dropped, so the colour code becomes harmless visible text."""
    assert clean_text("\x1b[31mred\x1b[0m") == "[31mred[0m"


def test_clean_text_removes_c1_csi_char() -> None:
    """\\x9b is the one-byte C1 form of 'ESC [' - some terminals obey it, so it is dropped."""
    assert clean_text("a\x9b31mb") == "a31mb"


@pytest.mark.parametrize("char", ["\u202e", "\u200b", "\x00"])
def test_clean_text_removes_format_and_null_chars(char: str) -> None:
    """Right-to-left override, zero-width space and NUL are all dropped."""
    assert clean_text(f"ab{char}cd") == "abcd"


def test_clean_text_tab_becomes_space() -> None:
    """A tab is turned into a plain space rather than deleted (keeps words apart)."""
    assert clean_text("Server:\tnginx") == "Server: nginx"


def test_clean_text_only_control_chars_gives_empty_string() -> None:
    """Input made entirely of control chars and line breaks cleans to ''."""
    assert clean_text("\x1b\x00\r\n\u202e\n") == ""


def test_clean_text_exception_object_goes_through_str() -> None:
    """Error values are often exception objects; they are converted with str() first."""
    assert clean_text(ValueError("bad\nthing")) == "bad | thing"


def test_clean_text_int_goes_through_str() -> None:
    """Non-string values like ints are converted with str()."""
    assert clean_text(10061) == "10061"


def test_clean_text_keeps_up_to_four_marks_in_a_row() -> None:
    """Four stacked combining accents (U+0301) on one letter are all kept."""
    assert clean_text("e" + "\u0301" * 4) == "e" + "\u0301" * 4


def test_clean_text_caps_zalgo_marks_at_four() -> None:
    """'Zalgo text' with 30 stacked accents is cut down to 4."""
    assert clean_text("e" + "\u0301" * 30) == "e" + "\u0301" * 4


def test_clean_text_control_char_between_marks_does_not_reset_the_count() -> None:
    """A NUL hidden between marks is removed first, so it can't be used to sneak more marks in."""
    assert clean_text("e" + "\u0301" * 3 + "\x00" + "\u0301" * 3) == "e" + "\u0301" * 4


def test_clean_text_separate_mark_runs_are_each_kept() -> None:
    """Two letters with 3 accents each: each run is under the cap, so nothing is dropped."""
    text = "a" + "\u0301" * 3 + "b" + "\u0301" * 3
    assert clean_text(text) == text


@pytest.mark.parametrize(
    "text",
    [
        unicodedata.normalize("NFD", "Tiếng Việt"),   # decomposed Vietnamese: 2 marks per letter
        "क\u094dष\u093f",                              # Devanagari "kshi"
    ],
    ids=["vietnamese_decomposed", "devanagari"],
)
def test_clean_text_real_scripts_are_unchanged(text: str) -> None:
    """Normal accented text in real languages stays exactly the same."""
    assert clean_text(text) == text


@pytest.mark.parametrize("filler", ["\u115f", "\u1160", "\u3164", "\uffa0"])
def test_clean_text_filler_letters_do_not_reset_the_mark_cap(filler: str) -> None:
    """An invisible filler between two 3-mark runs doesn't buy extra marks: 4 in total survive."""
    text = "a" + "\u0301" * 3 + filler + "\u0301" * 3
    assert clean_text(text) == "a" + "\u0301" * 3 + filler + "\u0301"


def test_clean_text_old_style_korean_with_filler_is_unchanged() -> None:
    """Real old-style Korean jamo using U+1160 (jungseong filler) comes through untouched."""
    text = "ᄀ\u1160ᆨ 한"
    assert clean_text(text) == text


def test_clean_text_fillers_without_marks_are_unchanged() -> None:
    """Fillers on their own (no accent marks around them) are kept as they are."""
    assert clean_text("x\u3164y\uffa0z") == "x\u3164y\uffa0z"
