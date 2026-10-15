import unicodedata

SEPARATOR = " | "

# Most real text puts at most ~3 combining marks on one letter (Vietnamese 2, pointed
# Hebrew 3). 4 is a trade-off: rare longer legitimate stacks get trimmed, while "Zalgo"
# text (dozens of stacked marks that smear over neighbouring lines) is cut right down.
MAX_MARKS_IN_A_ROW = 4

# Invisible Hangul "filler" letters: they look like nothing, so they must not end a run of
# marks (otherwise "4 marks + filler + 4 marks + ..." rebuilds a Zalgo stack). They are kept,
# because U+1160 also appears in real old-style Korean text.
_FILLERS = frozenset("ᅟᅠㅤﾠ")


def _cap_marks(line: str) -> str:
    """Drop combining marks (accents etc.) beyond MAX_MARKS_IN_A_ROW in a row."""
    out, run = [], 0
    for ch in line:
        if ch in _FILLERS:              # transparent: keep it, don't reset the count
            out.append(ch)
            continue
        run = run + 1 if unicodedata.category(ch).startswith("M") else 0
        if run <= MAX_MARKS_IN_A_ROW:
            out.append(ch)
    return "".join(out)


def clean_text(text: object) -> str | None:
    """Make server-controlled text safe to print: one printable line.

    Line breaks become " | ", tabs become spaces, and every other Unicode control or
    format character (terminal escape codes, text-direction flips, zero-width chars)
    is dropped, so a hostile server can't fake report lines or recolour the terminal.
    Long runs of stacked accent marks ("Zalgo text") are cut down to a few.
    """
    if text is None:
        return None
    parts = []
    for line in str(text).splitlines():      # also splits on \x85, U+2028 and U+2029
        line = "".join(ch for ch in line.replace("\t", " ")
                       if not unicodedata.category(ch).startswith("C"))
        line = _cap_marks(line).strip()      # after control chars are gone, so they can't reset the count
        if line:
            parts.append(line)
    return SEPARATOR.join(parts)
