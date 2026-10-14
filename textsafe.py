import unicodedata

SEPARATOR = " | "


def clean_text(text: object) -> str | None:
    """Make server-controlled text safe to print: one printable line.

    Line breaks become " | ", tabs become spaces, and every other Unicode control or
    format character (terminal escape codes, text-direction flips, zero-width chars)
    is dropped, so a hostile server can't fake report lines or recolour the terminal.
    """
    if text is None:
        return None
    parts = []
    for line in str(text).splitlines():      # also splits on \x85, U+2028 and U+2029
        line = "".join(ch for ch in line.replace("\t", " ")
                       if not unicodedata.category(ch).startswith("C")).strip()
        if line:
            parts.append(line)
    return SEPARATOR.join(parts)
