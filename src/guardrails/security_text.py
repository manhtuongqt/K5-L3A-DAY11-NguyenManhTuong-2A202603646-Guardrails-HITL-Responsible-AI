"""Bounded inspection views; decoded text is never promoted to instructions.

This is normalization/decoding, not decryption or a general language translator.
Limits prevent recursively encoded data from consuming unbounded CPU/memory.
"""
import base64
import binascii
import codecs
import html
import re
from urllib.parse import unquote

MAX_TEXT = 12000
MAX_VIEWS = 32
MAX_DEPTH = 3
MAX_TOKENS = 24
_B64 = re.compile(r"(?<![\w+/=-])[A-Za-z0-9+/_-]{8,}={0,2}(?![\w+/=-])")
_HEX = re.compile(r"(?<![\w])(?:[0-9a-fA-F]{2}){6,}(?![\w])")
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})")


def inspection_views(text: str) -> list[str]:
    """Inspect up to 3 decoding layers / 32 views / 24 tokens per view.

    Always include the complete original. Only decode texts <= 12000 characters.
    Invalid encodings are ignored, never executed. UTF-8 decoding is strict.
    """
    views, seen = [text], {text}
    frontier = [text] if len(text) <= MAX_TEXT else []
    for _ in range(MAX_DEPTH):
        next_frontier = []
        for current in frontier:
            candidates = [html.unescape(current), unquote(current, errors="replace"),
                          _UNICODE_ESCAPE.sub(lambda m: chr(int(m[1] or m[2], 16)), current),
                          codecs.decode(current, "rot_13"), current[::-1]]
            for token in _B64.findall(current)[:MAX_TOKENS]:
                try:
                    candidates.append(base64.b64decode(token + "=" * (-len(token) % 4),
                                                       altchars=b"-_", validate=True).decode("utf-8"))
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    pass
            for token in _HEX.findall(current)[:MAX_TOKENS]:
                try:
                    candidates.append(bytes.fromhex(token).decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    pass
            for candidate in candidates:
                if candidate and candidate not in seen and len(candidate) <= MAX_TEXT:
                    if len(views) >= MAX_VIEWS:
                        return views
                    seen.add(candidate)
                    views.append(candidate)
                    next_frontier.append(candidate)
        frontier = next_frontier
    return views
