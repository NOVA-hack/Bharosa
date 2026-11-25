"""Find links, UPI URIs and UPI IDs inside free text so a message can fan out to every relevant check."""

from __future__ import annotations

import re

UPI_URI_RE = re.compile(r"upi://[^\s<>\"']+", re.IGNORECASE)
URL_RE = re.compile(
    r"(?:(?:https?|hxxps?)://|www\.)[^\s<>\"']+"
    r"|\b(?:[a-z0-9\-]+\.)+(?:com|in|net|org|xyz|top|click|info|live|co|io|me|app|site|online|link|buzz|icu|shop|support|ly|gl|gy|at|cc|tk|ml|ga|cf|gq)(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)
VPA_IN_TEXT_RE = re.compile(r"(?<![\w.\-@/])([a-z0-9.\-_]{2,64}@[a-z][a-z0-9]{1,30})(?![\w@]|\.\w)", re.IGNORECASE)


def extract_upi_uris(text: str) -> list[str]:
    return _unique(m.group(0).rstrip(".,;)") for m in UPI_URI_RE.finditer(text))


def extract_urls(text: str) -> list[str]:
    without_upi = UPI_URI_RE.sub(" ", text)
    without_email = re.sub(r"\S+@\S+", " ", without_upi)
    urls = []
    for m in URL_RE.finditer(without_email):
        u = m.group(0).rstrip(".,;)!")
        u = re.sub(r"^hxxp", "http", u, flags=re.IGNORECASE)
        urls.append(u)
    return _unique(urls)


def extract_vpas(text: str) -> list[str]:
    without_upi = UPI_URI_RE.sub(" ", text)
    out = []
    for m in VPA_IN_TEXT_RE.finditer(without_upi):
        vpa = m.group(1)
        handle = vpa.split("@", 1)[1].lower()
        # Skip things that look like e-mail domains (contain a dot after @ is excluded by the regex).
        if handle in {"gmail", "yahoo", "outlook", "hotmail"}:
            continue
        out.append(vpa)
    return _unique(out)


def _unique(items) -> list[str]:
    seen, out = set(), []
    for i in items:
        if i.lower() not in seen:
            seen.add(i.lower())
            out.append(i)
    return out
