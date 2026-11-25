"""inspect_url: flag phishing indicators in a link. Never fetches the URL."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from ..rules import load_pack, ruleset_version
from ..verdict import Reason, Verdict, make_verdict
from . import MAX_URL_BYTES, enforce_limit


def _reason(rules: dict, rule_id: str, evidence: str = "") -> Reason:
    meta = rules[rule_id]
    return Reason(
        rule_id=rule_id,
        severity=meta["severity"],
        title=meta["title"],
        evidence=evidence,
        always_high=bool(meta.get("always_high", False)),
        truth_card=meta.get("truth_card"),
    )


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# Characters people use to imitate Latin letters (digits and common Cyrillic/Greek homoglyphs).
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a",
                             "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i",
                             "ѕ": "s", "ԁ": "d", "ɡ": "g", "ο": "o", "ν": "v", "κ": "k"})


def _skeleton(label: str) -> str:
    s = label.lower().translate(_HOMOGLYPHS)
    s = s.replace("rn", "m").replace("vv", "w")
    return re.sub(r"[^a-z]", "", s)


def split_host(host: str, multi_part_suffixes: list[str]) -> tuple[str, str, list[str]]:
    """Return (registered_domain, suffix, subdomain_labels) using a small offline suffix list."""
    labels = [p for p in host.split(".") if p]
    if len(labels) < 2:
        return host, "", []
    last_two = ".".join(labels[-2:])
    if last_two in multi_part_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:]), last_two, labels[:-3]
    return last_two, labels[-1], labels[:-2]


def _scripts(text: str) -> set[str]:
    out = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            out.add(name.split(" ")[0] if name else "UNKNOWN")
    return out


def normalise(url: str) -> str:
    url = url.strip().strip("<>\"'")
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.IGNORECASE):
        url = "http://" + url if not url.lower().startswith("//") else "http:" + url
    return url


def inspect_url(url: str) -> Verdict:
    enforce_limit(url, MAX_URL_BYTES, "URL")
    pack = load_pack("url")
    rules = pack["rules"]
    version = ruleset_version()
    reasons: list[Reason] = []
    original = url.strip()
    scheme_given = bool(re.match(r"^[a-z][a-z0-9+.\-]*://", original, re.IGNORECASE))
    url = normalise(original)

    try:
        parts = urlsplit(url)
        host_raw = parts.hostname or ""
        port = parts.port
    except ValueError:
        return make_verdict("inspect_url", [_reason(rules, "URL-UNPARSEABLE", original[:80])], version,
                            {"parsed": False})
    if not host_raw:
        return make_verdict("inspect_url", [_reason(rules, "URL-UNPARSEABLE", original[:80])], version,
                            {"parsed": False})

    scheme = parts.scheme.lower()
    netloc = parts.netloc
    path = unquote(parts.path or "")
    full_lower = (path + "?" + (parts.query or "")).lower()

    if "@" in netloc:
        reasons.append(_reason(rules, "URL-AT-SIGN", f"real host is '{host_raw}'"))

    # Decode punycode labels to see what the user would see.
    host_ascii = host_raw.lower().rstrip(".")
    try:
        host_unicode = host_ascii.encode("ascii").decode("idna") if "xn--" in host_ascii else host_ascii
    except (UnicodeError, ValueError):
        host_unicode = host_ascii
    if not host_ascii.isascii():
        host_unicode = host_ascii
        try:
            host_ascii = host_ascii.encode("idna").decode("ascii")
        except UnicodeError:
            pass

    is_ip = False
    try:
        ipaddress.ip_address(host_raw.strip("[]"))
        is_ip = True
    except ValueError:
        if re.fullmatch(r"\d+", host_raw) or re.fullmatch(r"0x[0-9a-f]+", host_raw, re.I):
            is_ip = True  # decimal or hex encoded IPv4
    if is_ip:
        reasons.append(_reason(rules, "URL-RAW-IP", host_raw))

    official_domains = {d for ds in pack["brand_allowlist"].values() for d in ds}
    registered, suffix, subs = ("", "", [])
    if not is_ip:
        if "xn--" in host_ascii or not host_raw.isascii():
            reasons.append(_reason(rules, "URL-PUNYCODE", f"{host_ascii} shows as {host_unicode}"))
        for label in host_unicode.split("."):
            scripts = _scripts(label)
            if len(scripts) > 1:
                reasons.append(_reason(rules, "URL-MIXED-SCRIPT", f"'{label}' mixes {', '.join(sorted(scripts))}"))
                break

        registered, suffix, subs = split_host(host_unicode, pack["multi_part_suffixes"])
        is_official = registered in official_domains or host_unicode in official_domains

        if not is_official:
            reg_label = registered.split(".")[0]
            skel = _skeleton(reg_label)
            matched_brand = None
            for brand, domains in pack["brand_allowlist"].items():
                brand_labels = {brand} | {d.split(".")[0] for d in domains}
                for bl in brand_labels:
                    if len(bl) < 3:
                        continue
                    dist = levenshtein(skel, bl)
                    if reg_label != bl and (dist == 0 or (len(bl) >= 6 and dist <= 2) or (len(bl) >= 4 and dist == 1 and len(skel) == len(bl))):
                        reasons.append(_reason(rules, "URL-LOOKALIKE", f"'{registered}' imitates {domains[0]}"))
                        matched_brand = brand
                        break
                if matched_brand:
                    break
            if not matched_brand:
                tokens = re.split(r"[.\-_]", ".".join(subs + [reg_label]).lower())
                joined = "".join(tokens)
                for brand, domains in pack["brand_allowlist"].items():
                    names = {brand} | {d.split(".")[0] for d in domains}
                    hit = next((n for n in names if len(n) >= 3 and (n in tokens or (len(n) >= 5 and n in joined))), None)
                    if hit:
                        reasons.append(_reason(rules, "URL-BRAND-IN-DOMAIN", f"'{hit}' in {host_unicode}, official is {domains[0]}"))
                        break

            tld = host_unicode.rsplit(".", 1)[-1]
            if tld in pack["risky_tlds"]:
                reasons.append(_reason(rules, "URL-RISKY-TLD", f".{tld}"))

            if registered in pack["shorteners"] or host_unicode in pack["shorteners"]:
                reasons.append(_reason(rules, "URL-SHORTENER", host_unicode))

            lure_text = host_unicode + " " + full_lower
            lure = next((k for k in pack["lure_keywords"]
                         if re.search(r"(?<![a-z])" + re.escape(k) + r"(?![a-z])", lure_text)), None)
            if lure:
                reasons.append(_reason(rules, "URL-LURE-KEYWORD", f"'{lure}' on {registered}"))

            if len(subs) >= 4:
                reasons.append(_reason(rules, "URL-MANY-SUBDOMAINS", f"{len(subs)} sub-domains"))
        details_official = is_official
    else:
        details_official = False

    if scheme == "http" and scheme_given:
        login = next((w for w in pack["login_path_words"] if w in full_lower or w in host_unicode), None)
        if login:
            reasons.append(_reason(rules, "URL-HTTP-LOGIN", f"http with '{login}'"))

    if path.lower().endswith(".apk") or ".apk?" in full_lower:
        reasons.append(_reason(rules, "URL-APK", path.rsplit("/", 1)[-1]))

    if port is not None and port not in (80, 443):
        reasons.append(_reason(rules, "URL-NONSTANDARD-PORT", f"port {port}"))

    details = {
        "parsed": True,
        "scheme": scheme if scheme_given else None,
        "host": host_unicode,
        "host_ascii": host_ascii,
        "registered_domain": registered or host_unicode,
        "official_domain": details_official,
        "fetched": False,
    }
    return make_verdict("inspect_url", reasons, version, details)
