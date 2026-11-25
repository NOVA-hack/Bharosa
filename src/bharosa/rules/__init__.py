"""Versioned YAML rule packs.

Packs live in ``bharosa/rules/packs``. Set ``BHAROSA_RULES_DIR`` to load an edited copy of the
packs from another folder without touching the code.
"""

from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

PACK_NAMES = ("qr", "url", "playbooks", "truth_cards", "i18n")


def packs_dir() -> Path:
    override = os.environ.get("BHAROSA_RULES_DIR")
    return Path(override) if override else Path(__file__).parent / "packs"


@lru_cache(maxsize=None)
def _load(directory: str, name: str) -> dict[str, Any]:
    path = Path(directory) / f"{name}.yaml"
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if "version" not in data:
        raise ValueError(f"Rule pack {path} has no version field")
    return data


def load_pack(name: str) -> dict[str, Any]:
    if name not in PACK_NAMES:
        raise KeyError(f"Unknown rule pack {name!r}")
    return _load(str(packs_dir()), name)


def ruleset_version() -> str:
    """One version string for the whole ruleset: pack versions plus a content hash."""
    d = packs_dir()
    h = hashlib.sha256()
    versions = []
    for name in PACK_NAMES:
        versions.append(load_pack(name)["version"])
        h.update((d / f"{name}.yaml").read_bytes())
    return "+".join(versions[:3]) + "#" + h.hexdigest()[:8]


def rule_meta(rule_id: str) -> dict[str, Any]:
    """Title, severity and flags for a rule id from any pack."""
    for name in ("qr", "url"):
        rules = load_pack(name)["rules"]
        if rule_id in rules:
            return rules[rule_id]
    pbs = load_pack("playbooks")["playbooks"]
    if rule_id in pbs:
        return pbs[rule_id]
    raise KeyError(rule_id)


def all_rule_ids() -> list[str]:
    ids = list(load_pack("qr")["rules"]) + list(load_pack("url")["rules"])
    ids += list(load_pack("playbooks")["playbooks"])
    return ids


def clear_cache() -> None:
    _load.cache_clear()
