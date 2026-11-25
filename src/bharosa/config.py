"""Paths and per-profile settings.

* ``BHAROSA_HOME`` (default ``~/.bharosa``) holds the local SQLite database, evidence and voice cache.
* ``BHAROSA_PROFILE`` (default ``default``) picks the identity in ``$BHAROSA_HOME/profiles/<name>.json``.
  Two terminals on one laptop can be a parent and a guardian by using two profiles, sharing one DB.

The API token is kept in the OS keyring when the optional ``keyring`` package is installed and
``BHAROSA_NO_KEYRING`` is not set; otherwise it falls back to the profile file.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

KEYRING_SERVICE = "bharosa"


def home() -> Path:
    p = Path(os.environ.get("BHAROSA_HOME") or Path.home() / ".bharosa")
    p.mkdir(parents=True, exist_ok=True)
    return p


def profile_name() -> str:
    name = os.environ.get("BHAROSA_PROFILE", "default")
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,40}", name):
        raise ValueError("BHAROSA_PROFILE may contain only letters, digits, - and _")
    return name


def db_path() -> Path:
    return Path(os.environ.get("BHAROSA_DB") or home() / "bharosa.db")


def evidence_dir() -> Path:
    p = home() / "evidence"
    p.mkdir(parents=True, exist_ok=True)
    return p


def voice_cache_dir() -> Path:
    p = home() / "voice_cache"
    p.mkdir(parents=True, exist_ok=True)
    return p


@dataclass
class Profile:
    name: str = "default"
    role: str | None = None  # "parent" or "guardian"
    user_id: str | None = None
    family_id: str | None = None
    display_name: str | None = None
    language: str = "en"
    relay_url: str | None = None  # None = local mode (shared SQLite file)
    token_in_keyring: bool = False
    token: str | None = field(default=None, repr=False)

    @property
    def paired(self) -> bool:
        return bool(self.user_id and self.get_token())

    def get_token(self) -> str | None:
        if self.token:
            return self.token
        if self.token_in_keyring:
            kr = _keyring()
            if kr:
                return kr.get_password(KEYRING_SERVICE, f"{self.name}:{self.user_id}")
        return None

    def set_token(self, token: str) -> None:
        kr = _keyring()
        if kr:
            kr.set_password(KEYRING_SERVICE, f"{self.name}:{self.user_id}", token)
            self.token_in_keyring = True
            self.token = None
        else:
            self.token_in_keyring = False
            self.token = token


def _keyring():
    if os.environ.get("BHAROSA_NO_KEYRING"):
        return None
    try:
        import keyring  # type: ignore

        return keyring
    except Exception:
        return None


def profile_path(name: str | None = None) -> Path:
    d = home() / "profiles"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{name or profile_name()}.json"


def load_profile(name: str | None = None) -> Profile:
    name = name or profile_name()
    path = profile_path(name)
    if not path.exists():
        return Profile(name=name, relay_url=os.environ.get("BHAROSA_RELAY_URL"))
    data = json.loads(path.read_text(encoding="utf-8"))
    data["name"] = name
    prof = Profile(**{k: v for k, v in data.items() if k in Profile.__dataclass_fields__})
    if os.environ.get("BHAROSA_RELAY_URL"):
        prof.relay_url = os.environ["BHAROSA_RELAY_URL"]
    return prof


def save_profile(profile: Profile) -> Path:
    path = profile_path(profile.name)
    path.write_text(json.dumps(asdict(profile), indent=2), encoding="utf-8")
    return path


def delete_profile(name: str | None = None) -> None:
    path = profile_path(name)
    if path.exists():
        path.unlink()
