import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Every test gets its own BHAROSA_HOME, no keyring, and no real relay."""
    monkeypatch.setenv("BHAROSA_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BHAROSA_NO_KEYRING", "1")
    monkeypatch.setenv("BHAROSA_VOICE_ENGINE", "text")
    for var in ("BHAROSA_PROFILE", "BHAROSA_RELAY_URL", "BHAROSA_DB", "ANTHROPIC_API_KEY", "ELEVENLABS_API_KEY",
                "BHAROSA_S3_BUCKET", "BHAROSA_RULES_DIR"):
        monkeypatch.delenv(var, raising=False)
    yield tmp_path


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def service(clock):
    from bharosa.service import FamilyService
    from bharosa.store import Store

    return FamilyService(Store(":memory:"), clock=clock)


@pytest.fixture
def family(service):
    """A parent and a linked guardian."""
    p = service.create_family("Amma", "hi")
    g = service.join_family(p["pair_code"], "Rohan", "en", phone="+91 90000 00000")
    return {"parent": p["token"], "guardian": g["token"], "family_id": p["family_id"], "pair": p}
