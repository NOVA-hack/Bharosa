r"""Write the relay JSON fixtures the Android unit tests parse (android/app/src/test/resources).

Run after changing the shape of POST /check or GET /cases/{id}:
    .venv\Scripts\python scripts/make_android_fixtures.py
tests/test_appcheck.py fails if the fixtures fall out of step with the relay. Synthetic data only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from fastapi.testclient import TestClient  # noqa: E402

from bharosa.relay.app import create_app  # noqa: E402
from bharosa.service import FamilyService  # noqa: E402
from bharosa.store import Store  # noqa: E402

OUT = ROOT / "android" / "app" / "src" / "test" / "resources"
RISKY = "upi://pay?pa=rewards.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&tn=receive%20cashback"
SAFE = "upi://pay?pa=sharma.dairy@okaxis&pn=Sharma%20Dairy&am=60"


def build() -> dict[str, dict]:
    c = TestClient(create_app(FamilyService(Store(":memory:"))))
    p = c.post("/families", json={"parent_name": "Amma", "language": "hi"}).json()
    g = c.post("/join", json={"pair_code": p["pair_code"], "guardian_name": "Rohan"}).json()
    ph = {"Authorization": "Bearer " + p["token"]}
    gh = {"Authorization": "Bearer " + g["token"]}
    held = c.post("/check", json={"content": RISKY, "kind": "qr", "lang": "en"}, headers=ph).json()
    allowed = c.post("/check", json={"content": SAFE, "kind": "qr", "lang": "en"}, headers=ph).json()
    case = c.get(f"/cases/{held['case_id']}", headers=gh).json()
    return {"check_held.json": held, "check_allowed.json": allowed, "case_held.json": case}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in build().items():
        (OUT / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print("wrote", OUT / name)


if __name__ == "__main__":
    main()
