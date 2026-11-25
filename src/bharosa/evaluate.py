"""bharosa eval: run the labeled synthetic corpus and report recall, specificity and per-rule hits."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

from .pipeline import DirectRunner, Runner, check_message, check_qr, check_url
from .rules import ruleset_version

DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "samples" / "cases.yaml"


@dataclass
class CaseOutcome:
    id: str
    type: str
    label: str
    expected: str
    got: str
    score: int
    rules: list[str]

    @property
    def caught(self) -> bool:
        return self.got in ("medium", "high")

    @property
    def correct(self) -> bool:
        return self.caught if self.label == "scam" else self.got == "low"


def load_corpus(path: str | Path | None = None) -> list[dict]:
    p = Path(path) if path else DEFAULT_CORPUS
    with p.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)["cases"]


def run_eval(path: str | Path | None = None, runner: Runner | None = None) -> dict:
    runner = runner or DirectRunner()
    outcomes: list[CaseOutcome] = []
    for c in load_corpus(path):
        if c["type"] == "qr":
            r = check_qr(c["input"], runner)
        elif c["type"] == "url":
            r = check_url(c["input"], runner)
        else:
            r = check_message(c["input"], runner)
        outcomes.append(CaseOutcome(c["id"], c["type"], c["label"], c["expected"], r.verdict.risk_level,
                                    r.verdict.score, [x.rule_id for x in r.verdict.reasons]))
    scams = [o for o in outcomes if o.label == "scam"]
    benign = [o for o in outcomes if o.label == "benign"]
    hits = Counter(rule for o in outcomes for rule in o.rules)
    return {
        "ruleset_version": ruleset_version(),
        "n": len(outcomes),
        "scam_n": len(scams),
        "benign_n": len(benign),
        "recall": sum(o.caught for o in scams) / len(scams) if scams else None,
        "specificity": sum(o.got == "low" for o in benign) / len(benign) if benign else None,
        "exact_level_accuracy": sum(o.got == o.expected for o in outcomes) / len(outcomes) if outcomes else None,
        "per_rule_hits": dict(sorted(hits.items(), key=lambda kv: (-kv[1], kv[0]))),
        "misses": [o.__dict__ for o in outcomes if not o.correct],
        "level_mismatches": [o.__dict__ for o in outcomes if o.correct and o.got != o.expected],
        "outcomes": [o.__dict__ | {"caught": o.caught, "correct": o.correct} for o in outcomes],
    }
