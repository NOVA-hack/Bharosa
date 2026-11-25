"""The verdict shape every check tool returns, and the fixed scoring rules.

Scoring is deterministic and documented:

* each matched rule carries a weight from its severity: high 60, medium 30, low 10
* the score is the sum of weights, capped at 100
* score >= 60, or any matched rule flagged ``always_high``, gives ``high``
* 30 <= score < 60 gives ``medium``; below 30 gives ``low``

The same input with the same ruleset version always gives the same output.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

SEVERITY_WEIGHTS = {"high": 60, "medium": 30, "low": 10, "info": 0}
LEVELS = ("low", "medium", "high")
LEVEL_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}
HIGH_THRESHOLD = 60
MEDIUM_THRESHOLD = 30
SCORE_CAP = 100


@dataclass(frozen=True)
class Reason:
    rule_id: str
    severity: str
    title: str
    evidence: str = ""
    always_high: bool = False
    truth_card: str | None = None

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS[self.severity]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["weight"] = self.weight
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Reason":
        return cls(
            rule_id=d["rule_id"],
            severity=d["severity"],
            title=d.get("title", d["rule_id"]),
            evidence=d.get("evidence", ""),
            always_high=bool(d.get("always_high", False)),
            truth_card=d.get("truth_card"),
        )


@dataclass
class Verdict:
    tool: str
    risk_level: str
    score: int
    reasons: list[Reason]
    ruleset_version: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "risk_level": self.risk_level,
            "score": self.score,
            "reasons": [r.to_dict() for r in self.reasons],
            "ruleset_version": self.ruleset_version,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Verdict":
        return cls(
            tool=d["tool"],
            risk_level=d["risk_level"],
            score=int(d["score"]),
            reasons=[Reason.from_dict(r) for r in d.get("reasons", [])],
            ruleset_version=d.get("ruleset_version", "?"),
            details=d.get("details", {}),
        )

    @property
    def is_risky(self) -> bool:
        return self.risk_level in ("medium", "high")


def score_reasons(reasons: Iterable[Reason]) -> tuple[int, str]:
    reasons = list(reasons)
    score = min(SCORE_CAP, sum(r.weight for r in reasons))
    if score >= HIGH_THRESHOLD or any(r.always_high for r in reasons):
        level = "high"
    elif score >= MEDIUM_THRESHOLD:
        level = "medium"
    else:
        level = "low"
    return score, level


def make_verdict(tool: str, reasons: list[Reason], ruleset_version: str, details: dict | None = None) -> Verdict:
    # Stable order: severity (high first), then rule id, so output never depends on dict ordering.
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    reasons = sorted(_dedupe(reasons), key=lambda r: (order[r.severity], r.rule_id))
    score, level = score_reasons(reasons)
    return Verdict(tool, level, score, reasons, ruleset_version, details or {})


def combine(verdicts: list[Verdict], ruleset_version: str) -> Verdict:
    """Combine several tool verdicts for one case: the highest risk wins."""
    if not verdicts:
        return Verdict("combined", "low", 0, [], ruleset_version, {})
    if len(verdicts) == 1:
        return verdicts[0]
    top = max(verdicts, key=lambda v: (LEVEL_RANK[v.risk_level], v.score))
    reasons: list[Reason] = []
    for v in verdicts:
        reasons.extend(v.reasons)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    reasons = sorted(_dedupe(reasons), key=lambda r: (order[r.severity], r.rule_id))
    return Verdict(
        tool="combined",
        risk_level=top.risk_level,
        score=top.score,
        reasons=reasons,
        ruleset_version=ruleset_version,
        details={"tools": [v.to_dict() for v in verdicts]},
    )


def _dedupe(reasons: Iterable[Reason]) -> list[Reason]:
    seen: set[tuple[str, str]] = set()
    out: list[Reason] = []
    for r in reasons:
        key = (r.rule_id, r.evidence)
        if key not in seen:
            seen.add(key)
            out.append(r)
    return out
