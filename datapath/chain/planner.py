"""Attack-path planner (spec 5.1 & 5.3).

Searches for sequences of capabilities where each step's preconditions are met
by the state accumulated so far, until a sensitive boundary is reached. Each
path is scored by **realistic reachability** (the product of its steps'
reachabilities) times business impact, so the report is driven by whether a
vulnerable surface is actually on a path to data a real attacker could reach —
not merely by the presence of findings (spec 5.3).

The search stops a branch the moment it reaches a sensitive state: that is the
boundary, and the path ends there (confirmed-reachable, not-exploited).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .capability import SENSITIVE_STATES, Capability


@dataclass(frozen=True)
class AttackPath:
    steps: tuple[Capability, ...]
    reached: str                      # the sensitive state the path ends at
    reachability: float               # product of step reachabilities (0..1]
    impact: int                       # terminal business-impact contribution

    @property
    def score(self) -> float:
        """Reachability-weighted risk, 0..100."""
        return self.reachability * self.impact

    def narrative(self) -> list[str]:
        lines = []
        held = "anônimo"
        for i, cap in enumerate(self.steps, 1):
            lines.append(f"{i}. {cap.description}"
                         + (f"  [{cap.owasp}]" if cap.owasp else ""))
            if cap.evidence:
                lines.append(f"   evidência: {cap.evidence}")
        lines.append(f"■ LIMITE SENSÍVEL ALCANÇADO: {self.reached} "
                     f"— parar (confirmado-alcançável, não-explorado).")
        return lines

    def to_dict(self) -> dict:
        return {
            "reached_boundary": self.reached,
            "reachability": round(self.reachability, 4),
            "impact": self.impact,
            "score": round(self.score, 2),
            "steps": [
                {"cap_id": c.cap_id, "description": c.description,
                 "owasp": c.owasp, "evidence": c.evidence,
                 "reachability": c.reachability}
                for c in self.steps
            ],
            "status": "confirmed-reachable, not-exploited",
        }


class AttackPathPlanner:
    def __init__(
        self,
        capabilities: list[Capability],
        start_states: frozenset[str],
        sensitive_states: frozenset[str] = SENSITIVE_STATES,
        max_depth: int = 6,
    ) -> None:
        self._caps = list(capabilities)
        self._start = frozenset(start_states)
        self._sensitive = frozenset(sensitive_states)
        self._max_depth = max_depth

    def plan(self) -> list[AttackPath]:
        """Return attack paths reaching a boundary, best (highest score) first.

        At most one path per reached boundary — the highest-scoring one.
        """
        found: list[AttackPath] = []

        def dfs(held: frozenset[str], path: tuple[Capability, ...], reach: float) -> None:
            if len(path) >= self._max_depth:
                return
            for cap in self._caps:
                if not cap.applicable(held):
                    continue
                new_held = held | cap.grants
                new_path = path + (cap,)
                new_reach = reach * cap.reachability
                newly_sensitive = (cap.grants & self._sensitive) - held
                if newly_sensitive:
                    # Boundary reached — stop this branch here.
                    for state in sorted(newly_sensitive):
                        found.append(AttackPath(
                            steps=new_path, reached=state,
                            reachability=new_reach, impact=cap.impact,
                        ))
                else:
                    dfs(new_held, new_path, new_reach)

        dfs(self._start, (), 1.0)

        # keep the best path per reached boundary, then rank by score
        best: dict[str, AttackPath] = {}
        for p in found:
            cur = best.get(p.reached)
            if cur is None or p.score > cur.score:
                best[p.reached] = p
        return sorted(best.values(), key=lambda p: p.score, reverse=True)
