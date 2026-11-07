"""Intensity tiers and the side-effect taxonomy (review fix #4).

The spec's original two-tier wording (safe vs active) was too loose: it placed
crafted-payload checks (time-based inference, error-signature probing) in "safe"
mode, and treated "read-only" as a proxy for "no side effects" — but GET /logout,
GET /item/5/delete and GraphQL mutations over GET all change state.

We separate two orthogonal ideas:

  * Intensity  — a per-scope ceiling and a per-scan request (what the operator
                 is allowed to do), SAFE < ACTIVE.
  * SideEffectClass — what a single check actually does to the target. Each
                 check plugin declares this; the policy engine gates on it.
"""

from __future__ import annotations

import enum


class Intensity(enum.IntEnum):
    """Ordered intensity tiers. Higher is more intrusive.

    IntEnum so a scope ceiling can be compared with ``<=`` against a request.
    """

    SAFE = 1
    ACTIVE = 2

    @classmethod
    def parse(cls, value: str | "Intensity") -> "Intensity":
        if isinstance(value, Intensity):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown intensity: {value!r}") from exc


class SideEffectClass(enum.IntEnum):
    """What a check does to the target, independent of intensity.

    PASSIVE            — traffic a normal user would send; no crafted input.
    BENIGN_PAYLOAD     — crafted input, but provably no state change (the
                         payload is read-only w.r.t. the target).
    POTENTIALLY_MUTATING — may change target state. Never enabled by default,
                         and never permitted by this Phase-0 core at all.
    """

    PASSIVE = 1
    BENIGN_PAYLOAD = 2
    POTENTIALLY_MUTATING = 3


# Which side-effect classes each intensity tier may ever run.
# POTENTIALLY_MUTATING appears nowhere: Phase 0 refuses it unconditionally.
_ALLOWED_SIDE_EFFECTS: dict[Intensity, frozenset[SideEffectClass]] = {
    Intensity.SAFE: frozenset({SideEffectClass.PASSIVE}),
    Intensity.ACTIVE: frozenset(
        {SideEffectClass.PASSIVE, SideEffectClass.BENIGN_PAYLOAD}
    ),
}


def side_effect_permitted(
    intensity: Intensity, side_effect: SideEffectClass
) -> bool:
    """True iff a check of ``side_effect`` may run at ``intensity``."""
    return side_effect in _ALLOWED_SIDE_EFFECTS.get(intensity, frozenset())
