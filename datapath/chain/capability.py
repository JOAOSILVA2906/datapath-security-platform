"""Capabilities — findings modelled as composable steps (spec 5.1).

A single low/medium finding is often only interesting in combination. We model
each finding as a *capability*: it REQUIRES some attacker state (preconditions)
and, once used, GRANTS new state (postconditions). The planner then searches
for sequences where one capability unlocks the precondition of the next.

State is a vocabulary of plain tokens held by the attacker, e.g.:
  anonymous            — the baseline, unauthenticated start
  low_priv_token       — holds a valid low-privilege session
  endpoints_known      — has mapped the API surface
  object_id_known      — can name a specific object id (e.g. enumerable ids)
  cross_origin_read    — can read authenticated responses from another origin

The SENSITIVE_STATES are the boundary: reaching any of them is the stop
condition (spec 5.2) — the path ends there, confirmed-reachable, not-exploited.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Reaching any of these ends a path at a sensitive boundary.
SENSITIVE_STATES: frozenset[str] = frozenset({
    "cross_tenant_read",     # another tenant's/user's record is reachable
    "privileged_function",   # a privileged/admin function is reachable
    "sensitive_data_read",   # a regulated/PII surface is reachable
    "injection_confirmed",   # untrusted input provably reaches an interpreter
})

START_ANONYMOUS: frozenset[str] = frozenset({"anonymous"})
START_LOW_PRIV: frozenset[str] = frozenset({"anonymous", "low_priv_token"})


@dataclass(frozen=True)
class Capability:
    """One composable step derived from a finding/confirmation.

    reachability is in (0, 1]: how realistically an attacker can take this step
    from its preconditions (confirmed > inferred > speculative). impact is a
    0-100 business-impact contribution if this step reaches the boundary.
    """

    cap_id: str
    description: str
    requires: frozenset[str]
    grants: frozenset[str]
    reachability: float
    impact: int = 0
    evidence: str = ""
    owasp: str = ""

    def __post_init__(self) -> None:
        if not (0.0 < self.reachability <= 1.0):
            raise ValueError("reachability must be in (0, 1]")
        if not (0 <= self.impact <= 100):
            raise ValueError("impact must be in [0, 100]")
        object.__setattr__(self, "requires", frozenset(self.requires))
        object.__setattr__(self, "grants", frozenset(self.grants))

    def applicable(self, held: frozenset[str]) -> bool:
        """True if preconditions are met and it would grant something new."""
        return self.requires <= held and not self.grants <= held


# --- factories that turn concrete results into capabilities ---------------

def capability_from_bola(confirmation, requires: set[str]) -> Capability:
    """A confirmed BOLA (Phase 2) → a high-reachability step to the boundary."""
    ev = confirmation.boundary.evidence if confirmation.boundary else ""
    return Capability(
        cap_id="bola-confirmed",
        description="BOLA: referência direta ao objeto de outro tenant é aceita",
        requires=frozenset(requires),
        grants=frozenset({"cross_tenant_read"}),
        reachability=0.9,            # confirmed by active test
        impact=90,
        evidence=ev,
        owasp="A01:2021 Broken Access Control",
    )


def capability_from_vertical_privilege(confirmation, requires: set[str]) -> Capability:
    ev = confirmation.boundary.evidence if confirmation.boundary else ""
    return Capability(
        cap_id="vertical-privilege-confirmed",
        description="Token de baixo privilégio alcança função administrativa",
        requires=frozenset(requires),
        grants=frozenset({"privileged_function"}),
        reachability=0.9,
        impact=85,
        evidence=ev,
        owasp="A01:2021 Broken Access Control",
    )


def enumeration_capability(reachability: float = 0.8) -> Capability:
    """Sequential/guessable object ids let an attacker name a target object."""
    return Capability(
        cap_id="id-enumeration",
        description="Identificadores sequenciais/adivinháveis permitem nomear objetos",
        requires=frozenset({"anonymous", "endpoints_known"}),
        grants=frozenset({"object_id_known"}),
        reachability=reachability,
        impact=20,
        evidence="API usa ids numéricos sequenciais (ex.: /api/.../1).",
        owasp="A01:2021 Broken Access Control",
    )


def recon_capability() -> Capability:
    """Passive recon maps the surface — almost always available."""
    return Capability(
        cap_id="surface-mapping",
        description="Mapeamento passivo revelou endpoints e parâmetros",
        requires=frozenset({"anonymous"}),
        grants=frozenset({"endpoints_known"}),
        reachability=0.95,
        impact=5,
        evidence="Grafo de caminho-de-dados construído a partir das páginas em escopo.",
    )
