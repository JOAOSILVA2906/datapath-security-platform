"""Scanner-template supply-chain vetting (review fix #9).

Third-party template feeds (e.g. Nuclei community templates) include entries
tagged ``intrusive``, ``dos`` and ``fuzz``, and ingesting templates from outside
is a supply-chain risk. Before any template may run as a check plugin it must:

  1. be in the PINNED, vetted set (allow-listed by id);
  2. match the pinned content hash (so a feed update cannot silently change
     what a vetted id does);
  3. carry no forbidden tag (dos / intrusive / fuzz / bruteforce / ...);
  4. have EVERY tag mapped to a known SideEffectClass — an unmapped tag is a
     block, not a guess;
  5. resolve to a side-effect class that is not POTENTIALLY_MUTATING (the
     taxonomy refuses that everywhere).

The resulting side-effect class then flows into the policy engine exactly like
any other check's declaration, so a benign-payload template only runs under
ACTIVE intensity and a passive one runs under SAFE.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field

from .intensity import Intensity, SideEffectClass, side_effect_permitted


# Tags that disqualify a template outright, whatever else it claims.
DEFAULT_FORBIDDEN_TAGS = frozenset(
    {
        "dos",
        "network-dos",
        "intrusive",
        "fuzz",
        "fuzzing",
        "bruteforce",
        "brute-force",
        "stress",
        "flood",
    }
)

# Conservative default tag -> side-effect mapping. Extend deliberately; an
# unmapped tag blocks the template rather than defaulting to permissive.
DEFAULT_TAG_SIDE_EFFECTS: dict[str, SideEffectClass] = {
    # passive / observational
    "info": SideEffectClass.PASSIVE,
    "tech": SideEffectClass.PASSIVE,
    "detect": SideEffectClass.PASSIVE,
    "exposure": SideEffectClass.PASSIVE,
    "misconfig": SideEffectClass.PASSIVE,
    "headers": SideEffectClass.PASSIVE,
    "ssl": SideEffectClass.PASSIVE,
    "tls": SideEffectClass.PASSIVE,
    "dns": SideEffectClass.PASSIVE,
    "cve": SideEffectClass.PASSIVE,          # version/behaviour detection only
    "cnvd": SideEffectClass.PASSIVE,
    "default-login-detect": SideEffectClass.PASSIVE,
    # crafted input, no state change
    "sqli": SideEffectClass.BENIGN_PAYLOAD,
    "xss": SideEffectClass.BENIGN_PAYLOAD,
    "lfi": SideEffectClass.BENIGN_PAYLOAD,
    "ssrf": SideEffectClass.BENIGN_PAYLOAD,
    "injection": SideEffectClass.BENIGN_PAYLOAD,
    "redirect": SideEffectClass.BENIGN_PAYLOAD,
    "traversal": SideEffectClass.BENIGN_PAYLOAD,
}


class TemplateVerdict(enum.Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class TemplateManifest:
    """A template as presented by a feed."""

    template_id: str
    tags: tuple[str, ...]
    content: bytes
    source: str = "unknown"

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def normalized_tags(self) -> tuple[str, ...]:
        return tuple(t.strip().lower() for t in self.tags if t.strip())


@dataclass(frozen=True)
class VetResult:
    verdict: TemplateVerdict
    reason: str
    side_effect: SideEffectClass | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict is TemplateVerdict.ALLOWED


class TemplateVetter:
    def __init__(
        self,
        pinned: dict[str, str],  # template_id -> expected content hash
        tag_side_effects: dict[str, SideEffectClass] | None = None,
        forbidden_tags: frozenset[str] = DEFAULT_FORBIDDEN_TAGS,
    ) -> None:
        self._pinned = dict(pinned)
        self._tags = dict(tag_side_effects or DEFAULT_TAG_SIDE_EFFECTS)
        self._forbidden = forbidden_tags

    def vet(self, manifest: TemplateManifest) -> VetResult:
        block = lambda why: VetResult(TemplateVerdict.BLOCKED, why)  # noqa: E731

        # 1. must be pinned
        expected = self._pinned.get(manifest.template_id)
        if expected is None:
            return block(f"template {manifest.template_id!r} is not in the pinned set")

        # 2. hash must match the pinned value
        if manifest.content_hash != expected:
            return block(
                f"content hash mismatch for {manifest.template_id!r} "
                f"(feed changed since vetting)"
            )

        tags = manifest.normalized_tags()

        # 3. forbidden tags
        bad = sorted(set(tags) & self._forbidden)
        if bad:
            return block(f"forbidden tag(s): {', '.join(bad)}")

        # 4. every tag must map
        unmapped = sorted(t for t in tags if t not in self._tags)
        if unmapped:
            return block(f"unmapped tag(s) (block-by-default): {', '.join(unmapped)}")

        # 5. resolve side-effect = most severe mapped tag (PASSIVE if no tags)
        side_effect = SideEffectClass.PASSIVE
        for t in tags:
            se = self._tags[t]
            if se > side_effect:
                side_effect = se
        if side_effect is SideEffectClass.POTENTIALLY_MUTATING:
            return block("resolves to POTENTIALLY_MUTATING; refused everywhere")

        return VetResult(TemplateVerdict.ALLOWED, "", side_effect)

    def permitted_at(
        self, manifest: TemplateManifest, intensity: Intensity
    ) -> VetResult:
        """Vet AND check the template may run at the requested intensity."""
        result = self.vet(manifest)
        if not result.allowed:
            return result
        assert result.side_effect is not None
        if not side_effect_permitted(intensity, result.side_effect):
            return VetResult(
                TemplateVerdict.BLOCKED,
                f"{result.side_effect.name} not permitted at {intensity.name}",
                result.side_effect,
            )
        return result
