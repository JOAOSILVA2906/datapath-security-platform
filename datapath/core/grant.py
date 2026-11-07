"""AuthorizationGrant — signed, timestamped proof that testing is authorized.

A grant binds a proof method + verifier evidence + authorizing identity to a
specific scope version and validity window, and carries an HMAC signature so
tampering is detectable. Grants expire and must be re-verified before each
engagement (spec 1.2): the domain token is re-checked at scan start, not just
at registration, because ownership can change.

Review fixes folded in:
  * #6 — a document-only proof cannot unlock ACTIVE intensity. ACTIVE requires
         a technical proof (domain/host control, bug-bounty linkage, or
         cloud-account linkage).
  * wildcard assets require the proof to cover the parent domain.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .intensity import Intensity
from .scope import AssetKind, Scope


class ProofMethod(enum.Enum):
    DOMAIN_TOKEN = "domain_token"          # DNS TXT / well-known file / header
    SIGNED_DOCUMENT = "signed_document"     # countersigned RoE / SoW
    BUG_BOUNTY_LINK = "bug_bounty_link"     # OAuth link to H1/Bugcrowd/etc.
    CLOUD_ACCOUNT_LINK = "cloud_account_link"  # assume-role into customer cloud
    DELEGATED_AUTHORITY = "delegated_authority"  # agency + owner countersign


# Proofs strong enough to unlock ACTIVE intensity (review fix #6).
_TECHNICAL_PROOFS = frozenset(
    {
        ProofMethod.DOMAIN_TOKEN,
        ProofMethod.BUG_BOUNTY_LINK,
        ProofMethod.CLOUD_ACCOUNT_LINK,
    }
)


class GrantStatus(enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class AuthorizationGrant:
    grant_id: str
    method: ProofMethod
    scope_id: str
    scope_version: int
    authorizing_identity: str          # who approved (email / org / program)
    verifier_evidence: str             # what was checked (token value, doc hash)
    not_before: datetime
    not_after: datetime
    max_intensity: Intensity
    signature: str = ""                # HMAC-SHA256 over the canonical body
    revoked: bool = False

    def __post_init__(self) -> None:
        for name in ("not_before", "not_after"):
            val = getattr(self, name)
            if val.tzinfo is None:
                raise ValueError(f"{name} must be timezone-aware")
            object.__setattr__(self, name, val.astimezone(timezone.utc))
        if self.not_after <= self.not_before:
            raise ValueError("grant not_after must be after not_before")
        object.__setattr__(self, "max_intensity", Intensity.parse(self.max_intensity))

        # Review fix #6: a document-only proof is capped at SAFE.
        if (
            self.method not in _TECHNICAL_PROOFS
            and self.max_intensity > Intensity.SAFE
        ):
            raise ValueError(
                f"proof method {self.method.value!r} cannot authorize "
                f"intensity above SAFE; ACTIVE needs a technical proof"
            )

    # --- signing ----------------------------------------------------------

    def _body(self) -> bytes:
        payload = {
            "grant_id": self.grant_id,
            "method": self.method.value,
            "scope_id": self.scope_id,
            "scope_version": self.scope_version,
            "authorizing_identity": self.authorizing_identity,
            "verifier_evidence": self.verifier_evidence,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "max_intensity": int(self.max_intensity),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def signed(self, key: bytes) -> "AuthorizationGrant":
        """Return a copy carrying a fresh HMAC signature."""
        sig = hmac.new(key, self._body(), hashlib.sha256).hexdigest()
        return replace_grant(self, signature=sig)

    def signature_valid(self, key: bytes) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(key, self._body(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    # --- validity ---------------------------------------------------------

    def status(self, at: datetime) -> GrantStatus:
        if self.revoked:
            return GrantStatus.REVOKED
        at = at.astimezone(timezone.utc)
        if at < self.not_before or at > self.not_after:
            return GrantStatus.EXPIRED
        return GrantStatus.ACTIVE

    def covers_scope(self, scope: Scope) -> bool:
        return (
            self.scope_id == scope.scope_id
            and self.scope_version == scope.version
        )

    def is_valid_for(
        self, scope: Scope, at: datetime, key: bytes
    ) -> tuple[bool, str]:
        """Full check: signature, status, scope binding, wildcard parent cover.

        Returns (ok, reason). ``reason`` is empty when ok.
        """
        if not self.signature_valid(key):
            return False, "bad or missing signature"
        st = self.status(at)
        if st is not GrantStatus.ACTIVE:
            return False, f"grant {st.value}"
        if not self.covers_scope(scope):
            return False, "grant does not cover this scope version"

        # Wildcard assets require the proof to cover the parent domain. For a
        # domain-token proof we treat verifier_evidence as the verified host.
        if self.method is ProofMethod.DOMAIN_TOKEN:
            verified_host = self.verifier_evidence.strip().lower()
            for asset in scope.assets:
                if asset.kind is AssetKind.WILDCARD:
                    parent = asset.value[2:]
                    if verified_host != parent and not verified_host.endswith(
                        "." + parent
                    ):
                        return False, (
                            f"wildcard {asset.value} not covered by verified "
                            f"host {verified_host!r}"
                        )
        return True, ""


def replace_grant(grant: AuthorizationGrant, **changes) -> AuthorizationGrant:
    """dataclasses.replace, kept local so frozen-copy intent is explicit."""
    import dataclasses

    return dataclasses.replace(grant, **changes)
