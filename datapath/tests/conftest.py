"""Shared fixtures / helpers for Phase-0 tests (stdlib unittest style)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from datapath.core import (
    Asset,
    AssetKind,
    AuthorizationGrant,
    Intensity,
    ProofMethod,
    Scope,
    TestWindow,
)

KEY = b"test-signing-key-phase0"
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def make_scope(**overrides) -> Scope:
    defaults = dict(
        scope_id="acme",
        version=1,
        assets=(Asset(AssetKind.URL_PREFIX, "https://api.example.com/v2/"),),
        windows=(TestWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1)),),
        intensity_ceiling=Intensity.ACTIVE,
    )
    defaults.update(overrides)
    return Scope(**defaults)


def make_grant(scope: Scope, **overrides) -> AuthorizationGrant:
    defaults = dict(
        grant_id="g1",
        method=ProofMethod.DOMAIN_TOKEN,
        scope_id=scope.scope_id,
        scope_version=scope.version,
        authorizing_identity="sec@example.com",
        verifier_evidence="example.com",
        not_before=NOW - timedelta(days=1),
        not_after=NOW + timedelta(days=1),
        max_intensity=Intensity.ACTIVE,
    )
    defaults.update(overrides)
    return AuthorizationGrant(**defaults).signed(KEY)


def resolver(mapping: dict[str, list[str]]):
    def _resolve(host: str) -> list[str]:
        return mapping.get(host, [])

    return _resolve
