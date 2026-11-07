"""Runnable demo of the Phase-0 gate. No network access.

    python -m datapath.demo

Shows an allowed probe decision and several refusals, then verifies the audit
chain is intact.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from datapath.core import (
    AllowList,
    Asset,
    AssetKind,
    AuditLog,
    AuthorizationGrant,
    Intensity,
    KillSwitch,
    PolicyEngine,
    PolicyInput,
    ProofMethod,
    ResolutionError,
    Scope,
    SideEffectClass,
    TestWindow,
)

KEY = b"demo-signing-key"
NOW = datetime.now(timezone.utc)


def main() -> None:
    scope = Scope(
        scope_id="acme",
        version=1,
        assets=(
            Asset(AssetKind.URL_PREFIX, "https://api.example.com/v2/"),
            # In scope by URL, but its host resolves to cloud metadata — the
            # egress gate must still refuse it (SSRF block beats scope).
            Asset(AssetKind.URL_PREFIX, "https://internal.example.com/"),
        ),
        exclusions=(),
        windows=(TestWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1)),),
        intensity_ceiling=Intensity.SAFE,
    )
    grant = AuthorizationGrant(
        grant_id="g1",
        method=ProofMethod.DOMAIN_TOKEN,
        scope_id="acme",
        scope_version=1,
        authorizing_identity="sec@example.com",
        verifier_evidence="example.com",
        not_before=NOW - timedelta(days=1),
        not_after=NOW + timedelta(days=1),
        max_intensity=Intensity.SAFE,
    ).signed(KEY)

    audit = AuditLog()
    ks = KillSwitch()
    ks.register("scan-demo", at=NOW)
    engine = PolicyEngine(KEY, ks, audit)

    # A public resolver that also demonstrates the SSRF block-list.
    resolver = lambda h: {  # noqa: E731
        "api.example.com": ["93.184.216.34"],
        "internal.example.com": ["169.254.169.254"],  # metadata -> blocked
    }.get(h, [])
    allow = AllowList(scope, resolver)

    print("== DataPath Phase-0 gate demo ==\n")

    # 1. Allowed passive probe.
    target = allow.resolve("https://api.example.com/v2/search?q=1")
    res = engine.evaluate(
        PolicyInput(
            scope=scope, grant=grant, target=target,
            requested_intensity=Intensity.SAFE,
            side_effect=SideEffectClass.PASSIVE,
            scan_id="scan-demo", at=NOW,
        )
    )
    print(f"[1] passive, in-scope, in-window -> {res.decision.value.upper()} "
          f"(checks: {', '.join(res.checks)})")

    # 2. ACTIVE requested but scope ceiling is SAFE.
    res = engine.evaluate(
        PolicyInput(
            scope=scope, grant=grant, target=target,
            requested_intensity=Intensity.ACTIVE,
            side_effect=SideEffectClass.BENIGN_PAYLOAD,
            scan_id="scan-demo", at=NOW,
        )
    )
    print(f"[2] active over SAFE ceiling      -> {res.decision.value.upper()} "
          f"({res.reason})")

    # 3. SSRF: host resolves to cloud metadata.
    try:
        allow.resolve("https://internal.example.com/")
    except ResolutionError as e:
        print(f"[3] host -> 169.254.169.254       -> REFUSED ({e})")

    # 4. Out-of-scope redirect target.
    try:
        allow.resolve("https://evil.example.net/v2/")
    except ResolutionError as e:
        print(f"[4] off-scope redirect            -> REFUSED ({e})")

    # 5. Kill switch engaged mid-scan.
    ks.abort("scan-demo")
    res = engine.evaluate(
        PolicyInput(
            scope=scope, grant=grant, target=target,
            requested_intensity=Intensity.SAFE,
            side_effect=SideEffectClass.PASSIVE,
            scan_id="scan-demo", at=NOW,
        )
    )
    print(f"[5] after per-scan abort          -> {res.decision.value.upper()} "
          f"({res.reason})")

    ok, bad = audit.verify()
    print(f"\naudit chain: {'INTACT' if ok else f'BROKEN at seq {bad}'} "
          f"({len(audit)} records)")


if __name__ == "__main__":
    main()
