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

    # Tradução dos nomes das verificações internas para exibição.
    nomes_pt = {
        "kill_switch": "botão-de-parada",
        "grant_valid": "autorização-válida",
        "test_window": "janela-de-tempo",
        "intensity_ceiling": "teto-de-intensidade",
        "side_effect_class": "classe-de-efeito",
        "target_in_scope": "alvo-em-escopo",
    }

    def decisao_pt(valor: str) -> str:
        return {"allow": "PERMITIDO", "deny": "NEGADO"}.get(valor, valor.upper())

    print("== Demonstração do portão da Fase 0 do DataPath ==\n")

    # 1. Sondagem passiva permitida.
    target = allow.resolve("https://api.example.com/v2/search?q=1")
    res = engine.evaluate(
        PolicyInput(
            scope=scope, grant=grant, target=target,
            requested_intensity=Intensity.SAFE,
            side_effect=SideEffectClass.PASSIVE,
            scan_id="scan-demo", at=NOW,
        )
    )
    verificacoes = ", ".join(nomes_pt.get(c, c) for c in res.checks)
    print(f"[1] passiva, em escopo, na janela -> {decisao_pt(res.decision.value)} "
          f"(verificações: {verificacoes})")

    # 2. Pediu modo ATIVO, mas o teto do escopo é SEGURO.
    res = engine.evaluate(
        PolicyInput(
            scope=scope, grant=grant, target=target,
            requested_intensity=Intensity.ACTIVE,
            side_effect=SideEffectClass.BENIGN_PAYLOAD,
            scan_id="scan-demo", at=NOW,
        )
    )
    print(f"[2] ativo acima do teto SEGURO    -> {decisao_pt(res.decision.value)} "
          f"(intensidade pedida excede o teto do escopo)")

    # 3. SSRF: o host resolve para metadados de nuvem.
    try:
        allow.resolve("https://internal.example.com/")
    except ResolutionError:
        print("[3] host -> 169.254.169.254       -> RECUSADO "
              "(endereço bloqueado: faixa protegida contra SSRF, "
              "não é um ativo interno em escopo)")

    # 4. Alvo de redirecionamento fora do escopo.
    try:
        allow.resolve("https://evil.example.net/v2/")
    except ResolutionError:
        print("[4] redirect fora de escopo       -> RECUSADO "
              "(url não está no escopo)")

    # 5. Botão de parada acionado no meio do scan.
    ks.abort("scan-demo")
    res = engine.evaluate(
        PolicyInput(
            scope=scope, grant=grant, target=target,
            requested_intensity=Intensity.SAFE,
            side_effect=SideEffectClass.PASSIVE,
            scan_id="scan-demo", at=NOW,
        )
    )
    print(f"[5] após abortar o scan           -> {decisao_pt(res.decision.value)} "
          f"(scan não está em execução: abortado/pausado/desconhecido)")

    ok, bad = audit.verify()
    estado = "ÍNTEGRA" if ok else f"QUEBRADA no registro {bad}"
    print(f"\ncadeia de auditoria: {estado} ({len(audit)} registros)")


if __name__ == "__main__":
    main()
