"""Demonstração da Fase 2 — confirmação ativa com parada no limite sensível.

Roda OFFLINE. Simula dois tenants de treino com dados DECOY (falsos). Mostra o
engine confirmando que a identidade A alcança o objeto do tenant B — e PARANDO
no limite: confirma que é alcançável, captura prova mascarada, e NÃO puxa o dado.

    python -m datapath.demo_fase2
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from datapath.core import (
    AllowList, Asset, AssetKind, AuditLog, Intensity, KillSwitch,
    PolicyEngine, RateLimiter, Scope, TestWindow,
)
from datapath.core.grant import AuthorizationGrant, ProofMethod
from datapath.scan import GatedEgress, HttpResponse
from datapath.confirm import ActiveConfirmer

KEY = b"demo-fase2"
NOW = datetime.now(timezone.utc)
DECOY_B = "DECOY-TENANT-B-7f3a9c"   # marcador falso semeado no tenant de teste B


def main() -> None:
    # Escopo com teto ATIVO (o cliente autorizou confirmação ativa).
    scope = Scope(
        scope_id="treino", version=1,
        assets=(Asset(AssetKind.URL_PREFIX, "https://treino.example.com/"),),
        windows=(TestWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1)),),
        intensity_ceiling=Intensity.ACTIVE,
    )
    grant = AuthorizationGrant(
        grant_id="g1", method=ProofMethod.DOMAIN_TOKEN,
        scope_id="treino", scope_version=1,
        authorizing_identity="voce@treino.example.com",
        verifier_evidence="treino.example.com",
        not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=1),
        max_intensity=Intensity.ACTIVE,
    ).signed(KEY)

    ks = KillSwitch(); ks.register("scan-demo", at=NOW)
    audit = AuditLog()
    policy = PolicyEngine(KEY, ks, audit)

    pedidos = []

    def transporte(target, headers):
        pedidos.append(target.url)
        # O objeto 1002 pertence ao tenant B e carrega o marcador decoy.
        if target.url.endswith("/api/orders/1002"):
            return HttpResponse(200, {"Content-Type": "application/json"},
                                b'{"id":1002,"owner":"tenantB","nota":"' + DECOY_B.encode() + b'"}',
                                0.04, target.url)
        return HttpResponse(404, {}, b"", 0.01, target.url)

    # Egress em modo ativo, COM confirmação por scan (opt-in explícito).
    egress = GatedEgress(
        scope=scope, grant=grant, signing_key=KEY,
        allowlist=AllowList(scope, lambda h: {"treino.example.com": ["93.184.216.34"]}.get(h, [])),
        policy=policy, rate_limiter=RateLimiter(), kill_switch=ks,
        transport=transporte, tenant="voce", scan_id="scan-demo", audit=audit,
        clock=lambda: 0.0, active_confirmed=True,
    )
    orig = egress._request
    egress._request = lambda u, i, s, h, at=None: orig(u, i, s, h, NOW)

    print("== Demonstração da Fase 2 — confirmação ativa (opt-in) ==\n")
    print("Alvo de treino (simulado), dois tenants com dados DECOY (falsos).")
    print("Teto de intensidade: ATIVO · confirmação por scan: SIM\n")

    confirmador = ActiveConfirmer(egress)
    print("Teste: a identidade A (baixo privilégio) consegue ler o pedido 1002,")
    print("que pertence ao tenant B?\n")

    resultado = confirmador.confirm_bola(
        url_for_object_b="https://treino.example.com/api/orders/1002",
        identity_a_token="token-da-identidade-A",
        decoy_marker_b=DECOY_B,
    )

    if resultado.confirmed:
        b = resultado.boundary
        print("  🔴 CONFIRMADO — limite sensível ALCANÇÁVEL (não explorado)")
        print(f"     tipo de limite : {b.kind.value}")
        print(f"     narrativa      : {resultado.narrative}")
        print(f"     prova mínima   : {b.evidence}")
        print(f"     estado         : {b.to_dict()['status']}")
    else:
        print(f"  🟢 NÃO confirmado — {resultado.narrative}")

    print(f"\n  >> O engine fez exatamente {len(pedidos)} requisição e PAROU.")
    print("     Não houve enumeração, não puxou o dado, não exfiltrou.")

    ok, _ = audit.verify()
    print(f"\nAuditoria: {'ÍNTEGRA' if ok else 'QUEBRADA'} ({len(audit)} registros)")
    print("\nObservação: 'parar no limite' é o que torna a plataforma segura para")
    print("uso autorizado — ela prova o risco sem realizar o dano.")


if __name__ == "__main__":
    main()
