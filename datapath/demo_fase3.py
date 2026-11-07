"""Demonstração da Fase 3 — encadeamento de caminhos de ataque.

Mostra o planejador compondo achados individuais (como capacidades) numa cadeia
realista até o dado sensível, priorizada por alcançabilidade, e PARANDO no
primeiro limite sensível.

    python -m datapath.demo_fase3
"""

from __future__ import annotations

from datapath.chain import (
    START_ANONYMOUS, AttackPathPlanner, Capability,
    capability_from_bola, enumeration_capability, recon_capability,
)
from datapath.confirm import BoundaryKind, BoundaryProof, Confirmation


def main() -> None:
    # Um BOLA confirmado na Fase 2 (identidade A alcançou o objeto do tenant B).
    bola = Confirmation(
        confirmed=True, narrative="",
        boundary=BoundaryProof(BoundaryKind.CROSS_TENANT_READ,
                               "marcador de decoy do tenant B presente; 1 registro"),
        http_status=200,
    )

    capacidades = [
        recon_capability(),                         # anônimo -> endpoints mapeados
        enumeration_capability(0.8),                # -> id de objeto adivinhável
        capability_from_bola(bola,                  # -> leitura entre tenants (LIMITE)
                             requires={"anonymous", "object_id_known"}),
        # Um achado "solto" que NÃO leva a dado: CORS num endpoint sem objeto sensível.
        Capability("cors-sem-caminho",
                   "CORS permissivo num endpoint sem dado sensível alcançável",
                   requires={"anonymous"}, grants={"cross_origin_read_isolado"},
                   reachability=0.7, impact=10, owasp="A05:2021"),
    ]

    print("== Demonstração da Fase 3 — encadeamento de caminhos de ataque ==\n")
    print("Capacidades (achados modelados como passos):")
    for c in capacidades:
        req = ", ".join(sorted(c.requires)) or "—"
        grant = ", ".join(sorted(c.grants))
        print(f"  · {c.cap_id:26} requer[{req}]  concede[{grant}]  "
              f"alcance={c.reachability}")
    print()

    planejador = AttackPathPlanner(capacidades, START_ANONYMOUS)
    caminhos = planejador.plan()

    print(f"Caminhos de ataque encontrados: {len(caminhos)} "
          f"(ordenados por risco ponderado por alcançabilidade)\n")

    for i, p in enumerate(caminhos, 1):
        print(f"CAMINHO {i} — score {p.score:.1f}  "
              f"(alcançabilidade {p.reachability:.2f} × impacto {p.impact})")
        for linha in p.narrative():
            print("   " + linha)
        print()

    print("Observação: o achado de CORS 'solto' NÃO virou caminho — ele não está")
    print("numa rota até dado sensível. É a priorização por alcançabilidade (5.3):")
    print("foca no que importa e reduz falso-positivo.")


if __name__ == "__main__":
    main()
