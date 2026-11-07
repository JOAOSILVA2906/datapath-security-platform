"""Demonstração da Fase 1 (recon seguro + detecção + relatório).

Roda OFFLINE contra um alvo de treino SIMULADO (deliberadamente mal
configurado), passando por todo o portão da Fase 0. Nenhuma rede é usada.

    python -m datapath.demo_fase1

Para apontar a um alvo de treino REAL na sua máquina (ex.: OWASP Juice Shop em
http://localhost:3000), veja as instruções no final da saída.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from datapath.core import (
    AllowList, Asset, AssetKind, AuditLog, Intensity, KillSwitch,
    PolicyEngine, RateLimiter, Scope, TestWindow,
)
from datapath.core.grant import AuthorizationGrant, ProofMethod
from datapath.scan import GatedEgress, HttpResponse, Recon, build_report, to_json

KEY = b"demo-fase1-key"
NOW = datetime.now(timezone.utc)

# Alvo de treino simulado: uma pequena app com vários problemas de configuração.
PAGINAS = {
    "https://treino.example.com/": HttpResponse(
        200,
        {"Content-Type": "text/html", "Server": "nginx/1.18.0",
         "X-Powered-By": "PHP/7.4.3", "Set-Cookie": "session=abc; Path=/"},
        b'<html><body><a href="/login">Entrar</a>'
        b'<script>fetch("/api/v2/users?id=1")</script></body></html>',
        0.05, "https://treino.example.com/"),
    "https://treino.example.com/login": HttpResponse(
        200, {"Content-Type": "text/html"},
        b"<html>Fatal error: Uncaught PDOException: SQLSTATE[42000] syntax</html>",
        0.04, "https://treino.example.com/login"),
    "https://treino.example.com/api/v2/users?id=1": HttpResponse(
        200,
        {"Content-Type": "application/json",
         "Access-Control-Allow-Origin": "*",
         "Access-Control-Allow-Credentials": "true"},
        b'{"id":1,"nome":"exemplo"}',
        0.03, "https://treino.example.com/api/v2/users?id=1"),
}


def main() -> None:
    scope = Scope(
        scope_id="treino", version=1,
        assets=(Asset(AssetKind.URL_PREFIX, "https://treino.example.com/"),),
        windows=(TestWindow(NOW - timedelta(hours=1), NOW + timedelta(hours=1)),),
        intensity_ceiling=Intensity.SAFE,
    )
    grant = AuthorizationGrant(
        grant_id="g1", method=ProofMethod.DOMAIN_TOKEN,
        scope_id="treino", scope_version=1,
        authorizing_identity="voce@treino.example.com",
        verifier_evidence="treino.example.com",
        not_before=NOW - timedelta(days=1), not_after=NOW + timedelta(days=1),
        max_intensity=Intensity.SAFE,
    ).signed(KEY)

    ks = KillSwitch(); ks.register("scan-demo", at=NOW)
    audit = AuditLog()
    policy = PolicyEngine(KEY, ks, audit)

    def transporte(target, headers):
        return PAGINAS.get(target.url, HttpResponse(404, {}, b"", 0.01, target.url))

    egress = GatedEgress(
        scope=scope, grant=grant, signing_key=KEY,
        allowlist=AllowList(scope, lambda h: {"treino.example.com": ["93.184.216.34"]}.get(h, [])),
        policy=policy, rate_limiter=RateLimiter(), kill_switch=ks,
        transport=transporte, tenant="voce", scan_id="scan-demo", audit=audit,
        clock=lambda: 0.0,
    )
    orig = egress.get
    egress.get = lambda url, at=None: orig(url, at=NOW)  # horário fixo na demo

    print("== Demonstração da Fase 1 — recon seguro + detecção ==\n")
    print("Alvo de treino (simulado): https://treino.example.com/")
    print("Modo: SEGURO / passivo — só leitura, tudo pelo portão da Fase 0.\n")

    resultado = Recon(egress, max_pages=10).run(["https://treino.example.com/"])
    relatorio = build_report(scope.ref, "scan-demo", resultado, generated_at=NOW)

    print(f"Páginas visitadas: {resultado.pages_fetched}")
    g = resultado.graph.summary()
    print(f"Grafo de caminho-de-dados: {g['node_count']} nós, {g['edge_count']} ligações "
          f"({g['nodes_by_kind']})\n")

    print(f"Achados ({relatorio['summary']['total_findings']}), do mais grave ao menos grave:\n")
    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "none": "⚪"}
    for f in relatorio["findings"]:
        print(f"  {emoji.get(f['severity'],'•')} [{f['severity'].upper():8}] "
              f"CVSS {f['cvss_score']:<4} {f['title']}")
        print(f"       {f['owasp']}")
        print(f"       onde: {f['affected_url']}")
        print(f"       correção: {f['fix']}\n")

    ok, _ = audit.verify()
    print(f"Auditoria: {'ÍNTEGRA' if ok else 'QUEBRADA'} "
          f"({len(audit)} registros de sondagem gravados)\n")

    print("-" * 68)
    print("Para rodar contra um alvo de treino REAL na sua máquina:")
    print("  1. Suba o OWASP Juice Shop (ex.: em http://localhost:3000).")
    print("  2. No escopo, inclua o host E a faixa de loopback como ativo interno:")
    print("       Asset(AssetKind.URL_PREFIX, 'http://localhost:3000/')")
    print("       Asset(AssetKind.CIDR, '127.0.0.1/32')")
    print("  3. Troque o transporte simulado pelo real:")
    print("       from datapath.scan.transport import urllib_transport")
    print("       transport=urllib_transport()")
    print("  Tudo o mais continua igual — e o portão segue recusando o que estiver")
    print("  fora do escopo.")


if __name__ == "__main__":
    main()
