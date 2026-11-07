"""Demonstração da Fase 4 — ciclo de correção.

Pega um achado, gera um ticket (GitHub/Jira), exporta SARIF, faz o reteste de um
clique com atestado assinado de "corrigido", mostra a postura ao longo de
varreduras e monta a notificação de Slack. Tudo offline.

    python -m datapath.demo_fase4
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from datapath.scan.findings import Finding
from datapath.remediate import (
    Notifier, Retester, ScanRecord, build_slack_message, posture_summary,
    to_github_issue, to_sarif,
)

KEY = b"demo-fase4"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def main() -> None:
    achado = Finding(
        check_id="cors-wildcard-credentials",
        title="CORS permissivo com credenciais",
        owasp="A05:2021 Security Misconfiguration",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        affected_url="https://treino.example.com/api/v2/users?id=1",
        evidence="Access-Control-Allow-Origin: * com Allow-Credentials: true.",
        fix="Nunca combine origem curinga com credenciais; use allow-list de origens.",
    )

    print("== Demonstração da Fase 4 — ciclo de correção ==\n")

    print("1) Ticket para o GitHub:")
    iss = to_github_issue(achado)
    print(f"   título: {iss['title']}")
    print(f"   labels: {iss['labels']}\n")

    print("2) Export SARIF (para code scanning / IDE):")
    sarif = to_sarif([achado])
    r = sarif["runs"][0]["results"][0]
    print(f"   ruleId={r['ruleId']} level={r['level']} "
          f"security-severity={r['properties']['security-severity']}\n")

    print("3) Reteste de um clique + atestado assinado:")
    rt = Retester(KEY)
    # Simulamos que o cliente corrigiu: a verificação não dispara mais.
    att = rt.retest(achado.check_id, achado.affected_url, "treino@v1",
                    "reteste-001", runner=lambda: False, at=NOW)
    print(f"   resultado: {att.result.value.upper()}")
    print(f"   assinatura válida: {att.signature_valid(KEY)}")
    print(f"   cobertura: {att.coverage}\n")

    print("4) Postura ao longo de 3 varreduras:")
    f = (achado.check_id, achado.affected_url)
    g = ("missing-hsts", "https://treino.example.com/")
    scans = [
        ScanRecord("v1", NOW, {f, g}),
        ScanRecord("v2", NOW + timedelta(days=12), {g}),   # CORS corrigido
        ScanRecord("v3", NOW + timedelta(days=30), set()), # HSTS corrigido
    ]
    s = posture_summary(scans)
    print(f"   varreduras: {s['scans']}  resolvidos: {s['resolved_count']}  "
          f"tempo médio p/ corrigir: {s['avg_days_to_remediate']} dias")
    print(f"   tendência de abertos: {s['open_trend']}")
    print(f"   classes recorrentes: {s['recurring_classes']}\n")

    print("5) Notificação de Slack:")
    enviados = []
    Notifier(lambda p: enviados.append(p)).notify(
        build_slack_message("treino@v1",
                            {"total_findings": 16,
                             "by_severity": {"high": 1, "medium": 12, "low": 3}},
                            top_path="anônimo → enumerar IDs → BOLA → tenant B")
    )
    print(f"   payload enviado: {enviados[0]['text']}")
    print(f"   blocos: {len(enviados[0]['blocks'])}")


if __name__ == "__main__":
    main()
