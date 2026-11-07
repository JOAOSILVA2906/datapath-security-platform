# DataPath — Fase 0: Núcleo de Autorização e Segurança

Este pacote é a **Fase 0** do roadmap do DataPath: o portão de autorização ao
qual toda capacidade posterior está subordinada. Ele **não contém nenhum código
de sondagem, varredura ou rede** — apenas a lógica que decide se uma sondagem
*seria* permitida, e que recusa por padrão.

> Conforme a especificação: *"Nenhuma capacidade de sondagem entra em produção
> até isto estar sólido e testado."*

## O que tem aqui

| Módulo | Seção da spec | Responsabilidade |
|---|---|---|
| `core/intensity.py` | 1.4 | Níveis de intensidade + a taxonomia de efeito colateral (passivo / payload-benigno / potencialmente-mutável). |
| `core/scope.py` | 1.1 | `Scope` versionado e imutável; ativos, exclusões (exclusão sempre vence), janelas de tempo, teto de intensidade. |
| `core/grant.py` | 1.2 | `AuthorizationGrant` com assinatura HMAC, expiração, vínculo ao escopo, checagem de curinga/domínio-pai. |
| `core/allowlist.py` | 1.3 | Resolução de alvo "resolve-e-fixa"; bloqueio SSRF; defesa contra DNS rebinding. |
| `core/policy.py` | 2.2 | O ponto único de decisão. **Nega por padrão, falha fechado.** |
| `core/audit.py` | 1.8 | Log de auditoria só-acréscimo, em cadeia de hashes (apenas metadados + hashes — sem corpos). |
| `core/killswitch.py` | 1.7 | Botão de parada global, abortar por scan, heartbeat (dead-man's switch). |
| `core/ownership.py` | 1.6 / revisão #5 | Classifica ativos em DONO / TERCEIRO / NÃO-VERIFICADO via CNAME + ASN/RDAP. |
| `core/dualcontrol.py` | revisão #7 | Aprovação por duas pessoas para mudanças sensíveis (allow-list / política). |
| `core/vault.py` | revisão #7 | Empréstimo de credenciais efêmeras por scan; seladas em repouso; rotação. |
| `core/ratelimit.py` | 1.5 | Taxa/concorrência por alvo, budgets por tenant e global, backpressure adaptativo. |
| `core/templates.py` | §7 / revisão #9 | Vetar templates de scanner (supply-chain): fixados por hash, tag→efeito, bloqueia não-mapeados/proibidos. |

Veja também o [THREAT-MODEL.md](THREAT-MODEL.md) — o modelo de ameaças da própria plataforma.

## Decisões de projeto trazidas da revisão da spec (correções da v0.2)

- **Taxonomia de efeito colateral** substitui "só-leitura == seguro". O nível
  `POTENTIALLY_MUTATING` (potencialmente mutável) é recusado em todos os níveis
  de intensidade por este núcleo.
- **Prova por documento não libera modo ATIVO** — ATIVO exige uma prova técnica
  (controle de domínio/host, vínculo com programa de bug bounty, ou vínculo com
  a conta de nuvem).
- **A política falha fechada**: qualquer erro ou entrada faltando resulta em
  NEGADO.
- **Resolve-e-fixa**: quem chama precisa conectar no IP fixado; um DNS rebinding
  entre a validação e a conexão não tem efeito.
- **O log de auditoria não guarda corpos** — evita puxar dados pessoais para um
  armazenamento que não dá para apagar (direito de exclusão da GDPR). Os corpos
  das evidências ficam no armazenamento de evidências separado.

## Rodar os testes

```
python -m unittest discover -s datapath/tests -t . -v
```

A suíte inclui os testes de aceitação da Fase 0: um host não verificado, um IP
sofrendo DNS rebinding, um endereço de metadados de nuvem, uma faixa privada e
um alvo de redirecionamento fora do escopo são cada um recusados — e as negações
de política são escritas na cadeia de auditoria, que o `verify()` confirma estar
íntegra.

## Rodar a demonstração

```
python -m datapath.demo
```

## Fase 1 — recon seguro + detecção + relatório

O pacote `datapath/scan` faz o mapeamento de superfície passivo, a detecção
(só-leitura) e o relatório. **Toda requisição passa pelo portão da Fase 0**: a
`GatedEgress` só envia um GET depois que a política (nega por padrão) e a
allow-list (resolve-e-fixa, anti-SSRF) aprovam, limitado pelo rate-limiter e
pelo botão de parada. É só modo SEGURO/PASSIVO — nada de entrada manipulada nem
exploração.

| Módulo | Seção da spec | Responsabilidade |
|---|---|---|
| `scan/egress.py` | 1.3 / 2.2 | Egress HTTP com portão: política + allow-list + rate-limit + auditoria antes de cada requisição. Transporte injetado. |
| `scan/graph.py` | 3.2 | O grafo de caminho-de-dados (páginas, APIs, parâmetros, lojas de dados). |
| `scan/recon.py` | 3.1 | Mapeamento passivo: visita páginas em escopo, extrai links/APIs, roda os detectores. |
| `scan/detectors.py` | 4 | Detectores passivos: cabeçalhos de segurança, CORS, erros detalhados, listagem de diretório, cookies, fingerprint. |
| `scan/findings.py` | 6.1 | Modelo de achado + cálculo correto de CVSS v3.1. |
| `scan/ingest.py` | 3.3 | Ingestão de OpenAPI (contexto do cliente) para o grafo. |
| `scan/report.py` | 6.3 | Relatório em JSON, ordenado por severidade. |
| `scan/transport.py` | — | O único ponto que toca a rede de verdade; conduzido só pela `GatedEgress`. |

Demonstração da Fase 1 (offline, contra um alvo de treino simulado):

```
python -m datapath.demo_fase1
```

## Fase 2 — confirmação ativa (opt-in) com parada no limite sensível

O pacote `datapath/confirm` faz a confirmação ativa das classes de maior valor
(BOLA / quebra de controle de acesso, privilégio vertical). É **opt-in**: exige
que o escopo e a autorização permitam o modo ATIVO **e** uma confirmação por
scan. Cada confirmador envia **uma** requisição só-leitura e **para no primeiro
limite sensível** (spec 5.2): captura uma prova mínima mascarada de que o limite
era *alcançável*, marca `confirmado-alcançável, não-explorado`, e **não puxa o
dado**. Trabalha contra tenants de teste com dados DECOY (falsos), e o corpo da
resposta é **descartado no portão** — impossível exfiltrar.

| Módulo | Seção da spec | Responsabilidade |
|---|---|---|
| `confirm/boundary.py` | 5.2 | O modelo de limite sensível e a prova mínima mascarada (invariante: nunca explorado). |
| `confirm/active.py` | 4 / Fase 2 | Confirmadores ativos: BOLA entre tenants e privilégio vertical. |

Demonstração da Fase 2 (offline):

```
python -m datapath.demo_fase2
```

## Fase 3 — encadeamento de caminhos de ataque

O pacote `datapath/chain` compõe achados individuais (modelados como
*capacidades* com pré e pós-condições) em caminhos de ataque realistas até o
dado sensível. O planejador faz uma busca a partir do privilégio inicial
(ex.: anônimo) e **prioriza por alcançabilidade** (spec 5.3): o score é o
produto das alcançabilidades dos passos vezes o impacto, então o relatório é
guiado por quão realmente alcançável é o dado — não pela mera presença de
achados. Cada caminho **termina no primeiro limite sensível**.

| Módulo | Seção da spec | Responsabilidade |
|---|---|---|
| `chain/capability.py` | 5.1 | Achados como capacidades (requer/concede estado); fábricas a partir de confirmações. |
| `chain/planner.py` | 5.1 / 5.3 | Busca e ranqueia caminhos; para no limite; narrativa + evidência por passo. |

Demonstração da Fase 3 (offline) — monta `anônimo → enumerar IDs → BOLA →
registro de outro tenant`:

```
python -m datapath.demo_fase3
```

## Ainda não construído (fases seguintes)

A implementação de rede do proxy de egress, as checagens de dono via
DNS/CNAME/ASN em produção (revisão #5), o cofre de segredos real por trás da
interface `Sealer` (revisão #7), e tudo das Fases 1–5 (recon, sondagem,
encadeamento, remediação).

---

*Observação sobre o idioma: os nomes de funções, classes e variáveis estão em
inglês (padrão de mercado em código), mas a documentação e a saída da
demonstração estão em português.*
