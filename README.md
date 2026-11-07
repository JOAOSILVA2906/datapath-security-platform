# DataPath — Plataforma de Avaliação de Segurança Baseada em Consentimento

> Uma plataforma que só testa sistemas com **autorização comprovada**, mapeia como a aplicação chega aos dados, confirma o risco com segurança e **para no primeiro limite sensível** — provando o risco sem causar o dano.

**Linguagem:** Python 3 (apenas biblioteca padrão, sem dependências) · **Testes:** 108 passando · **Licença:** MIT

---

## A ideia

A maioria dos scanners de segurança assume que você já tem permissão para testar. O DataPath inverte isso: **a autorização é o portão, e vem antes de tudo**. Nenhuma varredura é criada, enfileirada ou executada sem uma autorização ativa e verificada que cubra exatamente o alvo e a intensidade pedidos. Isso é imposto no código, em cada camada — não por política.

O segundo princípio é **parar no limite sensível**: ao chegar ao ponto onde o próximo passo leria dado real de outro usuário, cruzaria o isolamento entre clientes ou mudaria estado, o engine **para**, captura uma prova mínima mascarada de que o limite era *alcançável*, e marca `confirmado-alcançável, não-explorado`. Ele prova o risco sem realizá-lo.

> ⚠️ **Projeto educativo.** É um protótipo funcional e testado, construído para demonstrar a arquitetura correta de uma ferramenta de segurança autorizada. Não é um serviço em produção. Só use contra alvos que você possui ou foi autorizado a testar (ex.: [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) local).

## As seis fases

| Fase | O que faz | Pacote |
|------|-----------|--------|
| **0 — Autorização e segurança** | O portão. Nega por padrão, falha fechado. Escopo versionado, autorização assinada, allow-list anti-SSRF, auditoria encadeada, botão de parada, verificação de dono, controle de quatro olhos, cofre de credenciais, rate-limit, vetação de templates. | `datapath/core` |
| **1 — Recon + detecção + relatório** | Mapeamento passivo (só leitura) pelo portão, grafo de caminho-de-dados, detectores de configuração insegura, achados com CVSS v3.1 e correção. | `datapath/scan` |
| **2 — Confirmação ativa (opt-in)** | Confirma BOLA e privilégio vertical com uma requisição só-leitura contra dados falsos (decoy); o corpo é descartado no portão; para no limite. | `datapath/confirm` |
| **3 — Encadeamento de caminhos** | Compõe achados em caminhos de ataque realistas até o dado, priorizados por alcançabilidade. | `datapath/chain` |
| **4 — Ciclo de correção** | Tickets GitHub/Jira, export SARIF, reteste de um clique com atestado "corrigido" assinado, postura/tendência, notificações Slack. | `datapath/remediate` |
| **5 — Escala e garantia** | Plano organizacional: multi-tenant, pentest da plataforma, SOC 2 / ISO 27001, monitoramento contínuo. | `FASE5-GARANTIA.md` |

## Decisões de segurança que valem destacar

- **Taxonomia de efeito colateral** (passivo / payload-benigno / potencialmente-mutável) no lugar de "só-leitura == seguro". O nível mutável é recusado em qualquer intensidade.
- **A política falha fechado**: qualquer erro ou entrada faltando resulta em NEGADO.
- **Resolve-e-fixa (anti-SSRF / anti-DNS-rebinding)**: resolve o host, valida cada IP, e exige conexão ao IP fixado.
- **Auditoria não guarda corpos** — só metadados e hashes, para não puxar dado pessoal para um log que não dá para apagar (GDPR).
- **O corpo da resposta é descartado no portão** nos testes de limite — impossível exfiltrar.
- **Prova por documento não libera modo ativo** — modo ativo exige prova técnica (controle de domínio, bug bounty ou conta de nuvem).

## Como rodar

Requer Python 3.11+ (sem instalar nada além).

```bash
# Testes (108)
python -m unittest discover -s datapath/tests -t . -v

# Demonstrações (offline, contra alvos de treino simulados)
python -m datapath.demo         # a portaria: aceita 1 pedido, barra 4
python -m datapath.demo_fase1   # recon + detecção (16 achados)
python -m datapath.demo_fase2   # confirmação ativa, parada no limite
python -m datapath.demo_fase3   # encadeia anônimo -> enumerar IDs -> BOLA
python -m datapath.demo_fase4   # tickets, SARIF, reteste, postura, Slack
```

## Estrutura

```
datapath/
  core/        Fase 0 — autorização e segurança (o portão)
  scan/        Fase 1 — recon, detecção, relatório, egress com portão
  confirm/     Fase 2 — confirmação ativa + parada no limite
  chain/       Fase 3 — encadeamento de caminhos de ataque
  remediate/   Fase 4 — ciclo de correção
  tests/       108 testes (unittest)
  demo*.py     seis demonstrações rodáveis
  README.md            detalhes técnicos por módulo
  THREAT-MODEL.md      modelo de ameaças da própria plataforma
  FASE5-GARANTIA.md    plano da Fase 5
datapath-security-platform-spec.md   especificação v0.1 completa
```

## Documentos

- [Especificação completa (v0.1)](datapath-security-platform-spec.md)
- [Detalhes técnicos por módulo](datapath/README.md)
- [Modelo de ameaças da plataforma](datapath/THREAT-MODEL.md)
- [Plano da Fase 5 — escala e garantia](datapath/FASE5-GARANTIA.md)

## Licença

MIT — veja [LICENSE](LICENSE).
