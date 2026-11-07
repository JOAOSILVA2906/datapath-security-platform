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

## Ainda não construído (fases seguintes)

A implementação de rede do proxy de egress, as checagens de dono via
DNS/CNAME/ASN em produção (revisão #5), o cofre de segredos real por trás da
interface `Sealer` (revisão #7), e tudo das Fases 1–5 (recon, sondagem,
encadeamento, remediação).

---

*Observação sobre o idioma: os nomes de funções, classes e variáveis estão em
inglês (padrão de mercado em código), mas a documentação e a saída da
demonstração estão em português.*
