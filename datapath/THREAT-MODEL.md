# Modelo de Ameaças da Plataforma DataPath

*Correção #7 da revisão. Escopo: a segurança da própria plataforma DataPath, e
não dos alvos que ela avalia. Documento companheiro do código da Fase 0 em
`datapath/core`.*

A plataforma é, ela mesma, um alvo de alto valor: guarda credenciais de teste de
muitos clientes, armazena o mapa de como cada cliente chega aos seus dados, e
controla uma frota que pode enviar tráfego aos ativos desses clientes. Um
comprometimento aqui é o comprometimento de todos os clientes de uma vez. Este
documento lista os ativos, os adversários, as ameaças (STRIDE) e os controles —
marcando o que já está na Fase 0 e o que ainda falta.

## 1. Ativos a proteger

| Ativo | Por que importa |
|---|---|
| Credenciais de teste dos clientes | Acesso direto aos sistemas do cliente se vazarem. |
| Grafos de escopo / caminho-de-dados | Um mapa de como chegar aos dados de cada cliente. |
| Autorizações e chaves de assinatura | Forjar uma autoriza testes não autorizados. |
| Allow-lists e regras de política | Afrouxar uma aponta a frota a ativos fora de escopo. |
| Log de auditoria | Sua integridade é a defesa legal da plataforma. |
| Frota de egress | Poderia ser abusada como proxy de ataque contra terceiros. |

## 2. Adversários

- **Operador malicioso ou comprometido (ameaça interna).** Ameaça principal.
  Tem algum acesso legítimo e quer ampliar o escopo, exfiltrar credenciais, ou
  apontar a frota para um alvo que não é dele.
- **Cliente malicioso.** Tenta mirar a plataforma em ativos que não controla (um
  concorrente, um host compartilhado) forjando a autorização.
- **Atacante externo.** Mira a infraestrutura/APIs da própria plataforma para
  roubar os ativos acima.
- **Adversário da cadeia de suprimento.** Entrega um plugin de check malicioso
  ou um template de scanner (ex.: um template Nuclei marcado como
  `intrusive`/`dos`).

## 3. Ameaças e controles (STRIDE)

### Spoofing (falsificação de identidade)
- *Autorização forjada.* → Autorizações são assinadas com HMAC e vinculadas a
  uma versão de escopo; `AuthorizationGrant.signature_valid` / `is_valid_for`.
  **(Fase 0)**
- *Cliente alega ativos que não possui.* → Verificação de dono: checagens de
  CNAME/ASN, exclusão de terceiros/CDN; `OwnershipVerifier`. **(Fase 0)**

### Tampering (adulteração)
- *Edições no log para esconder atividade.* → Log em cadeia de hashes, só
  acréscimo; `AuditLog.verify` localiza o primeiro registro quebrado. **(Fase 0)**
- *Adulteração do armazenamento de segredos.* → Blobs selados têm integridade
  verificada ao abrir; `CredentialVault` / checagem de tag do sealer. **(Fase 0)**

### Repudiation (repúdio)
- *"Nunca autorizamos / rodamos isso."* → Toda decisão de política e evento de
  autorização é escrito no log encadeado com referência de escopo, id da
  autorização, alvo e modo. **(Fase 0)**

### Information disclosure (vazamento de informação)
- *Vazamento de credencial via logs.* → O cofre nunca devolve segredos para
  logs; só um fingerprint salgado é registrável; segredos excluídos do `repr`.
  O log de auditoria recusa payloads que pareçam corpos. **(Fase 0)**
- *Dados pessoais em evidência/auditoria.* → A auditoria guarda só metadados +
  hashes; os corpos das evidências ficam num armazenamento separado, apagável e
  criptografado (direito de exclusão da GDPR). **(Fase 0 para a auditoria; o
  armazenamento de evidências é de uma fase posterior.)**

### Denial of service (negação de serviço)
- *Frota abusada para inundar um alvo, ou um tenant sufoca a frota.* → Limites de
  taxa por alvo, budgets por tenant, backoff adaptativo (spec 1.5). **(Fase 0)**

### Elevation of privilege (elevação de privilégio)
- *Um operador amplia escopo/política sozinho.* → Controle por duas pessoas em
  mudanças sensíveis (adicionar à allow-list, afrouxar política, subir
  intensidade, sobrepor veredito de dono); `DualControl` recusa auto-aprovação e
  aprovações duplicadas. **(Fase 0)**
- *Serviço de política indisponível → libera.* → O motor de política falha
  **fechado**: qualquer erro ou entrada faltando resulta em NEGADO;
  `PolicyEngine.evaluate`. **(Fase 0)**

## 4. Botão de parada sobre trabalho em andamento

O botão de parada é autoritativo sobre o trabalho já em andamento, não só sobre
a fila. O gateway de egress precisa chamar `KillSwitch.scan_may_probe` (ou o
motor de política, que o chama primeiro) **imediatamente antes de cada
conexão**. Assim, uma parada global ou um abort de um scan nega a próxima
requisição de um scan que estava no meio do processo — a requisição já planejada
não se completa. A perda do heartbeat pausa o scan da mesma forma (dead-man's
switch). **(Fase 0)**

## 5. Regras de manuseio de credenciais (impostas pelo `CredentialVault`)

1. Segredos são selados em repouso por um sealer injetado (apoiado em KMS/HSM). O
   `_DevSealer` embutido é rotulado como só-para-dev e não pode ir a produção.
2. Segredos são **emprestados por scan** com TTL curto, nunca entregues inteiros.
3. Empréstimos são revogados no fim/abort do scan (`revoke_scan`) e na rotação.
4. A rotação invalida todo empréstimo pendente daquela credencial.
5. Só um fingerprint salgado de um segredo pode ser registrado em log.

## 6. Ainda falta (não está na Fase 0)

- Vetação de plugins/templates em produção (revisão #9): já há o `TemplateVetter`
  no núcleo; falta ligá-lo ao pipeline real de ingestão do feed.
- Criptografia de envelope real / integração com KMS por trás da interface
  `Sealer`.
- Isolamento por tenant e criptografia em repouso dos armazenamentos de grafo e
  de evidências.
- Pentest de terceiros + SOC 2 / ISO 27001 da plataforma (Fase 5 da spec).
