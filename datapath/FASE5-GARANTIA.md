# Fase 5 — Escala e Garantia

*Diferente das Fases 0–4, a Fase 5 é majoritariamente organizacional e
operacional, não código. Este documento é o plano e a lista de verificação.
Onde há um gancho no código, ele é apontado.*

A Fase 5 prepara a plataforma para operar com muitos clientes em produção, com
garantias externas. Nada aqui afrouxa o portão da Fase 0 — tudo o endurece.

## 1. Endurecimento multi-tenant

- **Isolamento por tenant**: chaves de criptografia por tenant; armazenamento
  de grafo e evidências segregado logicamente; nenhuma consulta cruza tenants.
  *Gancho:* o `CredentialVault` já sela por credencial; estender para derivar
  chave por tenant.
- **Negação por padrão entre tenants** no plano de dados, não só no de
  aplicação.
- **Budgets por tenant** já existem (`RateLimiter.set_tenant_budget`); ligar a
  cotas comerciais.
- **Registro de acesso a evidências/logs** já é least-privilege (spec 1.8);
  auditar o acesso de operadores (controle de quatro olhos já disponível em
  `DualControl`).

## 2. Auditoria de terceiros da própria plataforma

- **Pentest independente** da plataforma (não dos alvos), anual e a cada
  mudança de arquitetura relevante.
- **Programa de divulgação de vulnerabilidades** da plataforma (o cabeçalho de
  atribuição já aponta para uma página de abuso/contato).
- **Revisão de modelo de ameaças** (ver [THREAT-MODEL.md](THREAT-MODEL.md)) a
  cada release maior.

## 3. Certificações

- **SOC 2 Tipo II** — controles de segurança, disponibilidade e
  confidencialidade ao longo de um período.
- **ISO/IEC 27001** — sistema de gestão de segurança da informação.
- **Mapeamento de controles**: ligar cada controle da Fase 0 (política,
  auditoria encadeada, kill switch, quatro olhos, cofre) ao critério
  correspondente, para evidência de auditoria.

## 4. Monitoramento contínuo (oferta recorrente)

- Reteste agendado do escopo autorizado (com re-verificação da autorização a
  cada execução — a autorização expira e é re-checada, spec 1.2).
- Alerta quando um achado antes corrigido **reaparece** (regressão) — a Fase 4
  já calcula classes recorrentes e tendência (`posture.py`).
- Painéis de postura por cliente ao longo do tempo (dados da `posture_summary`).

## 5. Conformidade legal contínua (resumo da seção 8.2 da spec)

- Artefatos de autorização assinados e vinculados a cada varredura na auditoria;
  re-verificação em tempo de execução. *Já imposto no núcleo.*
- Proteção de dados (GDPR/CCPA): minimização e mascaramento de dados pessoais em
  evidência; retenção/exclusão definidas; evidência em região quando exigido.
  *A auditoria já não guarda corpos; o cofre sela segredos.*
- Triagem de sanções/exportação de clientes e alvos; KYC antes de liberar o modo
  ativo.
- Resposta a incidentes: processo definido se uma varredura causar impacto
  inesperado — kill switch imediato, notificação ao cliente, causa-raiz,
  divulgação do log de auditoria.

## 6. Critérios de saída da Fase 5

- [ ] Pentest de terceiros sem achados críticos em aberto.
- [ ] SOC 2 Tipo II emitido.
- [ ] Isolamento multi-tenant verificado por teste (nenhuma leitura cruza
      tenants, mesmo sob falha).
- [ ] Monitoramento contínuo com re-verificação de autorização em produção.
- [ ] Runbook de resposta a incidentes exercitado ao menos uma vez.
