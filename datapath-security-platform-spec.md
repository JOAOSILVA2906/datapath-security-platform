# DataPath — Consent-Based Database Security Assessment Platform

**Specification v0.1 — authorized, consented testing only**

A two-sided platform for professional penetration testers and bug-bounty teams. A customer registers a target, proves they are authorized to test it, and the platform maps how the application reaches its backend data store, then safely probes the reachable paths — chaining findings into realistic attack paths and **stopping at the first sensitive boundary**, documenting rather than exfiltrating or destroying. Customers pay to *find* issues and pay again to *fix* them.

The authorization and safety model (Section 1) is the foundation; every other component is gated by it. Nothing in this platform runs against a target that has not cleared the authorization pipeline.

---

## 1. Authorization & Safety Model (the foundation)

Everything else is subordinate to this. A scan cannot be created, queued, or executed unless an **active, verified authorization grant** covers the exact assets and test intensity requested. This is enforced in code at every layer, not by policy alone.

### 1.1 Scope definition

Scope is a first-class, versioned object — not free text. A scope record contains:

- **Asset list**: explicit FQDNs, IP ranges (CIDR), URL path prefixes, API base paths, and mobile/app backend hosts. Wildcards (`*.example.com`) are allowed only when the authorization proof covers the parent domain.
- **Exclusions**: hosts, paths, parameters, and endpoints that must never be touched (e.g. `/admin/delete`, payment callbacks, third-party SSO). Exclusions always win over inclusions.
- **Test window**: allowed date/time ranges and timezone. Out-of-window scans are refused.
- **Intensity ceiling**: the maximum test mode permitted (`safe` vs `active` — see 1.4).
- **Data-handling rules**: whether evidence may contain response snippets, and redaction requirements (PII masking on capture).
- **Contacts**: a security/ops escalation contact and a legal/authorizing contact.

Scope is immutable once a scan references it; changes create a new scope version requiring re-authorization.

### 1.2 Proof-of-authorization workflow

No asset is testable until its ownership/authorization is proven. Support multiple proof methods, each producing a signed, timestamped `AuthorizationGrant`:

1. **Domain/host control** (preferred): the authorizing party places a unique platform-issued token at a well-known location — a DNS `TXT` record (`_datapath-verify.example.com`), a file at `/.well-known/datapath-authorization.txt`, or an HTTP response header on the root. The platform verifies it from multiple network vantage points.
2. **Signed engagement document**: an uploaded, countersigned authorization letter / statement of work / rules-of-engagement (RoE), tied to a verified organizational identity (SSO domain match, business email on the apex domain, or manual KYC for high-value targets).
3. **Bug-bounty program linkage**: OAuth linkage to an existing program (e.g. the customer's HackerOne/Bugcrowd/Intigriti program) so the platform inherits that program's published scope and safe-harbor terms.
4. **Delegated authority check**: for agencies testing a client, a two-party grant — the agency's identity plus the asset owner's countersignature — so authority is traceable to the actual asset owner.

Each grant has: issuing method, verifier evidence, authorizing identity, covered scope version, validity window, and a cryptographic signature. Grants **expire** and must be re-verified before each engagement (re-check domain token at scan start, not just at registration — ownership can change).

**Re-verification at execution time**: immediately before a scan starts, the engine re-confirms the proof is still valid (token still present, grant not revoked, within window). If verification fails mid-pipeline, the scan is refused or aborted.

### 1.3 Allow-listing and target resolution

- The engine resolves every candidate target (after DNS resolution and any redirects) against the allow-list **at request time**, not just at discovery time. A redirect or a discovered link that points outside scope is dropped, logged, and never followed.
- **SSRF-safe egress**: the probing engine routes outbound requests through an egress proxy that enforces the allow-list, blocks RFC 1918 / link-local / cloud-metadata ranges (`169.254.169.254`, `fd00:ec2::254`, etc.) unless they are explicitly in-scope internal assets, and prevents DNS-rebinding (resolve-then-pin, re-validate resolved IP against allow-list before connect).
- Every outbound request carries a scan-correlated identifier header (e.g. `X-DataPath-Scan-Id`) and an honest `User-Agent` identifying the platform and linking to an abuse/contact page, so blue teams can recognize and attribute the traffic.

### 1.4 Safe mode vs. authorized active testing

Two intensity tiers, gated by the scope's intensity ceiling:

- **Safe mode (default, non-destructive)**: read-only and observational. Passive recon, surface mapping, auth-flow observation, and *detection-only* checks that infer a vulnerability from behavior without attempting to exploit it destructively (e.g. error-signature analysis, differential responses, header/config inspection, time-based inference bounded to tiny thresholds). No writes, no state mutation, no mass requests. Safe mode is always allowed within scope.
- **Active mode (explicit opt-in)**: confirmation-grade probing that may send crafted inputs to validate a suspected issue — still bounded by hard safety rules below. Active mode requires the scope intensity ceiling to permit it **and** a per-scan confirmation. Certain actions are *never* permitted in either mode (see 1.6).

Both modes obey the **stop-at-boundary** rule (Section 5): the moment a probe reaches a point where it *could* read sensitive data or mutate state, it stops and records the boundary rather than crossing it.

### 1.5 Rate limiting, concurrency, and backpressure

- Per-target request-rate caps and max concurrency, configurable but with conservative defaults and a hard ceiling that customers cannot exceed without elevated approval.
- Adaptive throttling: watch target latency and error rates; back off automatically on 5xx spikes, elevated latency, or WAF challenge responses (treat these as "the target is stressed — slow down").
- Global and per-tenant budgets so one engagement can't starve the fleet.
- Respect `Retry-After`, 429s, and any program-specified rate limits from linked bug-bounty scope.

### 1.6 Hard prohibitions (never, in any mode)

Enforced in the probing engine, not left to operator discretion:

- No data exfiltration — probes retrieve only the **minimum proof** that a boundary was reached (e.g. a single-row count, a masked indicator, a schema name), never bulk records or full sensitive rows.
- No destructive or state-mutating operations (no `DROP`/`DELETE`/`UPDATE`-style actions, no account takeover follow-through, no writing persistent content).
- No denial-of-service, resource-exhaustion, or volumetric testing.
- No persistence (no implants, no stored payloads, no backdoors).
- No pivoting beyond scoped assets; no touching third-party services even if reachable.
- No credential cracking at scale; no phishing or social engineering of real users.
- No CAPTCHA/anti-bot bypass.

### 1.7 Kill switch

- **Global kill switch**: an operator control (and automated triggers) that immediately halts all active scans, drains the queue, and closes egress. Triggered manually, or automatically on: authorization revocation, out-of-window drift, target-health alarms, or anomaly detection (unexpected spike in destructive-looking responses).
- **Per-scan abort**: any authorizing contact can stop their scan instantly; the platform acknowledges within seconds and confirms teardown.
- **Dead-man's switch**: scans require a periodic validity heartbeat (grant still active, within window); loss of heartbeat pauses the scan.

### 1.8 Audit logging (tamper-evident)

- Every action — authorization events, scope changes, each outbound probe (target, intent, mode, timestamp, result class), findings, evidence capture, operator actions, kill-switch events — is written to an append-only, hash-chained audit log.
- Logs are immutable (WORM storage or hash-chained with periodic anchoring), retained per the engagement's legal requirements, and exportable as a defensible record of exactly what was done to whom and when.
- Access to logs and evidence is itself logged and least-privilege. PII in captured evidence is masked at write time.

---

## 2. Architecture

### 2.1 Components

```
                 ┌──────────────────────────────────────────────┐
                 │          Authorization & Policy Core          │
                 │  (scope, grants, allow-list, kill switch,     │
                 │   intensity gating) — consulted by ALL below  │
                 └──────────────────────────────────────────────┘
                                     ▲  (every action checks here)
   ┌──────────┐   ┌──────────────┐   ┌───────────────┐   ┌────────────────┐
   │  Target  │──▶│  Recon /     │──▶│   Probing     │──▶│  Attack-Path    │
   │  Intake  │   │  Surface Map │   │   Engine      │   │  Chaining       │
   └──────────┘   └──────────────┘   └───────────────┘   └────────────────┘
                          │                 │                   │
                          ▼                 ▼                   ▼
                   ┌──────────────────────────────────────────────┐
                   │   Evidence Capture (redacted, hash-sealed)    │
                   └──────────────────────────────────────────────┘
                                          │
                                          ▼
                   ┌──────────────────────────────────────────────┐
                   │   Reporting & Remediation (findings, CVSS,    │
                   │   repro, business impact, fix guidance)       │
                   └──────────────────────────────────────────────┘
```

- **Target intake**: registration, scope builder, authorization proof collection/verification, engagement configuration.
- **Recon / attack-surface mapping**: discovers endpoints, APIs, parameters, auth flows; builds a **data-path graph** (Section 3).
- **Probing engine**: executes mode-gated, policy-checked checks against the mapped surface. Plugin-based (one plugin per check), sandboxed, with per-check safety declarations.
- **Attack-path / chaining module**: a graph reasoner that composes individual findings into realistic paths toward the data store and enforces the stop condition (Section 5).
- **Evidence capture**: records minimal, redacted proof for each finding, hash-sealed and linked into the audit chain.
- **Reporting & remediation**: generates findings with severity, reproduction, impact, and fix guidance; drives the "fix" side (Section 6).

### 2.2 Cross-cutting services

- **Policy engine** (e.g. OPA / Rego or an equivalent decision service): every probe request is a policy query — *is this target, at this intensity, at this time, under this grant, allowed?* Default-deny.
- **Egress gateway**: the only path to the internet for probes; enforces allow-list, SSRF protections, rate limits, and request attribution.
- **Orchestrator**: schedules scans, enforces concurrency/budgets, manages heartbeats and kill switch.
- **Secrets & tenant isolation**: per-tenant encryption keys, isolated storage; evidence encrypted at rest.

### 2.3 Suggested tech stack

- **Core services & APIs**: Go or Rust for the egress gateway/orchestrator (performance, strong concurrency, memory safety); Python or TypeScript for check plugins (ecosystem, speed of authoring).
- **Policy**: Open Policy Agent (Rego) as the decision point.
- **Queue/orchestration**: Temporal or a durable workflow engine for long-running, resumable scans with built-in heartbeats; Kafka/NATS for events.
- **Data**: PostgreSQL for relational state (scopes, grants, findings); a graph store (Neo4j or a Postgres `ltree`/graph model) for the data-path and attack-path graphs; object storage (S3-compatible, WORM-capable) for evidence and audit anchoring.
- **Sandboxing**: per-check execution in gVisor/Firecracker microVMs or locked-down containers with no ambient network — all egress forced through the gateway.
- **Frontend**: TypeScript + React for the console (scope builder, scan monitor, report viewer, remediation tracker).
- **Observability**: OpenTelemetry traces correlated by scan-id; append-only audit sink.
- **Reuse existing engines** where sensible (see Section 7) rather than reinventing scanners — wrap and orchestrate them under the same authorization gate.

---

## 3. Recon & Attack-Surface Mapping

Goal: produce a **data-path graph** — nodes are observable surfaces (pages, endpoints, parameters, auth flows, inferred backend services and data stores); edges are observed/inferred communication relationships (`page → API call → backend → returned document`).

### 3.1 Discovery techniques (passive-first)

- **Passive, non-destructive by default**: crawl in-scope web content; parse HTML/JS bundles for API URLs, fetch calls, GraphQL endpoints, and embedded config; read `robots.txt`, sitemaps, and OpenAPI/Swagger/GraphQL introspection documents *when published in scope*.
- **API & spec ingestion**: if the customer provides an OpenAPI/GraphQL schema or a Postman/HAR collection, use it as ground truth for endpoints and parameters (better and safer than blind discovery).
- **Endpoint & parameter enumeration**: derive endpoints and parameters from observed traffic, client code, and specs; wordlist-based discovery only within scope and under rate limits, honoring exclusions.
- **Auth-flow mapping**: observe login, session issuance, token formats (cookie/JWT/OAuth), refresh flows, and role boundaries by comparing responses across provided test identities (customer-supplied low-priv and, optionally, higher-priv test accounts).
- **Technology fingerprinting**: infer frameworks, API gateways, GraphQL/REST, and likely data-store types from headers, error signatures, and response shapes — enough to reason about the path, not to attack infrastructure.

### 3.2 Inferring the data path

The platform infers the *route to data* without touching the data: e.g. a search box → `GET /api/v2/search?q=` → a backend service → a datastore query → a returned JSON document. It models which parameters are likely to flow into a query, which endpoints return records vs. perform actions, and where trust boundaries (auth checks, tenant isolation) sit. This graph is what the chaining module later walks.

### 3.3 Using customer-provided context

Strongly prefer customer-supplied inputs — test credentials, API specs, architecture notes, a list of "most sensitive" data stores — because they make testing both safer (fewer blind requests) and more accurate.

---

## 4. Vulnerability Classes (mapped to OWASP)

For each class the engine performs **detection** (safe mode) and, where authorized, **confirmation** (active mode) — always stopping at the sensitive boundary. These are detection objectives and design checks, not exploit recipes.

### Web — OWASP Top 10 (2021)

- **A01 Broken Access Control**: horizontal/vertical privilege checks (can a low-priv test identity reach another tenant's object or an admin function?); IDOR detection via object-reference comparison across test identities; missing function-level authorization. *High priority — this is the most common path to data.*
- **A02 Cryptographic Failures**: sensitive data sent/stored without adequate transport security; weak TLS config; tokens or PII exposed in URLs, logs, or responses.
- **A03 Injection**: detect contexts where untrusted input reaches an interpreter (SQL/NoSQL/OS/LDAP/template). Detection relies on behavioral and error-signature signals; confirmation is limited to a benign, bounded proof that input is interpreted — never data extraction.
- **A04 Insecure Design**: missing rate limits on sensitive flows, weak workflow/trust-boundary design surfaced during mapping.
- **A05 Security Misconfiguration**: default credentials surfaces, verbose errors/stack traces, directory listing, dangerous HTTP methods, permissive CORS, missing security headers, exposed admin/debug endpoints.
- **A06 Vulnerable & Outdated Components**: fingerprint versions and cross-reference known-vulnerable component databases (informational — confirm, don't exploit).
- **A07 Identification & Authentication Failures**: weak session management, missing MFA on sensitive actions, predictable tokens, improper logout/refresh, credential-stuffing exposure (detection via policy, not actual stuffing).
- **A08 Software & Data Integrity Failures**: insecure deserialization surfaces, unsigned update/callback mechanisms, risky CI/CD or dependency sources (where observable).
- **A09 Security Logging & Monitoring Failures**: assessed collaboratively with the customer (did the blue team see our authorized traffic?) rather than probed.
- **A10 SSRF**: endpoints that fetch user-supplied URLs; detection bounded by the egress gateway's own metadata/internal-range protections so the platform never becomes an SSRF vector itself.

### APIs — OWASP API Security Top 10 (2023)

- **API1 Broken Object Level Authorization (BOLA/IDOR)** — primary data-reach path; test with multiple identities.
- **API2 Broken Authentication** — token validation, expiry, scope enforcement.
- **API3 Broken Object Property Level Authorization** — mass assignment / excessive-data-exposure checks on returned objects.
- **API4 Unrestricted Resource Consumption** — detect missing pagination/rate limits *by inspection*, not by exhausting them.
- **API5 Broken Function Level Authorization** — role-boundary checks on privileged operations.
- **API6 Unrestricted Access to Sensitive Business Flows** — identify sensitive flows lacking anti-automation.
- **API7 SSRF** — as above.
- **API8 Security Misconfiguration** — CORS, verbose errors, unneeded methods.
- **API9 Improper Inventory Management** — shadow/deprecated API versions, undocumented endpoints.
- **API10 Unsafe Consumption of APIs** — risky trust of third-party/upstream APIs (observable only).

Each check declares its **mode** (safe/active), its **side-effect class** (read-only vs. potentially mutating — the latter disabled by default), and its **stop condition**.

---

## 5. Attack-Path Chaining with a Hard Stop Condition

Individual low/medium findings are often only interesting in combination. The chaining module reasons over the data-path graph to compose them into a realistic path toward sensitive data, then **stops at the first sensitive boundary**.

### 5.1 How chaining works

- Model findings as **capabilities** (e.g. "unauthenticated read of endpoint X", "can enumerate object IDs", "verbose error reveals a parameter reaches a query", "low-priv token accepted on admin route").
- A planner searches for sequences where one capability unlocks the precondition of another, scoring paths by **realistic reachability** and resulting business impact (e.g. anonymous → ID enumeration → BOLA → another tenant's record = a credible data-exposure path).
- The output is a ranked set of **attack paths**, each a readable narrative of steps, with the evidence for each link.

### 5.2 The stop condition (non-negotiable)

A path is pursued only up to — and never past — the first **sensitive boundary**, defined as any point where the next action would:

- read actual sensitive/PII/regulated data (beyond a minimal, masked existence proof),
- cross a tenant/user isolation boundary into real data,
- mutate state, or
- require a destructive or exfiltrating action to proceed.

At the boundary the engine **halts, captures minimal proof that the boundary was reachable** (e.g. "a request as tenant A returned HTTP 200 with a record belonging to tenant B — captured only the masked record identifier and count"), records the full chain, and marks the path **confirmed-reachable, not-exploited**. It does not pull the data behind the boundary. This is what makes the platform demonstrably safe for authorized use: it proves the risk without realizing the harm.

### 5.3 Reachability, not just presence

Prioritization is driven by whether a vulnerable surface is actually on a path to data a real attacker could reach from their starting privilege — reducing false positives and focusing the report (and the "fix" work) on what matters.

---

## 6. Reporting & Remediation (the "fix" side)

### 6.1 Finding content

Each finding includes:

- **Title & class** (with OWASP Web/API mapping).
- **Severity**: CVSS v4.0 base + environmental, plus a platform business-impact score that factors in data sensitivity and reachability. Show the CVSS vector string.
- **Affected assets**: exact endpoints/parameters/identities, linked to scope.
- **Reproduction**: the minimal, authorized steps and the exact (redacted) evidence captured — enough for the customer's engineers to reproduce in their own environment, consistent with the stop condition.
- **Attack path** (if chained): the narrative from entry point to the sensitive boundary, with each link's evidence.
- **Business impact**: what data/function was reachable and what a real compromise would mean (regulatory, financial, trust).
- **Evidence**: hash-sealed, redacted artifacts linked to the audit log.

### 6.2 Remediation guidance (the paid "fix")

- **Concrete, framework-specific fixes**: e.g. for BOLA — enforce object-ownership checks server-side on every reference, use non-enumerable identifiers, add centralized authorization middleware with default-deny; for injection — parameterized queries/prepared statements, input validation, least-privilege DB accounts; for misconfig — specific header/CORS/error-handling settings.
- **Prioritized remediation plan**: ordered by reachability-weighted risk, with effort estimates.
- **Fix verification / retest**: one-click re-scan of just the fixed finding under the same scope, producing a signed "remediated" attestation — this closes the loop and is a natural recurring revenue point.
- **Integrations for the fix workflow**: push findings to Jira/GitHub/GitLab issues with suggested patches; SARIF export for code-scanning tools; webhook/Slack notifications.
- **Trend & posture reporting**: time-to-remediate, recurring classes, posture over repeat engagements — the data that justifies ongoing subscription.

### 6.3 Report formats

Interactive web report (filter by severity/class/asset), plus exportable PDF for stakeholders and machine-readable JSON/SARIF for tooling. Executive summary for leadership; technical appendix for engineers.

---

## 7. Comparison & Integration with Existing Tools

The platform's differentiators are **authorization-as-a-gate**, **data-path reasoning**, **safe chaining with a hard stop**, and the **find-and-fix business loop** — not reinventing individual scanners.

| Tool | Strength | Gap this platform fills |
|------|----------|-------------------------|
| **Burp Suite** | Best-in-class interactive proxy, manual testing, extensible | Manual/analyst-driven; no built-in consent/authorization gate, no automated data-path chaining with enforced stop conditions, no fix-loop business workflow |
| **OWASP ZAP** | Open-source scanner & proxy, automatable | Single-tool scanning; limited attack-path reasoning; no managed authorization/scope enforcement or remediation lifecycle |
| **sqlmap** | Deep, specialized injection confirmation | Highly offensive/extraction-capable by design — the opposite of stop-at-boundary; would be used only in a neutered detection-only mode, if at all |
| **Nuclei** | Fast, template-based known-issue detection | Template matching, not reasoning; no chaining, no consent model; ideal as a *detection feeder* into this platform |

**Integration strategy**: wrap ZAP/Nuclei (and selectively, detection-only modes of others) as check plugins **behind the egress gateway and policy engine**, so their traffic is scoped, rate-limited, attributed, and audited. Import Burp/ZAP findings to enrich the graph. Consume Nuclei templates and known-vuln feeds as detection inputs. The platform's unique layer is the authorization core, the data-path/attack-path graph, the enforced safety boundary, and the remediation business.

**Where it should *not* compete**: deep manual exploitation and novel exploit development remain the analyst's job in Burp — the platform augments and documents, it doesn't replace human judgment on high-severity confirmation.

---

## 8. Phased MVP Roadmap & Legal/Compliance Checklist

### 8.1 Phased roadmap

**Phase 0 — Authorization core (build first, before any scanning).**
Scope objects, proof-of-authorization (domain-token + signed RoE), allow-list, policy engine (default-deny), egress gateway with SSRF protections, audit logging, kill switch. *No probing capability ships until this is solid and tested.*

**Phase 1 — Safe-mode recon + reporting.**
Surface mapping and data-path graph, passive/read-only detection only, OpenAPI/HAR ingestion, basic findings with CVSS and fix guidance, PDF/JSON export. Deliver value with zero active probing.

**Phase 2 — Active confirmation (opt-in) for top classes.**
Confirmation-grade, bounded checks for the highest-value, highest-safety classes first: Broken Access Control / BOLA, security misconfiguration, auth failures. Integrate ZAP/Nuclei as gated plugins. Full stop-at-boundary enforcement.

**Phase 3 — Attack-path chaining.**
The graph planner, path ranking, narrative reporting, reachability-weighted prioritization.

**Phase 4 — Remediation & fix loop.**
Jira/GitHub integration, one-click retest + remediated attestation, trend/posture dashboards, subscription/retest monetization.

**Phase 5 — Scale & assurance.**
Multi-tenant hardening, third-party security audit of the platform itself, SOC 2, continuous-monitoring offering.

### 8.2 Legal & compliance checklist (operating as a paid service)

- **Computer-misuse law**: the entire product depends on verified authorization from the asset owner — map requirements under CFAA (US), the UK Computer Misuse Act, the EU equivalents, and local laws in every jurisdiction you operate or test in. Authorization must be from a party with actual authority over the asset.
- **Authorization artifacts**: signed master services agreement + per-engagement rules-of-engagement + scope; retained and tied to every scan in the audit log. Re-verification at execution.
- **Safe-harbor alignment**: when linked to a bug-bounty program, inherit and honor that program's safe-harbor and scope.
- **Data protection**: GDPR/CCPA/etc. — minimize and mask any PII in evidence, define retention/deletion, data-processing agreements with customers, and lawful basis for processing. Keep evidence in-region if required.
- **Cloud provider terms**: honor AWS/GCP/Azure penetration-testing policies for in-scope cloud-hosted targets.
- **Liability & insurance**: professional liability / cyber insurance; clear contractual limitation of liability; indemnification tied to the customer's authorization warranty.
- **Export/sanctions**: screen customers and targets against sanctions lists; restrict operation in prohibited jurisdictions.
- **Platform security & certifications**: SOC 2 Type II, ISO 27001; third-party pentest of the platform; vulnerability disclosure policy for the platform itself.
- **Abuse prevention**: KYC/business verification before active testing is unlocked; monitoring for customers attempting to point the tool at assets they don't own; a clear path for third parties to report suspected misuse (the attribution header links here).
- **Incident response**: a defined process if a scan causes an unintended impact despite safeguards — immediate kill switch, customer notification, root-cause, and audit-log disclosure.

---

*End of specification v0.1. Everything here presumes verified, consent-based authorization; the authorization and safety model (Section 1) gates every capability and is the first thing to build.*
