# DataPath Platform Threat Model

*Review fix #7. Scope: the security of the DataPath platform itself, not of the
targets it assesses. Companion to the Phase-0 code in `datapath/core`.*

The platform is a high-value target in its own right: it holds test credentials
for many customers, stores the map of how each customer reaches their data, and
controls a fleet that can send traffic to those customers' assets. A compromise
here is a compromise of every customer at once. This document enumerates the
assets, the adversaries, the threats (STRIDE), and the controls — marking which
are implemented in Phase 0 and which are still owed.

## 1. Assets to protect

| Asset | Why it matters |
|---|---|
| Customer test credentials | Direct access to customer systems if leaked. |
| Scope / data-path graphs | A blueprint of how to reach each customer's data. |
| Authorization grants & signing keys | Forging one authorizes unauthorized testing. |
| Allow-lists & policy rules | Widening one turns the fleet on out-of-scope assets. |
| Audit log | Its integrity is the platform's legal defence. |
| Egress fleet | Could be abused as an attack proxy against third parties. |

## 2. Adversaries

- **Malicious or compromised operator (insider).** Primary threat. Has some
  legitimate access and wants to widen scope, exfiltrate credentials, or point
  the fleet at a target they don't own.
- **Malicious customer.** Tries to aim the platform at assets they don't
  control (a competitor, a shared host) by faking authorization.
- **External attacker.** Targets the platform's own APIs/infra to steal the
  assets above.
- **Supply-chain adversary.** Ships a malicious check plugin or scanner
  template (e.g. a Nuclei template tagged `intrusive`/`dos`).

## 3. Threats and controls (STRIDE)

### Spoofing
- *Forged authorization grant.* → Grants are HMAC-signed and bound to a scope
  version; `AuthorizationGrant.signature_valid` / `is_valid_for`. **(Phase 0)**
- *Customer claims assets they don't own.* → Ownership verification: CNAME/ASN
  checks, third-party/CDN exclusion; `OwnershipVerifier`. **(Phase 0)**

### Tampering
- *Audit-log edits to hide activity.* → Hash-chained append-only log;
  `AuditLog.verify` locates the first broken record. **(Phase 0)**
- *Secret store tampering.* → Sealed blobs are integrity-checked on unseal;
  `CredentialVault` / sealer tag check. **(Phase 0)**

### Repudiation
- *"We never authorized / ran that."* → Every policy decision and grant event
  is written to the chained audit log with scope ref, grant id, target, mode.
  **(Phase 0)**

### Information disclosure
- *Credential leak via logs.* → Vault never returns secrets to logs; only a
  salted fingerprint is loggable; secrets excluded from `repr`. Audit log
  refuses body-like payloads. **(Phase 0)**
- *PII in evidence/audit.* → Audit stores metadata + hashes only; evidence
  bodies live in a separate, erasable, encrypted store (GDPR erasure). **(Phase 0
  for audit; evidence store is a later phase.)**

### Denial of service
- *Fleet abused to flood a target, or one tenant starves the fleet.* →
  Per-target rate caps, per-tenant budgets, adaptive backoff (spec 1.5).
  **(Owed — not in Phase 0.)**

### Elevation of privilege
- *One operator widens scope/policy alone.* → Two-person control on sensitive
  changes (allow-list add, policy relax, intensity raise, ownership override);
  `DualControl` refuses self-approval and duplicate approvals. **(Phase 0)**
- *Policy service unreachable → open.* → Policy engine fails **closed**: any
  error or missing input yields DENY; `PolicyEngine.evaluate`. **(Phase 0)**

## 4. Kill switch over in-flight work

The kill switch is authoritative over work already in progress, not just the
queue. The egress gateway must call `KillSwitch.scan_may_probe` (or the policy
engine, which calls it first) **immediately before every connect**. A global
halt or a per-scan abort therefore denies the very next request of a scan that
was mid-pipeline — the request already planned does not complete. A lost
heartbeat pauses the scan the same way (dead-man's switch). **(Phase 0)**

## 5. Credential handling rules (enforced by `CredentialVault`)

1. Secrets are sealed at rest by an injected KMS/HSM-backed sealer. The bundled
   `_DevSealer` is labelled dev-only and must not reach production.
2. Secrets are **leased per scan** with a short TTL, never handed out wholesale.
3. Leases are revoked on scan end/abort (`revoke_scan`) and on rotation.
4. Rotation invalidates every outstanding lease for that credential.
5. Only a salted fingerprint of a secret may be logged.

## 6. Still owed (not in Phase 0)

- Rate-limit / budget / backpressure engine (spec 1.5) — the DoS controls above.
- Plugin & template supply-chain vetting (review fix #9): pin a vetted template
  set, map tags to the side-effect taxonomy, block unmapped templates.
- Real envelope encryption / KMS integration behind the `Sealer` interface.
- Per-tenant isolation and encryption-at-rest for the graph and evidence stores.
- Third-party pentest + SOC 2 / ISO 27001 of the platform (spec Phase 5).
