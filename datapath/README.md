# DataPath — Phase 0: Authorization & Safety Core

This package is **Phase 0** of the DataPath roadmap: the authorization gate that
every later capability is subordinate to. It contains **no probing, scanning, or
network capability** — only the machinery that decides whether a probe would be
permitted, and refuses by default.

> Per the spec: *"No probing capability ships until this is solid and tested."*

## What's here

| Module | Spec section | Responsibility |
|---|---|---|
| `core/intensity.py` | 1.4 | Intensity tiers + the side-effect taxonomy (passive / benign-payload / potentially-mutating). |
| `core/scope.py` | 1.1 | Versioned, immutable `Scope`; assets, exclusions (exclusions win), test windows, intensity ceiling. |
| `core/grant.py` | 1.2 | `AuthorizationGrant` with HMAC signature, expiry, scope binding, wildcard-parent check. |
| `core/allowlist.py` | 1.3 | Resolve-then-pin target resolution; SSRF block-list; DNS-rebinding defence. |
| `core/policy.py` | 2.2 | The single decision point. **Default-deny, fails closed.** |
| `core/audit.py` | 1.8 | Append-only, hash-chained audit log (metadata + hashes only — no bodies). |
| `core/killswitch.py` | 1.7 | Global kill switch, per-scan abort, dead-man's heartbeat. |

## Design decisions carried over from the spec review (v0.2 fixes)

- **Side-effect taxonomy** replaces "read-only == safe". `POTENTIALLY_MUTATING`
  is refused at every intensity tier by this core.
- **Document-only proofs cannot unlock ACTIVE intensity** — ACTIVE requires a
  technical proof (domain/host control, bug-bounty linkage, cloud linkage).
- **Policy fails closed**: any error or missing input yields DENY.
- **Resolve-then-pin**: the caller must connect to the pinned IP; a DNS rebind
  between validation and connect cannot take effect.
- **Audit log stores no bodies** — avoids pulling PII into an undeletable store
  (GDPR erasure). Evidence bodies live in the separate evidence store.

## Run the tests

```
python -m unittest discover -s datapath/tests -t . -v
```

The suite includes the Phase-0 acceptance tests: an unverified host, a
DNS-rebound IP, a cloud-metadata address, a private range, and an out-of-scope
redirect target are each refused — and policy denials are written to the audit
chain, which `verify()` confirms is intact.

## Run the demo

```
python -m datapath.demo
```

## Not yet built (later phases)

Egress proxy wire implementation, DNS/CNAME/ASN ownership checks (review #5),
the platform's own threat model and secret vaulting (review #7), and everything
in Phases 1–5 (recon, probing, chaining, remediation).
