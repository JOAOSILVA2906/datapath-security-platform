"""Scoped, ephemeral credential vault (review fix #7).

Customer-supplied test credentials are among the platform's most dangerous
holdings. Rules enforced here:

  * secrets are kept SEALED at rest (wrapped by an injected sealer that stands
    in for a KMS/HSM — we do not roll our own crypto);
  * a secret is never handed out wholesale; it is LEASED to a specific scan
    with a short TTL;
  * a lease is revoked automatically when the scan ends or is aborted, and all
    leases for a credential are revoked on ROTATION;
  * secrets never appear in repr/str/logs — only an opaque, stable fingerprint
    (a salted hash) may be logged, so audit records can reference "which
    credential" without containing it.

The sealer is injected so production routes it to real envelope encryption; the
default dev sealer is clearly labelled and NOT for production.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol


class Sealer(Protocol):
    def seal(self, plaintext: bytes) -> bytes: ...
    def unseal(self, sealed: bytes) -> bytes: ...


class _DevSealer:
    """DEV ONLY. Keyed obfuscation so plaintext is not stored in the clear in
    process memory structures; it is NOT secure envelope encryption. Production
    must inject a KMS/HSM-backed Sealer."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 16:
            raise ValueError("dev sealer key too short")
        self._key = key

    def _keystream(self, n: int, nonce: bytes) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < n:
            out += hmac.new(
                self._key, nonce + counter.to_bytes(4, "big"), hashlib.sha256
            ).digest()
            counter += 1
        return bytes(out[:n])

    def seal(self, plaintext: bytes) -> bytes:
        nonce = secrets.token_bytes(16)
        ks = self._keystream(len(plaintext), nonce)
        ct = bytes(a ^ b for a, b in zip(plaintext, ks))
        tag = hmac.new(self._key, nonce + ct, hashlib.sha256).digest()
        return nonce + tag + ct

    def unseal(self, sealed: bytes) -> bytes:
        nonce, tag, ct = sealed[:16], sealed[16:48], sealed[48:]
        expected = hmac.new(self._key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, tag):
            raise ValueError("sealed blob failed integrity check")
        ks = self._keystream(len(ct), nonce)
        return bytes(a ^ b for a, b in zip(ct, ks))


class VaultError(Exception):
    pass


@dataclass
class _Entry:
    sealed: bytes
    version: int
    fingerprint: str


@dataclass(frozen=True)
class Lease:
    lease_token: str
    cred_id: str
    scan_id: str
    version: int
    expires_at: datetime
    fingerprint: str

    def __repr__(self) -> str:  # never leak anything secret
        return (
            f"Lease(cred_id={self.cred_id!r}, scan_id={self.scan_id!r}, "
            f"v{self.version}, fp={self.fingerprint[:12]}…)"
        )


class CredentialVault:
    def __init__(self, sealer: Sealer, fingerprint_salt: bytes | None = None) -> None:
        self._sealer = sealer
        self._salt = fingerprint_salt or secrets.token_bytes(16)
        self._entries: dict[str, _Entry] = {}
        self._leases: dict[str, Lease] = {}

    @classmethod
    def dev(cls, key: bytes) -> "CredentialVault":
        """Construct with the dev sealer. Not for production."""
        return cls(_DevSealer(key))

    def _fingerprint(self, secret: bytes) -> str:
        return hmac.new(self._salt, secret, hashlib.sha256).hexdigest()

    def store(self, cred_id: str, secret: bytes) -> str:
        """Store/replace a credential. Returns its fingerprint (safe to log)."""
        fp = self._fingerprint(secret)
        self._entries[cred_id] = _Entry(
            sealed=self._sealer.seal(secret), version=1, fingerprint=fp
        )
        return fp

    def rotate(self, cred_id: str, new_secret: bytes) -> str:
        entry = self._require(cred_id)
        fp = self._fingerprint(new_secret)
        entry.sealed = self._sealer.seal(new_secret)
        entry.version += 1
        entry.fingerprint = fp
        # Rotation invalidates every outstanding lease for this credential.
        self._revoke_where(lambda lz: lz.cred_id == cred_id)
        return fp

    def lease(
        self,
        cred_id: str,
        scan_id: str,
        ttl: timedelta,
        at: datetime | None = None,
    ) -> Lease:
        entry = self._require(cred_id)
        now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        lease = Lease(
            lease_token=secrets.token_urlsafe(24),
            cred_id=cred_id,
            scan_id=scan_id,
            version=entry.version,
            expires_at=now + ttl,
            fingerprint=entry.fingerprint,
        )
        self._leases[lease.lease_token] = lease
        return lease

    def use(self, lease_token: str, at: datetime | None = None) -> bytes:
        """Return the unsealed secret for a valid lease. Raises otherwise.

        Caller must use it transiently and never persist or log it.
        """
        lease = self._leases.get(lease_token)
        if lease is None:
            raise VaultError("unknown or revoked lease")
        now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if now > lease.expires_at:
            self._leases.pop(lease_token, None)
            raise VaultError("lease expired")
        entry = self._require(lease.cred_id)
        if entry.version != lease.version:
            self._leases.pop(lease_token, None)
            raise VaultError("credential rotated; lease stale")
        return self._sealer.unseal(entry.sealed)

    def revoke_lease(self, lease_token: str) -> None:
        self._leases.pop(lease_token, None)

    def revoke_scan(self, scan_id: str) -> int:
        """Revoke all leases for a scan (call on scan end/abort). Returns count."""
        return self._revoke_where(lambda lz: lz.scan_id == scan_id)

    def active_lease_count(self) -> int:
        return len(self._leases)

    def _revoke_where(self, pred) -> int:
        doomed = [t for t, lz in self._leases.items() if pred(lz)]
        for t in doomed:
            del self._leases[t]
        return len(doomed)

    def _require(self, cred_id: str) -> _Entry:
        try:
            return self._entries[cred_id]
        except KeyError as exc:
            raise VaultError(f"unknown credential {cred_id!r}") from exc
