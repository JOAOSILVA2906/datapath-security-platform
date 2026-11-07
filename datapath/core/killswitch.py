"""Kill switch & dead-man's switch (spec 1.7).

  * Global kill switch — halts all scans and closes egress; once engaged,
    every policy query is denied regardless of grant.
  * Per-scan abort — any authorizing contact stops their scan instantly.
  * Dead-man's switch — a scan requires a periodic validity heartbeat; loss of
    heartbeat pauses the scan. A paused scan may not probe.

Review fix #7: the kill switch is authoritative over in-flight work, not just
the queue. The egress gateway must consult ``scan_may_probe`` (or the policy
engine, which consults this) immediately before every connect, so a scan that
is aborted mid-pipeline cannot complete a request already planned.
"""

from __future__ import annotations

import enum
from datetime import datetime, timedelta, timezone


class ScanState(enum.Enum):
    RUNNING = "running"
    PAUSED = "paused"        # heartbeat lost; may resume
    ABORTED = "aborted"      # terminal


class KillSwitch:
    def __init__(self, heartbeat_timeout: timedelta = timedelta(seconds=60)) -> None:
        self._global_halt = False
        self._heartbeat_timeout = heartbeat_timeout
        self._scans: dict[str, ScanState] = {}
        self._last_heartbeat: dict[str, datetime] = {}

    # --- global -----------------------------------------------------------

    def engage_global(self) -> None:
        self._global_halt = True

    def reset_global(self) -> None:
        self._global_halt = False

    @property
    def global_halted(self) -> bool:
        return self._global_halt

    # --- per-scan ---------------------------------------------------------

    def register(self, scan_id: str, at: datetime | None = None) -> None:
        self._scans[scan_id] = ScanState.RUNNING
        self._last_heartbeat[scan_id] = (at or datetime.now(timezone.utc)).astimezone(
            timezone.utc
        )

    def abort(self, scan_id: str) -> None:
        self._scans[scan_id] = ScanState.ABORTED

    def heartbeat(self, scan_id: str, at: datetime | None = None) -> None:
        if self._scans.get(scan_id) is ScanState.ABORTED:
            raise ValueError(f"scan {scan_id} is aborted; cannot heartbeat")
        self._last_heartbeat[scan_id] = (at or datetime.now(timezone.utc)).astimezone(
            timezone.utc
        )
        if self._scans.get(scan_id) is ScanState.PAUSED:
            self._scans[scan_id] = ScanState.RUNNING

    def state(self, scan_id: str, at: datetime | None = None) -> ScanState:
        st = self._scans.get(scan_id)
        if st is None:
            raise KeyError(f"unknown scan {scan_id}")
        if st is ScanState.ABORTED:
            return st
        now = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        last = self._last_heartbeat.get(scan_id)
        if last is None or now - last > self._heartbeat_timeout:
            self._scans[scan_id] = ScanState.PAUSED
            return ScanState.PAUSED
        return st

    def scan_may_probe(self, scan_id: str, at: datetime | None = None) -> bool:
        """Authoritative gate consulted immediately before every connect."""
        if self._global_halt:
            return False
        try:
            return self.state(scan_id, at) is ScanState.RUNNING
        except KeyError:
            return False
