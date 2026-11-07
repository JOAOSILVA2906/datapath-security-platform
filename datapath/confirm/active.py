"""Active confirmation (opt-in) for the highest-value classes (spec Phase 2).

Covers the top classes first: Broken Access Control / BOLA and vertical
privilege. Each confirmer:

  * runs only through a GatedEgress built with ``active_confirmed=True`` and a
    scope/grant that permit ACTIVE — otherwise every probe is refused;
  * sends exactly ONE crafted-but-read-only request and then STOPS — it never
    enumerates further, so the stop-at-boundary rule holds by construction;
  * works against customer-seeded TEST tenants carrying DECOY data (review fix
    #1), so "crossing the isolation boundary" reaches fake data, never real;
  * sees only a ReducedResponse (body already discarded at the gateway), and
    captures a minimal masked proof.

The result is a Confirmation: confirmed-reachable / not-confirmed, with a
BoundaryProof and a short narrative.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..scan.egress import EgressDenied, GatedEgress, ReducedResponse
from .boundary import BoundaryKind, BoundaryProof, mask


@dataclass(frozen=True)
class Confirmation:
    confirmed: bool
    narrative: str
    boundary: BoundaryProof | None = None
    http_status: int | None = None

    def to_dict(self) -> dict:
        d = {
            "confirmed": self.confirmed,
            "narrative": self.narrative,
            "http_status": self.http_status,
        }
        if self.boundary is not None:
            d["boundary_proof"] = self.boundary.to_dict()
        return d


class ActiveConfirmer:
    def __init__(self, egress: GatedEgress) -> None:
        self._egress = egress

    def confirm_bola(
        self,
        url_for_object_b: str,
        identity_a_token: str,
        decoy_marker_b: str,
    ) -> Confirmation:
        """Can test-identity A read test-tenant B's object (BOLA / A01)?

        Requests tenant B's object URL using A's token. If the response carries
        B's decoy marker, the cross-tenant isolation boundary is REACHABLE.
        We stop immediately — one request, masked proof, no data pulled.
        """
        try:
            r = self._egress.probe(
                url_for_object_b,
                markers=[decoy_marker_b],
                extra_headers={"Authorization": f"Bearer {identity_a_token}"},
            )
        except EgressDenied as exc:
            return Confirmation(False, f"sondagem recusada pelo portão: {exc}")

        if r.status == 200 and decoy_marker_b in r.markers_present:
            proof = BoundaryProof(
                kind=BoundaryKind.CROSS_TENANT_READ,
                evidence=(
                    f"identidade A recebeu HTTP 200 contendo o marcador de "
                    f"decoy do tenant B ({mask(decoy_marker_b)}); 1 registro "
                    f"alcançável. Corpo não retido (hash {r.sha256[:12]}…)."
                ),
            )
            return Confirmation(
                confirmed=True,
                narrative=(
                    "Caminho: identidade de baixo privilégio A → referência ao "
                    "objeto do tenant B → leitura entre tenants. PARADO no "
                    "limite: confirmado alcançável, não explorado."
                ),
                boundary=proof,
                http_status=r.status,
            )
        return Confirmation(
            confirmed=False,
            narrative=(
                f"A não alcançou o objeto de B (HTTP {r.status}, marcador de "
                f"decoy ausente). Isolamento parece respeitado."
            ),
            http_status=r.status,
        )

    def confirm_vertical_privilege(
        self,
        privileged_url: str,
        low_priv_token: str,
        admin_decoy_marker: str,
    ) -> Confirmation:
        """Can a low-privilege identity reach a privileged function (A01/API5)?"""
        try:
            r = self._egress.probe(
                privileged_url,
                markers=[admin_decoy_marker],
                extra_headers={"Authorization": f"Bearer {low_priv_token}"},
            )
        except EgressDenied as exc:
            return Confirmation(False, f"sondagem recusada pelo portão: {exc}")

        if r.status == 200 and admin_decoy_marker in r.markers_present:
            proof = BoundaryProof(
                kind=BoundaryKind.VERTICAL_PRIVILEGE,
                evidence=(
                    f"token de baixo privilégio recebeu HTTP 200 numa rota "
                    f"privilegiada, com o marcador administrativo "
                    f"({mask(admin_decoy_marker)}). Corpo não retido "
                    f"(hash {r.sha256[:12]}…)."
                ),
            )
            return Confirmation(
                confirmed=True,
                narrative=(
                    "Caminho: identidade de baixo privilégio → função "
                    "administrativa sem verificação de autorização. PARADO no "
                    "limite: confirmado alcançável, não explorado."
                ),
                boundary=proof,
                http_status=r.status,
            )
        return Confirmation(
            confirmed=False,
            narrative=(
                f"Baixo privilégio não alcançou a função (HTTP {r.status}). "
                f"Autorização de nível de função parece aplicada."
            ),
            http_status=r.status,
        )
