"""Real HTTP transport (stdlib only).

This is the ONE piece that actually touches the network, and it is designed to
be driven exclusively by GatedEgress — it is never the default path and does no
gating of its own (the gate already ran). It performs a single GET to a target
the gate already resolved, pinned and approved, with a short timeout and no
redirect following (GatedEgress re-checks each hop as a fresh request).

For a training target on localhost, point the scope at 127.0.0.1/32 as an
explicit in-scope internal asset so the SSRF block-list admits it.
"""

from __future__ import annotations

import http.client
import ssl
import time

from .egress import MAX_BODY_BYTES, HttpResponse


def urllib_transport(timeout: float = 10.0):
    """Build a transport callable: (ResolvedTarget, headers) -> HttpResponse.

    Connects to the gate's PINNED ip (not a fresh resolution), preserving the
    Host header, so the anti-rebinding guarantee holds through to connect.
    """

    def _fetch(target, headers: dict[str, str]) -> HttpResponse:
        from urllib.parse import urlsplit

        parts = urlsplit(target.url)
        https = parts.scheme == "https"
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        send_headers = dict(headers)
        send_headers["Host"] = target.host  # real vhost; we connect to pinned IP

        if https:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(
                target.pinned_ip, target.port, timeout=timeout, context=ctx
            )
            # SNI/cert validation uses the real host name.
            conn._context.check_hostname = True  # type: ignore[attr-defined]
        else:
            conn = http.client.HTTPConnection(
                target.pinned_ip, target.port, timeout=timeout
            )

        start = time.monotonic()
        try:
            conn.request("GET", path, headers=send_headers)
            r = conn.getresponse()
            body = r.read(MAX_BODY_BYTES + 1)
            elapsed = time.monotonic() - start
            hdrs = {k: v for k, v in r.getheaders()}
            return HttpResponse(
                status=r.status, headers=hdrs, body=body,
                elapsed=elapsed, final_url=target.url,
            )
        finally:
            conn.close()

    return _fetch
