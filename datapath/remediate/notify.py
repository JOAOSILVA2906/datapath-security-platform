"""Webhook / Slack notifications (spec 6.2).

Builds a Slack-style message payload from a report summary and sends it through
an INJECTED sender, so there is no network here and it stays testable. The real
sender would post to a tenant-configured webhook behind the secret vault.
"""

from __future__ import annotations

from typing import Callable

Sender = Callable[[dict], None]


def build_slack_message(scope_ref: str, summary: dict, top_path: str | None = None) -> dict:
    by = summary.get("by_severity", {})
    sev_line = " · ".join(
        f"{k}: {by[k]}" for k in ("critical", "high", "medium", "low")
        if by.get(k)
    ) or "nenhum"
    blocks = [
        {"type": "header",
         "text": {"type": "plain_text", "text": "DataPath — varredura concluída"}},
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": f"*Escopo:* `{scope_ref}`\n*Achados:* "
                          f"{summary.get('total_findings', 0)} ({sev_line})"}},
    ]
    if top_path:
        blocks.append({"type": "section",
                       "text": {"type": "mrkdwn",
                                "text": f"*Caminho crítico:* {top_path}"}})
    return {
        "text": f"DataPath: {summary.get('total_findings', 0)} achados em {scope_ref}",
        "blocks": blocks,
    }


class Notifier:
    def __init__(self, sender: Sender) -> None:
        self._sender = sender

    def notify(self, payload: dict) -> None:
        self._sender(payload)
