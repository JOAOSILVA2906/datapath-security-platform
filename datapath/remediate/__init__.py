"""DataPath Phase 4 — remediation & the fix loop.

Turns findings into action: issue-tracker tickets, SARIF export, one-click
retest with a signed "remediated" attestation (covering only the re-run check),
posture/trend metrics over repeat engagements, and webhook/Slack notifications.
Network calls live in integration layers; everything here is pure/injected.
"""

from .attestation import RemediationAttestation, RetestResult, Retester
from .tickets import to_github_issue, to_jira_issue
from .sarif import to_sarif
from .posture import (
    ScanRecord,
    open_trend,
    posture_summary,
    recurring_classes,
    time_to_remediate,
)
from .notify import Notifier, build_slack_message

__all__ = [
    "RemediationAttestation",
    "RetestResult",
    "Retester",
    "to_github_issue",
    "to_jira_issue",
    "to_sarif",
    "ScanRecord",
    "open_trend",
    "posture_summary",
    "recurring_classes",
    "time_to_remediate",
    "Notifier",
    "build_slack_message",
]
