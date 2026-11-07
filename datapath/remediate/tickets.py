"""Push findings to issue trackers (spec 6.2).

Builds structured issue payloads for GitHub/GitLab and Jira. These are plain
dicts — the actual API call is the integration layer's job (and would go behind
the same tenancy/secret controls). No network here.
"""

from __future__ import annotations

from ..scan.findings import Finding

_SEV_LABEL = {
    "critical": "severity/critical",
    "high": "severity/high",
    "medium": "severity/medium",
    "low": "severity/low",
    "none": "severity/info",
}


def _body_markdown(f: Finding) -> str:
    return (
        f"**Severidade:** {f.severity.value.upper()} (CVSS {f.score} — `{f.cvss_vector}`)\n\n"
        f"**Classe:** {f.owasp}\n\n"
        f"**Local:** `{f.affected_url}`\n\n"
        f"**Evidência:** {f.evidence}\n\n"
        + (f"**Descrição:** {f.description}\n\n" if f.description else "")
        + f"**Correção:** {f.fix}\n\n"
        f"---\n_Gerado pelo DataPath. Teste autorizado, modo seguro._"
    )


def to_github_issue(f: Finding) -> dict:
    return {
        "title": f"[{f.severity.value.upper()}] {f.title}",
        "body": _body_markdown(f),
        "labels": ["datapath", _SEV_LABEL.get(f.severity.value, "severity/info")],
    }


def to_jira_issue(f: Finding, project_key: str = "SEC") -> dict:
    priority = {
        "critical": "Highest", "high": "High", "medium": "Medium",
        "low": "Low", "none": "Lowest",
    }[f.severity.value]
    return {
        "fields": {
            "project": {"key": project_key},
            "issuetype": {"name": "Bug"},
            "priority": {"name": priority},
            "summary": f"[{f.severity.value.upper()}] {f.title}",
            "description": _body_markdown(f),
            "labels": ["datapath", f.check_id],
        }
    }
