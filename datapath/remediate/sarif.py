"""SARIF v2.1.0 export for code-scanning tools (spec 6.3).

Produces a valid SARIF log so findings flow into GitHub code scanning, IDEs and
other SARIF consumers. CVSS score is carried as the `security-severity`
property each of those tools understands.
"""

from __future__ import annotations

from ..scan.findings import Finding

_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "none": "note",
}


def to_sarif(findings: list[Finding], tool_name: str = "DataPath") -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        if f.check_id not in rules:
            rules[f.check_id] = {
                "id": f.check_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "helpUri": "https://datapath.example/checks/" + f.check_id,
                "properties": {
                    "security-severity": f"{f.score}",
                    "owasp": f.owasp,
                    "tags": ["security", f.owasp.split(":")[0]],
                },
                "help": {"text": f.fix},
            }
        results.append({
            "ruleId": f.check_id,
            "level": _LEVEL.get(f.severity.value, "note"),
            "message": {"text": f"{f.title} — {f.evidence}"},
            "properties": {"security-severity": f"{f.score}",
                           "cvss_vector": f.cvss_vector},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.affected_url},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "informationUri": "https://datapath.example",
                "version": "0.1.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
