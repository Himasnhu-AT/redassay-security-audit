"""SARIF 2.1.0 output, so findings can be uploaded to GitHub code scanning.

Only the parts of the spec that consumers actually read are emitted. A partial
but valid document beats a complete one that no tool ingests.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Sequence

from . import severity as sev
from .models import Finding

SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

_LEVEL = {
    sev.CRITICAL: "error",
    sev.HIGH: "error",
    sev.MEDIUM: "warning",
    sev.LOW: "note",
    sev.INFO: "note",
}

_SECURITY_SEVERITY = {
    sev.CRITICAL: "9.5",
    sev.HIGH: "7.5",
    sev.MEDIUM: "5.0",
    sev.LOW: "3.0",
    sev.INFO: "1.0",
}


def build(findings: Sequence[Finding], tool_version: str = "0.1.0", repo_uri: str = "") -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        if finding.rule_id not in rules:
            tags = ["security"] + list(finding.cwe) + list(finding.tags)
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": _pascal(finding.rule_id),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "help": {
                    "text": finding.remediation or finding.title,
                    "markdown": f"**{finding.title}**\n\n{finding.description}\n\n**Fix:** {finding.remediation}",
                },
                "defaultConfiguration": {"level": _LEVEL[finding.severity]},
                "properties": {
                    "tags": tags,
                    "security-severity": _SECURITY_SEVERITY[finding.severity],
                    "precision": {"high": "high", "medium": "medium", "low": "low"}.get(finding.confidence, "medium"),
                },
            }
        results.append({
            "ruleId": finding.rule_id,
            "level": _LEVEL[finding.severity],
            "message": {"text": finding.description or finding.title},
            "partialFingerprints": {"redassayId": finding.id},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": max(finding.line, 1),
                        "endLine": max(finding.location.end_line or finding.line, 1),
                        "snippet": {"text": finding.location.snippet},
                    },
                }
            }],
            "properties": {
                "confidence": finding.confidence,
                "severity": finding.severity,
                "status": finding.status,
                "source": finding.source,
            },
        })

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "redassay",
                "version": tool_version,
                "informationUri": "https://github.com/redassay/redassay",
                "rules": list(rules.values()),
            }
        },
        "results": results,
    }
    if repo_uri:
        run["versionControlProvenance"] = [{"repositoryUri": repo_uri}]
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}


def dumps(findings: Sequence[Finding], **kwargs: Any) -> str:
    return json.dumps(build(findings, **kwargs), indent=2)


def _pascal(rule_id: str) -> str:
    return "".join(part.capitalize() for part in rule_id.replace(".", "-").split("-"))
