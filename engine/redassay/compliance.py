"""Control-framework mapping.

A finding already carries a CWE and an OWASP category, which is the vocabulary
engineers use. It is not the vocabulary the people who have to sign something
use: they work in NIST CSF subcategories and, in a SOC, in ATT&CK techniques.

Both mappings already exist as published relationships - NIST and MITRE maintain
them. This module encodes the subset covering the CWEs redassay actually emits,
so one scan answers "what is broken" and "which control this falls under"
without anyone maintaining a spreadsheet in between.

It adds nothing to a finding's truth. A control id is a filing decision, and
treating it as evidence is how compliance theatre starts - so the report says
which control a finding *touches*, never that a control is satisfied.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import Finding

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "compliance.json")

_cache: Optional[Dict[str, Any]] = None


def _load() -> Dict[str, Any]:
    global _cache
    if _cache is not None:
        return _cache
    try:
        with open(DATA, "r", encoding="utf-8") as handle:
            _cache = json.load(handle)
    except (OSError, json.JSONDecodeError):
        _cache = {"mappings": {}, "csf_functions": {}}
    return _cache


def mappings() -> Dict[str, Any]:
    return _load().get("mappings", {})


def csf_functions() -> Dict[str, str]:
    return _load().get("csf_functions", {})


def for_cwe(cwe: str) -> Dict[str, Any]:
    return mappings().get(cwe, {})


def annotate(finding: Finding) -> Dict[str, Any]:
    """The control context for one finding, derived from its CWEs."""
    csf: List[str] = []
    attack: List[str] = []
    themes: List[str] = []
    for cwe in finding.cwe:
        entry = for_cwe(cwe)
        for control in entry.get("nist_csf") or []:
            if control not in csf:
                csf.append(control)
        for technique in entry.get("mitre_attack") or []:
            if technique not in attack:
                attack.append(technique)
        theme = entry.get("theme")
        if theme and theme not in themes:
            themes.append(theme)
    return {"nist_csf": csf, "mitre_attack": attack, "themes": themes}


def function_of(control: str) -> str:
    """'PR.AA-05' -> 'Protect'."""
    return csf_functions().get(control.split(".")[0], "")


def coverage(findings: Sequence[Finding]) -> Dict[str, Any]:
    """Which controls this run touched, and how heavily."""
    by_control: Dict[str, int] = {}
    by_function: Dict[str, int] = {}
    by_technique: Dict[str, int] = {}
    unmapped: Set[str] = set()

    for finding in findings:
        marks = annotate(finding)
        if not marks["nist_csf"] and not marks["mitre_attack"]:
            unmapped.update(finding.cwe)
        for control in marks["nist_csf"]:
            by_control[control] = by_control.get(control, 0) + 1
            function = function_of(control)
            if function:
                by_function[function] = by_function.get(function, 0) + 1
        for technique in marks["mitre_attack"]:
            by_technique[technique] = by_technique.get(technique, 0) + 1

    return {
        "nist_csf": dict(sorted(by_control.items(), key=lambda kv: -kv[1])),
        "functions": dict(sorted(by_function.items(), key=lambda kv: -kv[1])),
        "mitre_attack": dict(sorted(by_technique.items(), key=lambda kv: -kv[1])),
        "unmapped_cwes": sorted(unmapped),
        "findings": len(findings),
    }


def report(findings: Sequence[Finding]) -> str:
    """A control-framework view of a scan."""
    from . import severity as sev

    data = coverage(findings)
    out: List[str] = ["# Control coverage", ""]
    out.append(f"{data['findings']} open findings, mapped to "
               f"{len(data['nist_csf'])} NIST CSF 2.0 subcategories and "
               f"{len(data['mitre_attack'])} ATT&CK techniques.")
    out.append("")
    out.append("This says which controls the findings **touch**. It does not say a "
               "control is satisfied - no scan can say that, and reading it that way "
               "is how a green dashboard ends up meaning nothing.")
    out.append("")

    if data["functions"]:
        out.append("## By CSF function")
        out.append("")
        out.append("| Function | Findings |")
        out.append("| --- | --- |")
        for function, count in data["functions"].items():
            out.append(f"| {function} | {count} |")
        out.append("")

    if data["nist_csf"]:
        out.append("## NIST CSF 2.0 subcategories")
        out.append("")
        out.append("| Subcategory | Function | Findings |")
        out.append("| --- | --- | --- |")
        for control, count in data["nist_csf"].items():
            out.append(f"| `{control}` | {function_of(control)} | {count} |")
        out.append("")

    if data["mitre_attack"]:
        out.append("## ATT&CK techniques")
        out.append("")
        out.append("Techniques an attacker could use the finding to perform. Useful for "
                   "checking a detection rule exists for each.")
        out.append("")
        out.append("| Technique | Findings |")
        out.append("| --- | --- |")
        for technique, count in data["mitre_attack"].items():
            out.append(f"| `{technique}` | {count} |")
        out.append("")

    if data["unmapped_cwes"]:
        out.append("## Unmapped")
        out.append("")
        out.append("Findings whose CWE has no entry in the table. Not an error - the "
                   "table covers what the rules emit and is refreshed deliberately.")
        out.append("")
        out.append(", ".join(f"`{cwe}`" for cwe in data["unmapped_cwes"]))
    return "\n".join(out)
