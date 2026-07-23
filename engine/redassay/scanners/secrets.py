"""Hardcoded credential detection.

Two detectors, deliberately different in character:

* **provider patterns** - `AKIA...`, `ghp_...`, `sk-...`. These have almost no
  false positive rate because the vendor designed the prefix to be unique. They
  ship at high confidence and high severity.
* **assignment + entropy** - `API_KEY = "aG9yc2ViYXR0ZXJ5c3RhcGxl"`. This is the
  noisy half. It is gated on three things at once: the variable name looks like a
  secret, the value is long enough, and its Shannon entropy is above a threshold
  that ordinary English and ordinary identifiers do not reach.

The placeholder filter matters more than either detector. Every repo is full of
`password = "changeme"` in an example config, and a tool that reports those gets
turned off.
"""

from __future__ import annotations

import math
import os
import re
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from ..models import Finding
from ..walker import SourceFile
from .base import ScanContext, Scanner
from .registry import register

# --- provider-specific tokens ------------------------------------------------
PROVIDER_PATTERNS: List[Tuple[str, str, str, str]] = [
    ("aws-access-key-id", r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b", "AWS access key id", "critical"),
    ("aws-secret-access-key", r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?", "AWS secret access key", "critical"),
    ("github-token", r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", "GitHub token", "critical"),
    ("github-fine-grained", r"\b(github_pat_[A-Za-z0-9_]{60,})\b", "GitHub fine-grained token", "critical"),
    ("gitlab-token", r"\b(glpat-[A-Za-z0-9\-_]{20,})\b", "GitLab personal access token", "critical"),
    ("slack-token", r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b", "Slack token", "high"),
    ("slack-webhook", r"(https://hooks\.slack\.com/services/T[A-Za-z0-9/+_-]{20,})", "Slack incoming webhook", "medium"),
    ("stripe-secret", r"\b(sk_(?:live|test)_[A-Za-z0-9]{16,})\b", "Stripe secret key", "critical"),
    ("stripe-restricted", r"\b(rk_(?:live|test)_[A-Za-z0-9]{16,})\b", "Stripe restricted key", "high"),
    ("openai-key", r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b", "OpenAI API key", "critical"),
    ("anthropic-key", r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b", "Anthropic API key", "critical"),
    ("google-api-key", r"\b(AIza[0-9A-Za-z\-_]{35})\b", "Google API key", "high"),
    ("gcp-service-account", r"\"type\"\s*:\s*\"service_account\"", "GCP service account key file", "critical"),
    ("firebase-key", r"\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b", "Firebase cloud messaging key", "high"),
    ("sendgrid-key", r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b", "SendGrid API key", "high"),
    ("twilio-sid", r"\b(AC[a-f0-9]{32})\b", "Twilio account SID", "medium"),
    ("mailgun-key", r"\b(key-[a-f0-9]{32})\b", "Mailgun API key", "high"),
    ("npm-token", r"\b(npm_[A-Za-z0-9]{36})\b", "npm access token", "high"),
    ("pypi-token", r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b", "PyPI upload token", "critical"),
    ("square-token", r"\b(sq0atp-[A-Za-z0-9_-]{22}|EAAA[A-Za-z0-9_-]{60})\b", "Square access token", "high"),
    ("shopify-token", r"\b(shp(at|ca|pa|ss)_[a-fA-F0-9]{32})\b", "Shopify token", "high"),
    ("private-key-block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", "Private key block", "critical"),
    ("jwt-literal", r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b", "Hardcoded JWT", "medium"),
    ("basic-auth-url", r"[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s:@]{4,})@", "Credentials embedded in a URL", "high"),
    ("db-conn-string", r"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:([^\s:@/]{4,})@", "Database connection string with a password", "high"),
    ("azure-storage-key", r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{60,})", "Azure storage account key", "critical"),
    ("heroku-key", r"(?i)heroku[a-z0-9_ .\-]{0,20}[:=]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", "Heroku API key", "high"),
]

# --- generic assignment detection -------------------------------------------
SECRET_NAME = re.compile(
    r"(?i)\b([\w.\-]*(?:secret|passwd|password|pwd|token|api[_-]?key|apikey|access[_-]?key"
    r"|auth[_-]?token|credential|private[_-]?key|client[_-]?secret|session[_-]?key"
    r"|encryption[_-]?key|signing[_-]?key|master[_-]?key|bearer)[\w.\-]*)\s*"
    r"(?::=|=|:|=>)\s*"
    r"[\"'`]([^\"'`\n]{6,200})[\"'`]"
)

PLACEHOLDER_VALUES = {
    "changeme", "change_me", "changethis", "password", "passwd", "secret",
    "your_password", "your-password", "yourpassword", "your_secret", "mysecret",
    "test", "testing", "test123", "example", "sample", "dummy", "placeholder",
    "none", "null", "nil", "undefined", "todo", "fixme", "xxx", "xxxx",
    "redacted", "hidden", "removed", "notset", "not_set", "empty", "default",
    "admin", "root", "user", "guest", "foo", "bar", "baz", "qwerty", "123456",
    "abc123", "letmein", "hunter2", "s3cr3t", "supersecret", "topsecret",
}

PLACEHOLDER_MARKERS = re.compile(
    r"(?i)(\{\{|\}\}|\$\{|<%|%>|\$\(|<[a-z_ ]+>|\byour[_ -]|\bmy[_ -]|xxx+|\*\*\*+|"
    r"\.\.\.|example\.com|localhost|replace[_ -]?me|insert[_ -]?|enter[_ -]?|"
    r"placeholder|redacted|process\.env|os\.environ|getenv|ENV\[|config\(|"
    r"secrets\.|vault|\bnull\b|\bnone\b)"
)

LOW_RISK_PATHS = re.compile(
    r"(?i)(^|/)(test|tests|spec|specs|fixtures?|examples?|samples?|docs?|mocks?|"
    r"__tests__|__mocks__|e2e|demo)(/|$)|\.(test|spec)\.[a-z]+$|"
    r"(^|/)(\.env\.(example|sample|template)|.*\.example|.*\.sample|.*\.template)$"
)

ENTROPY_FLOOR_BASE64 = 3.6
ENTROPY_FLOOR_HEX = 2.8
MIN_SECRET_LENGTH = 12


def shannon_entropy(value: str) -> float:
    """Bits per character. Random base64 sits near 6, English prose near 4."""
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def looks_like_placeholder(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    if stripped.lower() in PLACEHOLDER_VALUES:
        return True
    if PLACEHOLDER_MARKERS.search(stripped):
        return True
    if len(set(stripped)) <= 3:                     # "aaaaaaaa", "--------"
        return True
    if re.fullmatch(r"[\d.\-_ /:]+", stripped):     # versions, dates, numbers
        return True
    if re.fullmatch(r"(?i)[a-z_]+(\.[a-z_]+)+", stripped):   # dotted identifier
        return True
    if stripped.startswith(("/", "./", "../", "~/")) and " " not in stripped:
        return True
    return False


def is_high_entropy(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < MIN_SECRET_LENGTH:
        return False
    if re.fullmatch(r"[a-fA-F0-9]{16,}", stripped):
        return shannon_entropy(stripped) >= ENTROPY_FLOOR_HEX
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-.~]{12,}", stripped):
        return False
    return shannon_entropy(stripped) >= ENTROPY_FLOOR_BASE64


def redact(value: str, keep: int = 4) -> str:
    stripped = value.strip()
    if len(stripped) <= keep * 2:
        return "*" * len(stripped)
    return f"{stripped[:keep]}{'*' * 8}{stripped[-keep:]}"


@register
class SecretScanner(Scanner):
    name = "secrets"
    description = "Hardcoded credentials: provider tokens, key material, high-entropy assignments"

    def applies_to(self, source: SourceFile) -> bool:
        return source.language not in {"lockfile", "npm-lock", "yarn-lock", "poetry-lock", "cargo-lock", "go-lock", "composer-lock", "pip-lock"}

    def scan_file(self, source: SourceFile, context: ScanContext) -> Iterator[Finding]:
        from .. import suppress as suppress_mod

        lines = source.lines()
        low_risk = bool(LOW_RISK_PATHS.search(source.path))
        seen_values: set = set()

        for index, line in enumerate(lines):
            if len(line) > 4000:
                continue
            line_no = index + 1
            yielded_here = False

            for rule_slug, pattern, label, base_severity in PROVIDER_PATTERNS:
                match = re.search(pattern, line)
                if not match:
                    continue
                value = match.group(1) if match.groups() else match.group(0)
                if looks_like_placeholder(value):
                    continue
                if suppress_mod.suppressed_by_source(lines, line_no, f"secret.{rule_slug}"):
                    continue
                key = (rule_slug, value)
                if key in seen_values:
                    continue
                seen_values.add(key)
                severity = _downgrade(base_severity) if low_risk else base_severity
                yield self.make_finding(
                    rule_id=f"secret.{rule_slug}",
                    title=f"{label} committed to the repository",
                    source=source,
                    line=line_no,
                    snippet=_mask_line(line, value),
                    severity=severity,
                    confidence="low" if low_risk else "high",
                    description=(
                        f"A {label.lower()} appears in source. Treat it as compromised the moment it "
                        f"lands in version control - it is in the object history, on every clone, and "
                        f"in every CI cache."
                        + (" This path looks like test or example material, so the value may be fake."
                           if low_risk else "")
                    ),
                    remediation=(
                        "Revoke and rotate the credential first - removing the line does not un-leak it. "
                        "Then load it from the environment or a secret manager, and purge the history "
                        "if the repository is public."
                    ),
                    cwe=["CWE-798"],
                    owasp=["A07:2021 Identification and Authentication Failures"],
                    tags=["secrets", rule_slug],
                    scanner=self.name,
                )
                yielded_here = True

            if yielded_here:
                continue

            for match in SECRET_NAME.finditer(line):
                name, value = match.group(1), match.group(2)
                if looks_like_placeholder(value) or not is_high_entropy(value):
                    continue
                if suppress_mod.suppressed_by_source(lines, line_no, "secret.hardcoded-assignment"):
                    continue
                key = ("generic", value)
                if key in seen_values:
                    continue
                seen_values.add(key)
                severity = "low" if low_risk else "high"
                yield self.make_finding(
                    rule_id="secret.hardcoded-assignment",
                    title=f"High-entropy value assigned to '{name}'",
                    source=source,
                    line=line_no,
                    snippet=_mask_line(line, value),
                    severity=severity,
                    confidence="low" if low_risk else "medium",
                    description=(
                        f"'{name}' is assigned a {len(value)}-character literal with "
                        f"{shannon_entropy(value):.1f} bits of entropy per character. That is the "
                        "shape of a real credential rather than a placeholder."
                    ),
                    remediation=(
                        "Move the value into the environment or a secret manager and rotate it. "
                        "If it is genuinely not a secret, rename the variable or add "
                        "`# redassay: ignore secret.hardcoded-assignment` with the reason."
                    ),
                    cwe=["CWE-798"],
                    owasp=["A07:2021 Identification and Authentication Failures"],
                    tags=["secrets", "entropy"],
                    scanner=self.name,
                )

    def finalize(self, context: ScanContext) -> Iterator[Finding]:
        """Flag committed env files separately - the file itself is the problem."""
        for source in context.files:
            name = os.path.basename(source.path).lower()
            if not name.startswith(".env"):
                continue
            if LOW_RISK_PATHS.search(source.path) or name.endswith((".example", ".sample", ".template", ".dist")):
                continue
            body = source.read()
            populated = [
                ln for ln in body.splitlines()
                if "=" in ln and not ln.strip().startswith("#") and len(ln.split("=", 1)[1].strip().strip("\"'")) > 3
            ]
            if not populated:
                continue
            yield self.make_finding(
                rule_id="secret.env-file-committed",
                title=f"{source.path} is tracked in the repository",
                source=source,
                line=1,
                snippet=f"{len(populated)} populated variables",
                severity="high",
                confidence="high",
                description=(
                    f"{source.path} contains {len(populated)} populated variables and is present in "
                    "the working tree. Environment files are where the real credentials live, which "
                    "is exactly why they should never be committed."
                ),
                remediation=(
                    "Add it to .gitignore, rotate everything inside it, commit a .env.example with "
                    "empty values instead, and scrub it from history if it was ever pushed."
                ),
                cwe=["CWE-538"],
                owasp=["A05:2021 Security Misconfiguration"],
                tags=["secrets", "hygiene"],
                scanner=self.name,
            )


def _mask_line(line: str, value: str) -> str:
    return line.replace(value, redact(value)).strip()[:400]


_DOWNGRADE = {"critical": "medium", "high": "low", "medium": "low", "low": "info", "info": "info"}


def _downgrade(severity: str) -> str:
    return _DOWNGRADE.get(severity, "low")
