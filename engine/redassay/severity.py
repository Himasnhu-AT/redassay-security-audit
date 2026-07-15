"""Severity and confidence vocabulary.

Kept in one place because three different things need to agree on ordering: the
CLI exit code, the board's default filter, and the triage sorter.
"""

from __future__ import annotations

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO]
_RANK = {name: index for index, name in enumerate(ORDER)}

# Aliases we accept from rule packs and from external tools, normalized inward.
_ALIASES = {
    "crit": CRITICAL,
    "blocker": CRITICAL,
    "error": HIGH,
    "warning": MEDIUM,
    "moderate": MEDIUM,
    "med": MEDIUM,
    "minor": LOW,
    "note": INFO,
    "informational": INFO,
}


def normalize(value: object) -> str:
    """Coerce anything severity-shaped into one of the five canonical names."""
    if value is None:
        return MEDIUM
    text = str(value).strip().lower()
    text = _ALIASES.get(text, text)
    return text if text in _RANK else MEDIUM


def rank(value: object) -> int:
    """Lower rank means more severe. Useful as a sort key."""
    return _RANK[normalize(value)]


def at_least(value: object, floor: object) -> bool:
    """True when ``value`` is at least as severe as ``floor``."""
    return rank(value) <= rank(floor)


def cvss_band(score: float) -> str:
    """Map a CVSS base score onto our vocabulary."""
    if score >= 9.0:
        return CRITICAL
    if score >= 7.0:
        return HIGH
    if score >= 4.0:
        return MEDIUM
    if score > 0.0:
        return LOW
    return INFO
