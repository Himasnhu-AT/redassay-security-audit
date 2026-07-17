"""Scanners turn files into findings.

Everything in here is deterministic. If a scanner needs a judgement call it does
not belong here - it belongs in the model-driven half of the pipeline, which
writes its findings in through `redassay add`.
"""

from .base import Scanner, ScanContext  # noqa: F401
from .registry import REGISTRY, register, get, available, build_all  # noqa: F401
