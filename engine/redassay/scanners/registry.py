"""Scanner registry. Import a scanner module and it registers itself."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Type

from .base import Scanner

REGISTRY: Dict[str, Type[Scanner]] = {}


def register(cls: Type[Scanner]) -> Type[Scanner]:
    REGISTRY[cls.name] = cls
    return cls


def get(name: str) -> Optional[Type[Scanner]]:
    return REGISTRY.get(name)


def available() -> List[str]:
    _load_builtin()
    return sorted(REGISTRY)


def describe() -> List[Dict[str, str]]:
    _load_builtin()
    return [
        {"name": name, "description": cls.description}
        for name, cls in sorted(REGISTRY.items())
    ]


def build_all(
    include: Optional[Sequence[str]] = None,
    exclude: Optional[Sequence[str]] = None,
    **options: Any,
) -> List[Scanner]:
    _load_builtin()
    names = list(include) if include else sorted(REGISTRY)
    skip = set(exclude or ())
    built: List[Scanner] = []
    for name in names:
        if name in skip:
            continue
        cls = REGISTRY.get(name)
        if cls is None:
            raise KeyError(f"unknown scanner: {name}")
        built.append(cls(**options))
    return built


_loaded = False


def _load_builtin() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    from . import pattern, secrets, python_ast, javascript, deps, configs, cicd  # noqa: F401
