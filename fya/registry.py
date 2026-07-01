from __future__ import annotations

import importlib
import pkgutil
from typing import Iterable, List, Type

from .models import Finding, Profile, ScanContext, profile_rank

_REGISTRY: List[Type["Check"]] = []
_DISCOVERED = False


class Check:
    name: str = ""
    title: str = ""
    target_kinds: tuple = ()
    min_profile: Profile = Profile.PASSIVE

    def applies(self, ctx: ScanContext) -> bool:
        if self.target_kinds and ctx.target.kind not in self.target_kinds:
            return False
        if profile_rank(ctx.profile) < profile_rank(self.min_profile):
            return False
        return True

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        raise NotImplementedError


def register(cls: Type[Check]) -> Type[Check]:
    if not getattr(cls, "name", ""):
        raise ValueError(f"check {cls.__name__} is missing a name")
    _REGISTRY.append(cls)
    return cls


def _load_plugins() -> None:
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return
    try:
        eps = entry_points()
        selected = eps.select(group="fya.checks") if hasattr(eps, "select") else eps.get("fya.checks", [])
    except Exception:
        return
    for ep in selected:
        try:
            ep.load()
        except Exception:
            continue


def discover() -> None:
    global _DISCOVERED
    if _DISCOVERED:
        return
    from . import checks as checks_pkg

    for module in pkgutil.iter_modules(checks_pkg.__path__):
        importlib.import_module(f"{checks_pkg.__name__}.{module.name}")
    _load_plugins()
    _DISCOVERED = True


def all_checks() -> List[Type[Check]]:
    discover()
    return list(_REGISTRY)


def applicable_checks(ctx: ScanContext) -> List[Check]:
    selected = []
    for cls in all_checks():
        instance = cls()
        if instance.applies(ctx):
            selected.append(instance)
    return selected
