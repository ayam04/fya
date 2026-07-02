from __future__ import annotations

from .detect import is_local
from .models import Target, TargetKind

NOTICE = (
    "fya performs active security testing. Only scan systems you own or are "
    "explicitly authorized in writing to test. Unauthorized scanning may be "
    "illegal. You are responsible for how you use this tool."
)


def authorize(target: Target, authorized: bool) -> tuple[bool, str]:
    if target.kind is TargetKind.APK:
        return True, "local APK analysis"
    if target.kind is TargetKind.SOURCE:
        return True, "local source analysis"
    if is_local(target.host or ""):
        return True, f"local target {target.host}"
    if authorized:
        return True, "authorization asserted by operator"
    return (
        False,
        (
            f"target {target.host} is not local. Re-run with --i-am-authorized to "
            "confirm you have written permission to test it."
        ),
    )
