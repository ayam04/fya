from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from .fingerprint import fingerprint_web
from .http import AdaptiveHTTP
from .models import Finding, Profile, ScanContext, ScanResult, Target, TargetKind, now
from .registry import applicable_checks
from .tools import detect_tools


def run_scan(
    target: Target,
    profile: Profile = Profile.SAFE,
    options: Optional[dict] = None,
    log: Optional[Callable[[str], None]] = None,
    detect_external: bool = True,
) -> ScanResult:
    options = dict(options or {})
    result = ScanResult(target=target, profile=profile)
    log = log or (lambda _msg: None)

    http = None
    if target.kind is TargetKind.WEB:
        http = AdaptiveHTTP(
            timeout=options.get("timeout", 12.0),
            verify=options.get("verify", False),
            proxy=options.get("proxy"),
            base_interval=options.get("base_interval", 0.05),
            allow_redirects=options.get("allow_redirects", True),
        )

    tools = detect_tools() if detect_external else {}
    result.tool_versions = {name: meta.get("version", "") for name, meta in tools.items()}

    ctx = ScanContext(
        target=target,
        profile=profile,
        http=http,
        options=options,
        tools=tools,
        log=log,
    )

    if target.kind is TargetKind.WEB and http is not None:
        log("fingerprinting target")
        target.fingerprint = fingerprint_web(ctx)
        if target.fingerprint.get("reachable") is False:
            result.errors.append("target did not respond to the initial request")

    checks = applicable_checks(ctx)
    result.checks_run = sorted(c.name for c in checks)
    log(f"running {len(checks)} checks at profile={profile.value}")

    max_workers = int(options.get("workers", 8))
    seen = set()

    def _run_one(check):
        try:
            return check.name, list(check.run(ctx)), None
        except Exception:
            return check.name, [], traceback.format_exc(limit=4)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_run_one, c) for c in checks]
        for future in as_completed(futures):
            name, findings, error = future.result()
            if error:
                result.errors.append(f"{name}: {error.strip().splitlines()[-1]}")
                log(f"check {name} failed")
                continue
            for finding in findings:
                if not isinstance(finding, Finding):
                    continue
                if not finding.target:
                    finding.target = target.label()
                fkey = finding.key()
                if fkey in seen:
                    continue
                seen.add(fkey)
                result.findings.append(finding)

    if http is not None:
        result.tool_versions["_requests"] = str(http.request_count)
        http.close()

    result.finished_at = now()
    log(f"done: {len(result.findings)} findings in {result.duration_seconds():.1f}s")
    return result
