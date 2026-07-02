from __future__ import annotations

import argparse
import sys

from . import __version__, baseline, report
from .authorization import NOTICE, authorize
from .detect import detect_target
from .engine import run_scan
from .models import Profile

_EXT_FORMAT = {".json": "json", ".sarif": "sarif", ".md": "markdown", ".html": "html"}

ALL_CATEGORIES = {"web", "tls", "api", "apk", "integrations", "blackbox", "graybox", "whitebox"}

MODES = {
    "auto": {"categories": None, "profile": None},
    "recon": {"categories": {"web", "tls", "apk"}, "profile": "passive"},
    "web": {"categories": {"web", "tls", "api"}, "profile": None},
    "api": {"categories": {"api", "web"}, "profile": None},
    "mobile": {"categories": {"apk"}, "profile": None},
    "blackbox": {"categories": {"blackbox", "web", "tls"}, "profile": None},
    "graybox": {"categories": {"graybox", "api"}, "profile": None},
    "whitebox": {"categories": {"whitebox"}, "profile": None},
    "full": {"categories": ALL_CATEGORIES, "profile": "aggressive"},
}

MODE_DESC = {
    "auto": "everything that applies to the detected target (default)",
    "recon": "passive, read-only reconnaissance",
    "web": "web app: headers, TLS, active web checks, and API",
    "api": "API surface plus supporting web checks",
    "mobile": "Android APK static analysis",
    "blackbox": "no internals: input fuzzing and robustness plus outside-in web checks",
    "graybox": "partial knowledge: IDOR, auth bypass, and API contract probing",
    "whitebox": "source access: static analysis of a code directory (secrets, risky sinks)",
    "full": "everything, aggressive, including external tool handoff",
}

_CAT_LABEL = {
    "web": "web",
    "tls": "tls",
    "api": "api",
    "apk": "apk",
    "integrations": "tools",
    "blackbox": "black",
    "graybox": "gray",
    "whitebox": "white",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fya",
        description="Point it at your app, it tries to break it.",
    )
    parser.add_argument("--version", action="version", version=f"fya {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a localhost/URL server, an .apk file, or a source directory")
    scan.add_argument("target", help="URL, host:port, path to an .apk, or a source code directory")
    scan.add_argument(
        "--mode",
        choices=list(MODES),
        default="auto",
        help="which family of checks to run: " + ", ".join(MODES),
    )
    scan.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="pick the mode and profile from a menu before scanning",
    )
    scan.add_argument("--only", help="comma-separated categories to include (web,tls,api,apk,integrations,blackbox,graybox,whitebox)")
    scan.add_argument("--skip", help="comma-separated categories to exclude")
    scan.add_argument(
        "--profile",
        choices=[p.value for p in Profile],
        default=None,
        help="passive: read-only; safe: non-destructive (default); aggressive: heavier probes",
    )
    scan.add_argument("--output", "-o", help="write a report file (format inferred from extension)")
    scan.add_argument(
        "--format",
        "-f",
        choices=["console", "json", "sarif", "md", "markdown", "html"],
        help="report format for --output, or console",
    )
    scan.add_argument("--i-am-authorized", action="store_true", help="assert written permission for non-local targets")
    scan.add_argument("--timeout", type=float, default=12.0)
    scan.add_argument("--workers", type=int, default=8)
    scan.add_argument("--proxy", help="route web traffic through an HTTP proxy, e.g. http://127.0.0.1:8080")
    scan.add_argument("--header", "-H", action="append", metavar="'Name: value'", help="extra request header for authenticated scans, repeatable")
    scan.add_argument("--cookie", help="cookies to send: 'name=value; name2=value2'")
    scan.add_argument("--bearer", help="shortcut for an Authorization: Bearer <token> header")
    scan.add_argument("--include", action="append", metavar="REGEX", help="only request paths matching this regex, repeatable")
    scan.add_argument("--exclude", action="append", metavar="REGEX", help="never request paths matching this regex, repeatable")
    scan.add_argument("--max-requests", type=int, default=0, help="stop after this many HTTP requests (0 = no cap)")
    scan.add_argument("--spa", action="store_true", help="render pages with a headless browser to crawl JS/SPA apps (needs the [browser] extra)")
    scan.add_argument("--baseline", help="suppress findings whose ids are listed in this baseline JSON file")
    scan.add_argument("--write-baseline", help="write the current findings to this baseline JSON file")
    scan.add_argument("--verify-tls", action="store_true", help="verify TLS certs during crawling (off by default)")
    scan.add_argument("--no-tools", action="store_true", help="skip detection of external tools")
    scan.add_argument("--no-animate", action="store_true", help="disable the live progress animation")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="exit 2 if a finding at or above this severity is found")
    scan.add_argument("--quiet", "-q", action="store_true")
    scan.add_argument("--verbose", "-v", action="store_true")

    sub.add_parser("tools", help="list external security tools fya can use")
    sub.add_parser("modes", help="list the available scan modes")
    return parser


def _pick_interactive(console, args) -> None:
    from rich.prompt import Prompt
    from rich.table import Table

    table = Table(title="scan modes", border_style="grey37", header_style="bold")
    table.add_column("mode")
    table.add_column("what it runs", style="grey62")
    for name, desc in MODE_DESC.items():
        table.add_row(name, desc)
    console.print(table)
    args.mode = Prompt.ask("mode", choices=list(MODES), default=args.mode or "auto")
    default_profile = MODES[args.mode]["profile"] or args.profile or Profile.SAFE.value
    args.profile = Prompt.ask(
        "profile", choices=[p.value for p in Profile], default=default_profile
    )


def _resolve_scope(args) -> tuple[str, set]:
    mode = MODES[args.mode]
    profile = args.profile or mode["profile"] or Profile.SAFE.value

    categories = mode["categories"]
    if args.only:
        categories = {c.strip() for c in args.only.split(",") if c.strip()}
    if args.skip:
        base = set(categories) if categories else set(ALL_CATEGORIES)
        categories = base - {c.strip() for c in args.skip.split(",") if c.strip()}
    if categories is not None and set(categories) == ALL_CATEGORIES:
        categories = None
    return profile, categories


def _parse_headers(pairs):
    headers = {}
    for item in pairs or []:
        if ":" in item:
            name, value = item.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers


def _parse_cookies(raw):
    cookies = {}
    for part in (raw or "").split(";"):
        if "=" in part:
            name, value = part.split("=", 1)
            cookies[name.strip()] = value.strip()
    return cookies


def _run_scan(args) -> int:
    from rich.console import Console

    console = Console(stderr=True)
    target = detect_target(args.target)

    ok, reason = authorize(target, args.i_am_authorized)
    if not ok:
        console.print(f"[red]refusing to scan:[/] {reason}")
        console.print(f"[grey50]{NOTICE}[/]")
        return 1

    if args.interactive and sys.stdin.isatty():
        _pick_interactive(console, args)
    profile, categories = _resolve_scope(args)

    if not args.quiet:
        console.print(
            f"[grey50]authorized:[/] {reason}    "
            f"[grey50]mode[/] [bold]{args.mode}[/]    [grey50]profile[/] [bold]{profile}[/]"
        )

    def log(message: str) -> None:
        if args.verbose:
            console.print(f"· {message}", style="grey42", markup=False)

    animate = not args.quiet and not args.no_animate
    extra_headers = _parse_headers(args.header)
    if args.bearer:
        extra_headers["Authorization"] = f"Bearer {args.bearer}"
    scan_kwargs = dict(
        profile=Profile(profile),
        options={
            "timeout": args.timeout,
            "workers": args.workers,
            "proxy": args.proxy,
            "verify": args.verify_tls,
            "headers": extra_headers or None,
            "cookies": _parse_cookies(args.cookie) or None,
            "include": args.include,
            "exclude": args.exclude,
            "max_requests": args.max_requests,
            "spa": args.spa,
        },
        log=log,
        detect_external=not args.no_tools,
        categories=categories,
    )

    if animate:
        result = _run_animated(console, target, scan_kwargs)
    else:
        result = run_scan(target, **scan_kwargs)

    if args.write_baseline:
        count = baseline.save(args.write_baseline, result)
        if not args.quiet:
            console.print(f"[grey50]baseline written:[/] {args.write_baseline} ({count} findings)")
    suppressed = baseline.apply(result, baseline.load(args.baseline)) if args.baseline else 0

    if not args.quiet:
        report.render_console(result)
        if suppressed:
            console.print(f"[grey50]suppressed {suppressed} finding(s) via baseline[/]")

    if args.output:
        fmt = args.format
        if not fmt or fmt == "console":
            ext = args.output[args.output.rfind(".") :].lower()
            fmt = _EXT_FORMAT.get(ext, "json")
        report.write_report(result, "markdown" if fmt == "md" else fmt, args.output)
        if not args.quiet:
            console.print(f"[grey50]report written:[/] {args.output}")
    elif args.format and args.format != "console":
        fmt = "markdown" if args.format == "md" else args.format
        print(report.render(result, fmt))

    return report.exit_code(result, args.fail_on)


def _run_animated(console, target, scan_kwargs):
    from collections import Counter

    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
    )

    progress = Progress(
        SpinnerColumn(style="red"),
        TextColumn("[bold]{task.fields[label]:<6}"),
        BarColumn(bar_width=22, complete_style="cyan", finished_style="green"),
        MofNCompleteColumn(),
        TextColumn("[grey62]{task.fields[found]} found"),
        console=console,
        transient=True,
    )
    tasks = {}
    found = {}

    def on_plan(checks):
        per = Counter(c.name.split(".")[0] for c in checks)
        for cat, total in sorted(per.items()):
            found[cat] = 0
            tasks[cat] = progress.add_task(
                "", total=total, label=_CAT_LABEL.get(cat, cat), found=0
            )

    def on_check_done(name, category, n):
        found[category] = found.get(category, 0) + n
        if category in tasks:
            progress.advance(tasks[category])
            progress.update(tasks[category], found=found[category])

    with progress:
        return run_scan(
            target, on_plan=on_plan, on_check_done=on_check_done, **scan_kwargs
        )


def _list_tools() -> int:
    from rich.console import Console

    from .tools import detect_tools

    console = Console()
    found = detect_tools()
    if not found:
        console.print("no external tools detected on PATH. fya runs its built-in checks regardless.")
        console.print("optional: nuclei, nikto, sqlmap, nmap, testssl.sh, sslyze, jadx, apkleaks")
        return 0
    for name, meta in sorted(found.items()):
        console.print(f"[green]{name}[/]  {meta.get('version', '')}")
    return 0


def _list_modes() -> int:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="fya scan modes", border_style="grey37", header_style="bold")
    table.add_column("mode")
    table.add_column("what it runs", style="grey62")
    for name, desc in MODE_DESC.items():
        table.add_row(name, desc)
    console.print(table)
    console.print(
        "[grey50]note: fya does not run load/stress or network-chaos tests. They are "
        "denial-of-service shaped and violate the non-destructive guarantee. Use k6, "
        "Locust, or Toxiproxy for those, on infrastructure you own.[/]"
    )
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            return _run_scan(args)
        except KeyboardInterrupt:
            return 130
    if args.command == "tools":
        return _list_tools()
    if args.command == "modes":
        return _list_modes()
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
