from __future__ import annotations

import argparse
import sys

from . import __version__, report
from .authorization import NOTICE, authorize
from .detect import detect_target
from .engine import run_scan
from .models import Profile

_EXT_FORMAT = {".json": "json", ".sarif": "sarif", ".md": "markdown", ".html": "html"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fya",
        description="Point it at your app, it tries to break it.",
    )
    parser.add_argument("--version", action="version", version=f"fya {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a localhost/URL server or an .apk file")
    scan.add_argument("target", help="URL, host:port, or path to an .apk")
    scan.add_argument(
        "--profile",
        choices=[p.value for p in Profile],
        default=Profile.SAFE.value,
        help="passive: read-only; safe: non-destructive probes (default); aggressive: heavier probes",
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
    scan.add_argument("--verify-tls", action="store_true", help="verify TLS certs during crawling (off by default)")
    scan.add_argument("--no-tools", action="store_true", help="skip detection of external tools")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="exit 2 if a finding at or above this severity is found")
    scan.add_argument("--quiet", "-q", action="store_true")
    scan.add_argument("--verbose", "-v", action="store_true")

    sub.add_parser("tools", help="list external security tools fya can use")
    return parser


def _run_scan(args) -> int:
    from rich.console import Console

    console = Console(stderr=True)
    target = detect_target(args.target)

    ok, reason = authorize(target, args.i_am_authorized)
    if not ok:
        console.print(f"[red]refusing to scan:[/] {reason}")
        console.print(f"[grey50]{NOTICE}[/]")
        return 1
    if not args.quiet:
        console.print(f"[grey50]authorized:[/] {reason}")

    def log(message: str) -> None:
        if args.verbose:
            console.print(f"[grey42]· {message}[/]")

    result = run_scan(
        target,
        profile=Profile(args.profile),
        options={
            "timeout": args.timeout,
            "workers": args.workers,
            "proxy": args.proxy,
            "verify": args.verify_tls,
        },
        log=log,
        detect_external=not args.no_tools,
    )

    if not args.quiet:
        report.render_console(result)

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
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
