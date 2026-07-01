# Contributing to fya

Thanks for your interest in improving `fya`. Issues and pull requests are
welcome. New checks should be small, mapped to OWASP and CWE, and
non-destructive by default. Please read [SECURITY.md](SECURITY.md) before adding
anything that sends probes to a target.

## The website is off-limits

The `web/` folder (the Next.js site) is maintained by the project owner and is
not open to outside contributions. A required `guard-web` check fails any pull
request that changes files under `web/`. To suggest a website change, open an
issue describing it instead.

## Development setup

`fya` targets Python 3.9 and above. Its core dependencies are just `requests`
and `rich`; everything heavier is an optional extra.

Clone the repository and install it in editable mode with the dev extra, which
pulls in `pytest`, `ruff`, and `flask` (the bundled vulnerable app used for
manual testing):

```bash
python -m venv .venv
source .venv/bin/activate        # on Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

To work on the Android APK checks, also install the `apk` extra, which pulls in
`androguard`:

```bash
pip install -e ".[dev,apk]"
```

## Running the tests and linter

The test suite lives in `tests/` and runs under `pytest`:

```bash
pytest
```

Lint and import-sort checks run under `ruff`:

```bash
ruff check .
```

Ruff is configured in `pyproject.toml` with a 100 character line length and the
`E`, `F`, `I`, and `B` rule sets (with `E501` ignored). Run both `pytest`
and `ruff check .` before you submit a pull request.

## Trying a change against the bundled vulnerable app

There is a deliberately vulnerable Flask app for local testing:

```bash
python examples/vulnerable_app.py          # starts on http://127.0.0.1:5001
fya scan http://127.0.0.1:5001 -o report.html
```

Localhost targets need no authorization flag, so this is the fastest way to see
a new check fire.

## Add a check in one file

Checks are discovered automatically. Every module in `fya/checks/` is imported
at startup, and any class decorated with `@register` is added to the registry.
There is no central list to edit.

A check subclasses `Check` (from `fya/registry.py`), sets a few class
attributes, and implements `run`, which yields `Finding` objects. The base
class handles filtering: a check runs only when the target kind matches its
`target_kinds` and the active profile is at least its `min_profile`.

The class attributes:

- `name`: unique dotted id, for example `web.my_check`. Required; registration
  fails without it. By convention the prefix names the area (`web`, `api`,
  `tls`, `apk`, `integrations`).
- `title`: short human label.
- `target_kinds`: a tuple of `TargetKind` values the check applies to, for
  example `(TargetKind.WEB,)` or `(TargetKind.APK,)`.
- `min_profile`: the lowest `Profile` at which the check runs. Passive checks
  must be read-only; active probing belongs at `Profile.SAFE` or higher.

The `run` method receives a `ScanContext` (`ctx`) that gives you:

- `ctx.target`: the `Target`. Use `ctx.target.base_url()` for the scheme, host,
  and port, `ctx.target.url` for the full URL, `ctx.target.host`, and
  `ctx.target.apk_path` for APK targets. `ctx.target.fingerprint` holds the tech
  fingerprint gathered before checks run.
- `ctx.http`: the shared `AdaptiveHTTP` client for web targets. Use
  `ctx.http.get`, `.post`, `.head`, or `.request(method, url, ...)`. It returns
  `None` on a failed request, so always guard for that. It also throttles
  itself, so do not add your own sleeps. `ctx.http.marker()` gives a random
  `fya`-prefixed token for safe, identifiable injection probes.
- `ctx.profile`: the active `Profile`, useful for scaling effort (for example a
  larger crawl cap under `aggressive`).
- `ctx.tools`: detected external tools keyed by name, each with a `path`.
- `ctx.options` and `ctx.emit_log(msg)` for scan options and progress logging.

A `Finding` is a dataclass; the important fields are `check`, `title`,
`severity` (a `Severity`), `description`, and ideally `category` (OWASP or
MASVS), `cwe`, `confidence`, `remediation`, `location`, `evidence`, and
`references`. If you leave `target` empty the engine fills it in. Findings are
de-duplicated by the engine on a hash of check, title, target, and location.

A complete example. Drop this in `fya/checks/web_extra.py`:

```python
from __future__ import annotations

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register


@register
class PoweredByHeader(Check):
    name = "web.powered_by_header"
    title = "X-Powered-By header present"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        response = ctx.http.get(base)
        if response is None:
            return
        value = response.headers.get("x-powered-by")
        if value:
            yield Finding(
                check=self.name,
                title="X-Powered-By header discloses technology",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-200",
                description="The X-Powered-By header advertises server technology, "
                "which helps an attacker fingerprint the stack.",
                remediation="Suppress the X-Powered-By header at the app or proxy layer.",
                location=base,
                evidence=f"X-Powered-By: {value}",
                references=["https://owasp.org/www-project-secure-headers/"],
            )
```

That is the whole contract. On the next scan of a web target at any profile,
the check is discovered, selected, run in the thread pool, and its findings are
normalized and reported. Add a matching test under `tests/` and run `pytest`
and `ruff check .` before opening the pull request.

## Pull request checklist

- The change is small and focused.
- New checks are non-destructive and set an appropriate `min_profile`.
- Findings carry a `category` (OWASP or MASVS) and a `cwe` where one applies.
- The change does not modify `web/` (owner-maintained, blocked on pull requests).
- `pytest` passes.
- `ruff check .` is clean.
