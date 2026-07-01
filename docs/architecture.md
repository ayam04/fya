# Architecture

`fya` is a dynamic scanner built from small, independent parts. You point it at
a target, it works out what the target is, tunes itself, runs a set of checks
that fit, normalizes every finding, and reports. This document describes each
part and how a scan flows through them.

## Module map

```
fya/
  models.py        finding, target, profile, scan-result data models
  detect.py        target-kind detection (web vs apk) and locality
  fingerprint.py   web tech fingerprinting used to tune checks
  http.py          adaptive, self-throttling HTTP client
  registry.py      the Check base class and auto-discovery
  engine.py        orchestrator: fingerprint, plan, run in parallel, collect
  authorization.py the scope and consent gate
  tools.py         detection and bounded subprocess handoff to external tools
  report.py        console / json / sarif / markdown / html reporters
  cli.py           argument parsing and command wiring
  checks/          one file per area, auto-registered on import
```

## The data models

`fya/models.py` defines the vocabulary the rest of the code shares:

- `Severity` (`info` to `critical`) and `Confidence` (`low` to `high`), both
  ordered so results can be ranked and thresholded.
- `TargetKind` (`web`, `apk`) and `Profile` (`passive`, `safe`, `aggressive`),
  with helper ranks for comparison.
- `Target`: the resolved target, including scheme, host, port, url or apk path,
  and a `fingerprint` dict filled in before checks run. `base_url()` and
  `label()` are the accessors checks use.
- `Finding`: a single result, with a `key()` that hashes check, title, target,
  and location for de-duplication, and `to_dict()` for serialization.
- `ScanContext`: the object passed to every check, carrying the target, the
  profile, the HTTP client, detected tools, options, and a log callback.
- `ScanResult`: the accumulated output, with severity `counts()`,
  `sorted_findings()`, `worst_severity()`, and `to_dict()`.

## Detection

`fya/detect.py` decides what the raw target argument is. A path that ends in
`.apk`, or any zip file that contains an `AndroidManifest.xml`, is treated as an
APK target. Otherwise it is parsed as a web target: a bare host gets a scheme
inferred (`http` for local hosts, `https` otherwise) and a default port. The
same module decides locality (`localhost`, loopback and private IPs, and
`.local` names), which the authorization gate depends on.

## Fingerprinting

For web targets, `fya/fingerprint.py` makes the first requests and derives a
picture of the stack from what comes back: the `Server` and `X-Powered-By`
headers, the content type, the page title, cookie names, and body markers. It
matches these against a signature table to name technologies (Express, Django,
Laravel, WordPress, Next.js, and so on), guesses whether the target is a JSON or
GraphQL API, and notes any WAF hint (Cloudflare, Akamai, Sucuri). The result is
stored on `target.fingerprint` and is available to every check.

## Adaptive request pacing

All web traffic goes through one `AdaptiveHTTP` client in `fya/http.py`. It is
the safety and politeness layer:

- A single monotonic rate gate serializes requests behind a per-request
  interval, protected by a lock so concurrent checks share one pace.
- The interval starts small (0.05s) and moves between that floor and a 3.0s
  ceiling. After each request the client adapts: it multiplies the interval up
  on a failure, a slow response (over 2.5s), or a backpressure status (`429`,
  `502`, `503`, `504`), and eases it back down on healthy responses.
- Retries are bounded (total 2, with backoff) and never raise on status.
- Failed requests return `None` rather than throwing, so checks stay simple.
- `marker()` produces a random `fya`-prefixed token for identifiable probes.

Because every check shares this one client, raising the worker count cannot
outrun the pacing. This is what keeps `fya` from behaving like a flood.

## The check registry

`fya/registry.py` holds the plugin model. `Check` is the base class: it carries
`name`, `title`, `target_kinds`, and `min_profile`, and its `applies(ctx)`
method returns true only when the target kind matches and the active profile is
at or above the check's minimum. `run(ctx)` is the method each check implements,
yielding `Finding` objects.

`@register` appends a check class to the registry (and rejects any class without
a `name`). `discover()` imports every module under `fya/checks/` once, which
triggers those decorators, so dropping a new file into that package is enough to
register its checks. `applicable_checks(ctx)` instantiates every registered
check and returns the ones whose `applies(ctx)` is true for this scan.

## The engine

`fya/engine.py` is the orchestrator. `run_scan()` does the following:

1. Build a `ScanResult` and, for web targets, construct the shared
   `AdaptiveHTTP` client from the scan options.
2. Detect external tools (unless disabled) and record their versions.
3. Assemble the `ScanContext`.
4. For web targets, fingerprint the target and record if it was unreachable.
5. Select the applicable checks and record their names.
6. Run the checks concurrently in a bounded `ThreadPoolExecutor` (default 8
   workers). Each check runs in isolation; an exception is caught, its last line
   is recorded as a scan error, and other checks keep going.
7. Collect yielded findings, fill in a missing target label, and de-duplicate by
   `Finding.key()`.
8. Close the HTTP client, stamp the finish time, and return the `ScanResult`.

## Authorization

Before any of that runs, `fya/authorization.py` gates the scan. APK analysis and
local web targets are allowed. A non-local web target is refused unless the
operator passes `--i-am-authorized`. The gate returns a decision and a
human-readable reason, which the CLI prints.

## External tools

`fya/tools.py` locates known external tools on `PATH`
(`nuclei`, `nikto`, `sqlmap`, `nmap`, `testssl.sh`, `sslyze`, `jadx`,
`apkleaks`), reads their versions, and provides a `run()` wrapper that executes
a subprocess with a bounded timeout and captured output. The integration checks
in `fya/checks/integrations.py` use this to hand off at the `aggressive`
profile and fold the tool output back into normal findings.

## Reporting

`fya/report.py` renders a `ScanResult` in several formats: a rich console table,
JSON, SARIF 2.1 (for CI code scanning), Markdown, and a self-contained dark-mode
HTML page. Findings are always shown worst-first. `exit_code()` implements
`--fail-on`: it returns `2` when any finding meets or exceeds the requested
severity, so a scan can gate a CI job.

## Data flow, end to end

```
raw target
  -> detect_target()            decide web vs apk, resolve host/port/url
  -> authorize()                allow local/apk; require flag for remote
  -> run_scan()
       -> AdaptiveHTTP           shared, self-throttling client (web only)
       -> detect_tools()         optional external tool discovery
       -> fingerprint_web()      tech stack, api hint, waf hint (web only)
       -> applicable_checks()    filter registry by target kind + profile
       -> ThreadPoolExecutor     run checks concurrently, isolate failures
            each Check.run(ctx)  -> yields Finding(s)
       -> de-duplicate           by Finding.key()
  -> ScanResult
  -> report.render/write         console / json / sarif / markdown / html
  -> exit_code()                 --fail-on gate for CI
```
