from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from .web_active import _AGGRESSIVE_CRAWL_CAP, _SAFE_CRAWL_CAP, _discover, _set_param

_XPATH_SIGS = [
    "org.apache.xpath", "javax.xml.xpath", "system.xml.xpath", "xpathexception",
    "expression must evaluate to a node-set", "invalid xpath", "xpath error", "unclosed token",
]
_LDAP_SIGS = [
    "javax.naming.namingexception", "com.sun.jndi.ldap", "invalid dn syntax",
    "bad search filter", "ldap: error code", "invalid attribute syntax",
]


def _cap(ctx):
    return _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP


def _op_probe(url, param, expr):
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    query = urlencode(pairs)
    fragment = f"{param}{expr}"
    query = (query + "&" + fragment) if query else fragment
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def _stable(a, b) -> bool:
    if a is None or b is None or a.status_code != b.status_code:
        return False
    la, lb = len(a.text or ""), len(b.text or "")
    return abs(la - lb) <= max(24, int(0.05 * max(la, lb, 1)))


def _sig_hit(body, baseline, sigs):
    low = body.lower()
    base = baseline.lower()
    return next((s for s in sigs if s in low and s not in base), "")


@register
class NoSqlInjection(Check):
    name = "web.nosql_injection"
    title = "NoSQL injection"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        emitted = 0
        seen = set()
        for url, params in _discover(ctx, _cap(ctx), set()):
            for param in params:
                if not param or emitted >= 5 or param.lower() in ("page", "limit", "offset", "size"):
                    continue
                r1 = ctx.http.get(_set_param(url, param, ctx.http.marker()))
                r2 = ctx.http.get(_set_param(url, param, ctx.http.marker()))
                if not _stable(r1, r2):
                    continue
                token = ctx.http.marker()
                probe = ctx.http.get(_op_probe(url, param, f"[$ne]={token}"))
                if probe is None:
                    continue
                pbody = probe.text or ""
                if "$ne" in pbody or "[$ne]" in pbody:
                    continue
                base_len = len(r1.text or "")
                plen = len(pbody)
                status_changed = probe.status_code != r1.status_code and probe.status_code < 500
                len_changed = abs(plen - base_len) > max(200, int(0.30 * max(base_len, 1)))
                if not (status_changed or len_changed):
                    continue
                location = f"{url} [param: {param}]"
                if location in seen:
                    continue
                seen.add(location)
                emitted += 1
                yield Finding(
                    check=self.name,
                    title=f"Possible NoSQL injection via parameter '{param}'",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM if status_changed else Confidence.LOW,
                    category="A03:2021 Injection",
                    cwe="CWE-943",
                    description=f"Replacing the '{param}' value with a MongoDB-style operator "
                    f"({param}[$ne]=...) changed the response compared with two stable baselines, which "
                    "indicates the input reaches a NoSQL query as an operator rather than a plain value.",
                    remediation="Reject query/body values that are objects where scalars are expected, cast "
                    "inputs to the intended type, and use an ODM that disallows operator injection.",
                    location=location,
                    evidence=f"baseline {r1.status_code}/{base_len}b vs $ne {probe.status_code}/{plen}b",
                    references=["https://portswigger.net/web-security/nosql-injection"],
                )


@register
class XpathLdapSsiInjection(Check):
    name = "web.xpath_ldap_ssi_injection"
    title = "XPath / LDAP / SSI injection"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        emitted = 0
        seen = set()
        for url, params in _discover(ctx, _cap(ctx), set()):
            for param in params:
                if not param or emitted >= 6:
                    continue
                location = f"{url} [param: {param}]"
                if location in seen:
                    continue
                baseline = ctx.http.get(_set_param(url, param, "1"))
                base_body = baseline.text or "" if baseline is not None else ""

                xp = ctx.http.get(_set_param(url, param, "'\""))
                xp_sig = _sig_hit(xp.text or "", base_body, _XPATH_SIGS) if xp is not None else ""
                if xp_sig:
                    seen.add(location)
                    emitted += 1
                    yield self._finding(param, location, "XPath", "CWE-643", xp_sig,
                                        "user input is concatenated into an XPath query")
                    continue

                ld = ctx.http.get(_set_param(url, param, ")(cn=*)"))
                ld_sig = _sig_hit(ld.text or "", base_body, _LDAP_SIGS) if ld is not None else ""
                if ld_sig:
                    seen.add(location)
                    emitted += 1
                    yield self._finding(param, location, "LDAP", "CWE-90", ld_sig,
                                        "user input is concatenated into an LDAP search filter")
                    continue

                if self._ssi(ctx, url, param, base_body):
                    seen.add(location)
                    emitted += 1
                    yield Finding(
                        check=self.name,
                        title=f"Server-Side Includes injection via parameter '{param}'",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        category="A03:2021 Injection",
                        cwe="CWE-97",
                        description=f"A reflected value in '{param}' had an SSI directive consumed by the "
                        "server while a plain HTML comment survived, indicating Server-Side Includes are "
                        "processed on user input. SSI can be escalated to command execution.",
                        remediation="Disable SSI processing for user-influenced output, or HTML-encode input "
                        "so directives cannot be interpreted.",
                        location=location,
                        evidence="SSI #echo directive stripped while a control comment was reflected",
                        references=["https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection"],
                    )

    def _ssi(self, ctx, url, param, base_body):
        token = ctx.http.marker()
        control = ctx.http.get(_set_param(url, param, f"<!--{token}-->"))
        if control is None or token not in (control.text or ""):
            return False
        payload = f'<!--#echo var="DATE_GMT"-->{token}'
        probe = ctx.http.get(_set_param(url, param, payload))
        if probe is None:
            return False
        body = probe.text or ""
        return token in body and "#echo" not in body

    def _finding(self, param, location, engine, cwe, sig, mechanism):
        return Finding(
            check=self.name,
            title=f"{engine} injection via parameter '{param}'",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category="A03:2021 Injection",
            cwe=cwe,
            description=f"Injecting {engine} metacharacters into '{param}' produced a {engine} engine error "
            f"absent from the baseline, indicating {mechanism}.",
            remediation=f"Use parameterized {engine} queries or strict input validation and escaping.",
            location=location,
            evidence=f"{engine} error signature: {sig}",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
        )
