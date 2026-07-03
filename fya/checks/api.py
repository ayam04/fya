from __future__ import annotations

import json
import re

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_SPEC_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v2/api-docs",
    "/swagger-ui.html",
]

_GRAPHQL_PATHS = ["/graphql", "/api/graphql"]

_ADMIN_PATHS = [
    "/actuator",
    "/actuator/health",
    "/debug",
    "/console",
    "/metrics",
]

_INTROSPECTION_QUERY = {
    "query": "query{__schema{queryType{name}}}"
}

_SPECIFIC_SIGNATURES = [
    "Traceback (most recent call last)",
    "Werkzeug Debugger",
    "NullPointerException",
]

_FRAMED_SIGNATURES = [
    "at java.",
    "syntax error at line",
]

_STACK_FRAME_RE = re.compile(r"(?:\bat\s+\S+\([^)]*\)|\bat\s+[\w.$]+\.[\w$]+\()")
_FILE_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|/)[\w.\\/-]+\.\w+")
_LINE_FRAME_RE = re.compile(r"line\s+\d+", re.IGNORECASE)
_AT_FRAME_RE = re.compile(r"\bat\s+\S")


def _has_stack_framing(body: str) -> bool:
    if _STACK_FRAME_RE.search(body):
        return True
    if _FILE_PATH_RE.search(body):
        return True
    if len(_AT_FRAME_RE.findall(body)) >= 2:
        return True
    if _LINE_FRAME_RE.search(body) and _FILE_PATH_RE.search(body):
        return True
    return False


def _match_signature(body: str) -> str:
    for sig in _SPECIFIC_SIGNATURES:
        if sig in body:
            return sig
    for sig in _FRAMED_SIGNATURES:
        if sig in body and _has_stack_framing(body):
            return sig
    return ""


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + path


def _looks_like_spec(text: str) -> bool:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    if "openapi" in data or "swagger" in data:
        return True
    if "paths" in data and isinstance(data.get("paths"), dict):
        return True
    return False


@register
class ApiDocsExposure(Check):
    name = "api.docs_exposure"
    title = "API documentation exposure"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        for path in _SPEC_PATHS:
            url = _join(base, path)
            response = ctx.http.get(url)
            if response is None or response.status_code != 200:
                continue
            body = response.text or ""
            content_type = response.headers.get("content-type", "").lower()
            is_json_spec = _looks_like_spec(body)
            is_ui = path.endswith(".html") and "swagger" in body.lower()
            if not is_json_spec and not is_ui:
                continue
            yield Finding(
                check=self.name,
                title=f"Exposed API specification at {path}",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH if is_json_spec else Confidence.MEDIUM,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-200",
                description=(
                    "An API specification or documentation UI is reachable without authentication. "
                    "This exposes the full endpoint surface, parameters, and data models to anyone, "
                    "reducing the effort required to enumerate and attack the API."
                ),
                remediation=(
                    "Restrict access to API documentation and specification endpoints in production, "
                    "or require authentication for them."
                ),
                location=url,
                evidence=f"HTTP 200, content-type: {content_type}",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
            )


@register
class GraphqlIntrospection(Check):
    name = "api.graphql_introspection"
    title = "GraphQL introspection enabled"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        for path in _GRAPHQL_PATHS:
            url = _join(base, path)
            response = ctx.http.post(url, json=_INTROSPECTION_QUERY)
            if response is None or response.status_code != 200:
                continue
            body = response.text or ""
            if "__schema" not in body:
                continue
            try:
                data = json.loads(body)
            except (ValueError, TypeError):
                continue
            schema = None
            if isinstance(data, dict):
                inner = data.get("data")
                schema = inner.get("__schema") if isinstance(inner, dict) else None
            if not isinstance(schema, dict):
                continue
            yield Finding(
                check=self.name,
                title=f"GraphQL introspection enabled at {path}",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-200",
                description=(
                    "The GraphQL endpoint answers introspection queries, returning its full schema. "
                    "This lets an attacker map every type, query, and mutation, which speeds up "
                    "discovery of sensitive operations and fields."
                ),
                remediation=(
                    "Disable introspection in production, or gate it behind authentication and "
                    "authorization checks."
                ),
                location=url,
                evidence="introspection response contained __schema",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
            )


@register
class VerboseErrorDisclosure(Check):
    name = "api.verbose_errors"
    title = "Verbose error disclosure"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        seen = set()
        probes = [
            ("post_bad_json", lambda u: ctx.http.post(u, data="{not valid json",
                                                       headers={"Content-Type": "application/json"})),
            ("get_broken_param", lambda u: ctx.http.get(u, params={"id": "'\"[]{}"})),
        ]
        targets = [base, _join(base, "/api")]
        for url in targets:
            baseline = ctx.http.get(url)
            baseline_body = (baseline.text or "") if baseline is not None else ""
            for label, sender in probes:
                response = sender(url)
                if response is None:
                    continue
                body = response.text or ""
                matched = _match_signature(body)
                if not matched:
                    continue
                if matched in baseline_body:
                    continue
                dedupe_key = matched
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                yield Finding(
                    check=self.name,
                    title="Verbose error or stack trace disclosed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="A05:2021 Security Misconfiguration",
                    cwe="CWE-209",
                    description=(
                        "A malformed request caused the application to return a stack trace or "
                        "framework debug page. Detailed errors leak internal paths, dependency "
                        "versions, and query structure that assist further attacks."
                    ),
                    remediation=(
                        "Disable debug mode in production and return generic error responses. "
                        "Log detailed errors server side only."
                    ),
                    location=url,
                    evidence=f"probe {label} matched signature: {matched}",
                    references=["https://owasp.org/www-community/Improper_Error_Handling"],
                )


@register
class ExposedAdminEndpoints(Check):
    name = "api.admin_endpoints"
    title = "Exposed admin or debug endpoints"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        for path in _ADMIN_PATHS:
            url = _join(base, path)
            response = ctx.http.get(url)
            if response is None or response.status_code != 200:
                continue
            content_type = response.headers.get("content-type", "").lower()
            body = response.text or ""
            looks_management = (
                "json" in content_type
                or path in ("/actuator", "/actuator/health", "/metrics")
                or "status" in body.lower()
            )
            if not looks_management:
                continue
            yield Finding(
                check=self.name,
                title=f"Unauthenticated management endpoint at {path}",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                category="A05:2021 Security Misconfiguration",
                cwe="CWE-497",
                description=(
                    "A management, debug, or metrics endpoint responded without authentication. "
                    "These endpoints often expose configuration, health, environment, and internal "
                    "state that should not be publicly reachable."
                ),
                remediation=(
                    "Require authentication for management and debug endpoints, or bind them to a "
                    "private interface and block external access."
                ),
                location=url,
                evidence=f"HTTP 200, content-type: {content_type}",
                references=["https://owasp.org/www-community/Security_Misconfiguration"],
            )


def _resolved_typename(response) -> bool:
    if response is None or response.status_code != 200:
        return False
    if "json" not in response.headers.get("content-type", "").lower():
        return False
    try:
        data = json.loads(response.text or "")
    except (ValueError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    inner = data.get("data")
    return isinstance(inner, dict) and isinstance(inner.get("__typename"), str) and bool(inner.get("__typename"))


@register
class GraphqlHardening(Check):
    name = "api.graphql_hardening"
    title = "GraphQL hardening gaps"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.SAFE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        for path in _GRAPHQL_PATHS:
            url = _join(base, path)
            if not _resolved_typename(ctx.http.post(url, json={"query": "{__typename}"})):
                continue

            suggestion = ctx.http.post(url, json={"query": "query { __typenam }"})
            if suggestion is not None:
                try:
                    sdata = json.loads(suggestion.text or "")
                except (ValueError, TypeError):
                    sdata = None
                if isinstance(sdata, dict):
                    errors = sdata.get("errors") or []
                    messages = " ".join(
                        str(e.get("message", "")) for e in errors if isinstance(e, dict)
                    ).lower()
                    if "did you mean" in messages:
                        yield Finding(
                            check=self.name,
                            title="GraphQL field suggestions leak schema",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            category="A05:2021 Security Misconfiguration",
                            cwe="CWE-200",
                            description="The GraphQL endpoint returns 'Did you mean' field suggestions for "
                            "mistyped fields. This lets an attacker reconstruct the schema field by field "
                            "even when introspection is disabled.",
                            remediation="Disable field suggestions in production (e.g. GraphQL-JS "
                            "didYouMeanSuggestions off) alongside introspection.",
                            location=url,
                            evidence="response 'errors' contained a 'Did you mean' suggestion",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        )

            batch = ctx.http.post(url, json=[{"query": "{__typename}"}, {"query": "{__typename}"}])
            if batch is not None:
                try:
                    bdata = json.loads(batch.text or "")
                except (ValueError, TypeError):
                    bdata = None
                if (
                    isinstance(bdata, list)
                    and len(bdata) == 2
                    and all(
                        isinstance(x, dict)
                        and isinstance(x.get("data"), dict)
                        and isinstance(x["data"].get("__typename"), str)
                        for x in bdata
                    )
                ):
                    yield Finding(
                        check=self.name,
                        title="GraphQL query batching enabled",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="A05:2021 Security Misconfiguration",
                        cwe="CWE-770",
                        description="The endpoint executed an array of two operations in one request. Query "
                        "batching lets an attacker bypass per-request rate limiting and amplify brute-force "
                        "or resource-exhaustion attacks.",
                        remediation="Disable array-based batching or enforce per-operation cost and rate "
                        "limits across a batch.",
                        location=url,
                        evidence="a 2-operation batch returned two resolved responses",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                    )

            if _resolved_typename(ctx.http.get(url + "?query=%7B__typename%7D")):
                yield Finding(
                    check=self.name,
                    title="GraphQL executes queries over GET",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    category="A01:2021 Broken Access Control",
                    cwe="CWE-352",
                    description="The endpoint executed a GraphQL query sent as a GET request. GET-based "
                    "execution is cacheable, leaks queries in logs, and is a precondition for CSRF against "
                    "state-changing mutations.",
                    remediation="Only accept GraphQL over POST with a JSON content type, and require a CSRF "
                    "token or custom header.",
                    location=url,
                    evidence="GET ?query={__typename} resolved to JSON data",
                    references=["https://portswigger.net/web-security/graphql"],
                )
            return
