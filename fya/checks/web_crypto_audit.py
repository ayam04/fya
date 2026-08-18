from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import socket
import ssl
from html import escape
from urllib.parse import urljoin, urlsplit

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register
from .web_active import _AGGRESSIVE_CRAWL_CAP, _SAFE_CRAWL_CAP, _discover
from .web_jwt import _JWTBase, _redact

_CRYPTO_CATEGORY = "A02:2021 Cryptographic Failures"
_MISCONFIG_CATEGORY = "A05:2021 Security Misconfiguration"
_INTEGRITY_CATEGORY = "A08:2021 Software and Data Integrity Failures"

_TLS_TIMEOUT = 6.0

# ---------------------------------------------------------------------------
# web.jwt_weak_secret
# ---------------------------------------------------------------------------

_ALG_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}

# A tiny fixed wordlist of common/default HMAC signing secrets. This is a
# local dictionary check against already-harvested tokens - not a network
# brute force. Keep it short and high-signal.
_WORDLIST = (
    "secret",
    "password",
    "passw0rd",
    "changeme",
    "change-me",
    "admin",
    "administrator",
    "root",
    "test",
    "testing",
    "demo",
    "example",
    "default",
    "jwt",
    "jwtsecret",
    "jwt_secret",
    "jwt-secret",
    "jsonwebtoken",
    "your-256-bit-secret",
    "your_jwt_secret",
    "supersecret",
    "super-secret",
    "topsecret",
    "s3cr3t",
    "s3cret",
    "secretkey",
    "secret_key",
    "secretkey123",
    "mysecret",
    "mysecretkey",
    "signingkey",
    "signing_key",
    "hmac",
    "hmackey",
    "key",
    "apikey",
    "token",
    "auth",
    "authsecret",
    "123456",
    "12345678",
    "1234567890",
    "password123",
    "qwerty",
    "letmein",
    "node-jwt-secret",
    "django-insecure",
    "flask-secret",
    "express-jwt-secret",
    "shhhh",
    "seneca",
)


@register
class JWTWeakSecret(_JWTBase):
    name = "web.jwt_weak_secret"
    title = "JWT signed with a crackable HMAC secret (offline)"

    def run(self, ctx: ScanContext):
        emitted = 0
        for base, origin, token, header, _payload in self._tokens(ctx):
            if emitted >= 5:
                return
            alg = str(header.get("alg", "")).strip().upper()
            mod = _ALG_HASH.get(alg)
            if mod is None:
                continue
            parts = token.split(".")
            if len(parts) != 3:
                continue
            signing_input = token.rsplit(".", 1)[0]
            expected = parts[2]
            cracked = self._crack(signing_input, expected, mod)
            if cracked is None:
                continue
            emitted += 1
            redacted_secret = f"{cracked[:2]}\u2026 (length {len(cracked)})"
            yield Finding(
                check=self.name,
                title="JWT signed with a weak/default HMAC secret",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=_CRYPTO_CATEGORY,
                cwe="CWE-347",
                description="A JSON Web Token exposed by the application is HMAC-signed with a secret "
                "recovered from a small list of common/default values. Because the signing key is known, "
                "anyone can forge tokens with arbitrary claims (any user, any role) that the server will "
                "accept as authentic.",
                remediation="Rotate the signing secret immediately to a long, random, high-entropy value "
                "stored outside the codebase, and invalidate all outstanding tokens. Prefer asymmetric "
                "signing (RS256/ES256) so the verification key can be public.",
                location=base,
                evidence=f"{origin}: {_redact(token)} alg={alg} secret={redacted_secret}",
                references=[
                    "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
                    "https://cwe.mitre.org/data/definitions/347.html",
                ],
            )

    @staticmethod
    def _crack(signing_input, expected, mod):
        for secret in _WORDLIST:
            mac = hmac.new(secret.encode(), signing_input.encode(), mod).digest()
            calc = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
            if hmac.compare_digest(calc, expected):
                return secret
        return None


# ---------------------------------------------------------------------------
# web.jwt_header_injection
# ---------------------------------------------------------------------------

_KID_METACHARS = ("../", "..\\", "/etc/", "file:", "'", '"', ";", "|", "$(", "`")

# Public-suffix-ish table used only to reduce "off-host" false positives: pointing jku/x5u at
# your own identity provider (login.example.com from www.example.com) is the normal, correct
# architecture, so only a host outside the target's registrable domain is worth reporting.
_MULTI_LABEL_TLDS = frozenset(
    {
        "ac.uk", "co.uk", "gov.uk", "org.uk", "net.uk", "sch.uk",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "net.nz", "org.nz",
        "com.br", "com.cn", "com.mx", "com.ar", "com.hk", "com.sg", "com.tr",
        "com.tw", "com.my", "com.ph", "com.pl", "com.pk", "com.ua", "com.vn",
        "co.in", "co.za", "co.kr", "co.il", "co.id", "co.th",
    }
)

_IPV4_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _registrable_domain(host: str) -> str:
    """Best-effort registrable domain (last two labels, three for known multi-label TLDs)."""
    h = (host or "").strip().strip(".").lower()
    if not h or _IPV4_LIKE.match(h) or ":" in h:
        return h
    labels = h.split(".")
    if len(labels) < 3:
        return h
    if ".".join(labels[-2:]) in _MULTI_LABEL_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


@register
class JWTHeaderInjection(_JWTBase):
    name = "web.jwt_header_injection"
    title = "JWT jku/x5u/kid header injection surface"

    def run(self, ctx: ScanContext):
        target_host = ctx.target.host
        emitted = 0
        for base, origin, token, header, _payload in self._tokens(ctx):
            if emitted >= 5:
                return
            for field in ("jku", "x5u"):
                value = header.get(field)
                if not isinstance(value, str) or not value:
                    continue
                verdict = self._url_verdict(value, target_host)
                if verdict is None:
                    continue
                text, severity, confidence = verdict
                emitted += 1
                yield self._url_finding(
                    base, origin, token, field, value, text, severity, confidence
                )
                break
            else:
                kid = header.get("kid")
                if isinstance(kid, str) and any(meta in kid for meta in _KID_METACHARS):
                    emitted += 1
                    yield self._kid_finding(base, origin, token, kid)

    @staticmethod
    def _url_verdict(value, target_host):
        """Return (verdict, severity, confidence) or None.

        A key URL on a different hostname inside the same registrable domain (the app's own
        identity provider, e.g. login.example.com for www.example.com) is normal architecture
        and is never reported. Only a plaintext URL, or one on an entirely different
        registrable domain, is worth surfacing - and the latter only as a LOW hint because
        nothing here confirms the server dereferences the URL.
        """
        try:
            parsed = urlsplit(value)
        except ValueError:
            return None
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return None
        if scheme == "http":
            return ("fetched over plaintext http", Severity.MEDIUM, Confidence.MEDIUM)
        host = (parsed.hostname or "").lower()
        if not host or not target_host:
            return None
        own = _registrable_domain(target_host)
        if own and _registrable_domain(host) != own:
            return (
                f"points to {host}, outside the target's own domain ({own})",
                Severity.LOW,
                Confidence.LOW,
            )
        return None

    def _url_finding(self, base, origin, token, field, value, verdict, severity, confidence):
        return Finding(
            check=self.name,
            title=f"JWT '{field}' header references an attacker-influenceable key URL",
            severity=severity,
            confidence=confidence,
            category=_CRYPTO_CATEGORY,
            cwe="CWE-347",
            description=f"An exposed JSON Web Token carries a '{field}' header whose URL {verdict}. If the "
            "server fetches the verification key from this URL, an attacker who controls (or can MITM) that "
            "endpoint can supply their own key and forge valid tokens. This is a surface indicator, not "
            "proof the server trusts the URL.",
            remediation="Never fetch JWT verification keys from a URL embedded in the token. Pin verification "
            "to a fixed, locally configured key set and ignore jku/x5u in incoming tokens.",
            location=f"{base} [{field}]",
            evidence=f"{origin}: {_redact(token)} header.{field}={escape(value)[:200]}",
            references=[
                "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
                "https://cwe.mitre.org/data/definitions/347.html",
            ],
        )

    def _kid_finding(self, base, origin, token, kid):
        return Finding(
            check=self.name,
            title="JWT 'kid' header contains path/SQL metacharacters",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category=_CRYPTO_CATEGORY,
            cwe="CWE-91",
            description="An exposed JSON Web Token has a 'kid' (key id) header containing path-traversal or "
            "injection metacharacters. If the server interpolates kid into a file path or SQL lookup to "
            "select the verification key, this is an injection surface (directory traversal, SQL injection, "
            "or command metacharacters). This is a surface indicator, not proof of exploitation.",
            remediation="Treat kid as an opaque identifier looked up against an allow-list of known key ids. "
            "Never interpolate it into a filesystem path, SQL query, or shell command.",
            location=f"{base} [kid]",
            evidence=f"{origin}: {_redact(token)} header.kid={escape(kid)[:200]}",
            references=[
                "https://cwe.mitre.org/data/definitions/91.html",
                "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
            ],
        )


# ---------------------------------------------------------------------------
# tls.certificate_strength
# ---------------------------------------------------------------------------


def _https_ports(ctx):
    ports = [443]
    if ctx.target.scheme == "https" and ctx.target.port and ctx.target.port not in ports:
        ports.append(ctx.target.port)
    return ports


def _peer_der(host, port):
    context = ssl._create_unverified_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=_TLS_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True)
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError, ValueError):
        return None


@register
class TLSCertificateStrength(Check):
    name = "tls.certificate_strength"
    title = "Weak certificate key size or signature algorithm"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        try:
            from cryptography.x509 import load_der_x509_certificate
        except ImportError:
            return
        host = ctx.target.host
        if not host:
            return
        seen = set()
        for port in _https_ports(ctx):
            if port in seen:
                continue
            seen.add(port)
            der = _peer_der(host, port)
            if not der:
                continue
            try:
                cert = load_der_x509_certificate(der)
            except Exception:
                continue
            yield from self._evaluate(cert, f"{host}:{port}")

    def _evaluate(self, cert, location):
        subject_cn = self._subject_cn(cert)
        key_kind, key_size = self._key_info(cert)
        sig_name = ""
        try:
            alg = cert.signature_hash_algorithm
            sig_name = (alg.name if alg else "").lower()
        except Exception:
            sig_name = ""

        base_evidence = f"subject CN={subject_cn or '(none)'}; key={key_kind or '?'}/{key_size or '?'}; sig={sig_name or '?'}"

        weak_key = (
            key_size is not None
            and (
                (key_kind in ("RSA", "DSA") and key_size < 2048)
                or (key_kind == "EC" and key_size < 224)
            )
        )
        if weak_key:
            yield Finding(
                check=self.name,
                title=f"Undersized {key_kind} public key ({key_size}-bit) in TLS certificate",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=_CRYPTO_CATEGORY,
                cwe="CWE-326",
                description=f"The server's TLS certificate uses a {key_kind} public key of only {key_size} bits, "
                "below the accepted minimum (2048-bit RSA/DSA, 224-bit EC). Undersized keys are increasingly "
                "feasible to break, undermining the confidentiality and authenticity of the connection.",
                remediation="Re-issue the certificate with at least a 2048-bit RSA key (or a 256-bit+ EC key) "
                "and redeploy the full chain.",
                location=location,
                evidence=base_evidence,
                references=[
                    "https://cwe.mitre.org/data/definitions/326.html",
                    "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
                ],
            )

        if sig_name in ("md5", "sha1"):
            yield Finding(
                check=self.name,
                title=f"TLS certificate signed with broken hash ({sig_name.upper()})",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=_CRYPTO_CATEGORY,
                cwe="CWE-327",
                description=f"The server's TLS certificate is signed using {sig_name.upper()}, a hash algorithm "
                "with practical collision attacks. An attacker able to produce a colliding certificate can "
                "impersonate the server, so this signature provides no meaningful integrity guarantee.",
                remediation="Re-issue the certificate with a SHA-256 (or stronger) signature and retire the "
                "weakly signed certificate.",
                location=location,
                evidence=base_evidence,
                references=[
                    "https://cwe.mitre.org/data/definitions/327.html",
                    "https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures/",
                ],
            )

    @staticmethod
    def _subject_cn(cert):
        try:
            from cryptography.x509.oid import NameOID

            attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            return attrs[0].value if attrs else ""
        except Exception:
            return ""

    @staticmethod
    def _key_info(cert):
        try:
            from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

            pub = cert.public_key()
        except Exception:
            return None, None
        try:
            if isinstance(pub, rsa.RSAPublicKey):
                return "RSA", pub.key_size
            if isinstance(pub, dsa.DSAPublicKey):
                return "DSA", pub.key_size
            if isinstance(pub, ec.EllipticCurvePublicKey):
                return "EC", pub.key_size
        except Exception:
            return None, None
        return None, None


# ---------------------------------------------------------------------------
# web.mixed_content
# ---------------------------------------------------------------------------

_MC_SCRIPT = re.compile(r"<script\b[^>]*\bsrc\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_MC_IFRAME = re.compile(r"<iframe\b[^>]*\bsrc\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_MC_IMG = re.compile(r"<img\b[^>]*\bsrc\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_MC_SOURCE = re.compile(r"<source\b[^>]*\bsrc\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_MC_LINK_TAG = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_MC_HREF = re.compile(r"\bhref\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_MC_REL = re.compile(r"\brel\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_MC_CSS_URL = re.compile(r"url\(\s*(\"[^\"]*\"|'[^']*'|[^)]+)\s*\)", re.IGNORECASE)
_MC_AS = re.compile(r"\bas\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)

# rel values that always fetch active content (executed/applied by the page).
_ACTIVE_LINK_RELS = {"stylesheet"}
# rel=preload says nothing about activeness on its own - the `as` attribute decides.
_ACTIVE_PRELOAD_AS = {"script", "style", "worker", "serviceworker", "sharedworker", "document"}
# rel values that fetch passive content (cannot execute in the page).
_PASSIVE_LINK_RELS = {
    "icon",
    "shortcut",
    "apple-touch-icon",
    "apple-touch-icon-precomposed",
    "mask-icon",
    "manifest",
    "prefetch",
    "prerender",
}


def _unquote_attr(value: str) -> str:
    return value.strip().strip("\"'").strip()


@register
class MixedContent(Check):
    name = "web.mixed_content"
    title = "Active mixed content on an HTTPS page"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        if ctx.target.scheme != "https":
            return
        base = ctx.target.base_url()
        if not base:
            return
        resp = ctx.http.get(base)
        if resp is None:
            return
        final = (getattr(resp, "url", "") or base)
        if not final.lower().startswith("https://"):
            return
        body = resp.text or ""

        emitted = 0
        seen = set()
        for ref, active, kind in self._references(body):
            absolute = urljoin(final, ref)
            if not absolute.lower().startswith("http://"):
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            emitted += 1
            if emitted > 10:
                return
            severity = Severity.HIGH if active else Severity.LOW
            yield self._finding(final, absolute, severity, kind)

    def _references(self, body):
        refs = []
        for regex, kind in ((_MC_SCRIPT, "active (script)"), (_MC_IFRAME, "active (iframe)")):
            for raw in regex.findall(body):
                refs.append((_unquote_attr(raw), True, kind))
        for tag in _MC_LINK_TAG.findall(body):
            href_m = _MC_HREF.search(tag)
            if not href_m:
                continue
            rel_m = _MC_REL.search(tag)
            rel = _unquote_attr(rel_m.group(1)).lower() if rel_m else ""
            verdict = self._link_verdict(tag, set(rel.split()))
            if verdict is None:
                continue
            active, kind = verdict
            refs.append((_unquote_attr(href_m.group(1)), active, kind))
        for regex in (_MC_IMG, _MC_SOURCE):
            for raw in regex.findall(body):
                refs.append((_unquote_attr(raw), False, "passive (image/media)"))
        for raw in _MC_CSS_URL.findall(body):
            ref = _unquote_attr(raw)
            if ref.lower().startswith("http://"):
                refs.append((ref, False, "passive (css url())"))
        return refs

    @staticmethod
    def _link_verdict(tag, rel_tokens):
        """Classify a <link> as (is_active, kind) - or None when it references no subresource."""
        if rel_tokens & _ACTIVE_LINK_RELS:
            return True, "active (stylesheet)"
        if "modulepreload" in rel_tokens:
            return True, "active (modulepreload script)"
        if "preload" in rel_tokens:
            as_m = _MC_AS.search(tag)
            as_value = _unquote_attr(as_m.group(1)).lower() if as_m else ""
            if as_value in _ACTIVE_PRELOAD_AS:
                return True, f"active (preload as={as_value})"
            return False, f"passive (preload as={as_value or 'unspecified'})"
        if rel_tokens & _PASSIVE_LINK_RELS:
            return False, "passive (icon/manifest/prefetch)"
        return None

    def _finding(self, page, absolute, severity, kind):
        return Finding(
            check=self.name,
            title="HTTPS page loads a subresource over plaintext HTTP",
            severity=severity,
            confidence=Confidence.HIGH,
            category=_MISCONFIG_CATEGORY,
            cwe="CWE-319",
            description="This page is served over HTTPS but pulls a subresource over plaintext http://. A "
            "network attacker can read or tamper with that resource in transit; for active content "
            "(scripts, stylesheets, iframes) that means arbitrary code execution in the page, defeating the "
            "page's TLS entirely. Browsers block or downgrade such requests, so the resource may also fail "
            "to load.",
            remediation="Serve every subresource over HTTPS (use protocol-relative or https:// URLs) and add "
            "a Content-Security-Policy with upgrade-insecure-requests to catch regressions.",
            location=absolute,
            evidence=f"page {page} -> {kind} subresource {escape(absolute)[:200]}",
            references=[
                "https://cwe.mitre.org/data/definitions/319.html",
                "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            ],
        )


# ---------------------------------------------------------------------------
# web.serialized_objects
# ---------------------------------------------------------------------------

_JWT_SHAPED = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_PHP_SERIALIZED = re.compile(r'^(?:a:\d+:\{|O:\d+:"[^"]+":\d+:\{)')
_HIDDEN_INPUT = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_INPUT_TYPE = re.compile(r"\btype\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_INPUT_NAME = re.compile(r"\bname\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_INPUT_VALUE = re.compile(r"\bvalue\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_SO_LINK = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'>]+)["']""", re.IGNORECASE)
_JAVA_MAGIC = b"\xac\xed\x00\x05"

# Only the __VIEWSTATE field itself carries ObjectStateFormatter state. Siblings such as
# __VIEWSTATEGENERATOR (an 8-hex-digit page identity hash) and __EVENTVALIDATION are not
# serialized object graphs and must never be reported as one.
_VIEWSTATE_SOURCE = "hidden:__VIEWSTATE"
# ObjectStateFormatter marks an *unencrypted* ViewState with this two-byte prefix; an
# encrypted ViewState (ViewStateEncryptionMode=Always) decodes to opaque ciphertext instead.
_VIEWSTATE_PLAINTEXT_MARKER = b"\xff\x01"
_VIEWSTATE_FMT = ".NET ViewState (unencrypted ObjectStateFormatter)"


def _looks_base64(value: str) -> bool:
    if len(value) < 24:
        return False
    try:
        base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
        return True
    except (binascii.Error, ValueError):
        return False


def _classify_blob(value):
    v = (value or "").strip()
    if not v or len(v) < 5:
        return None
    if _JWT_SHAPED.match(v):
        return None
    if "_$$ND_FUNC$$_" in v:
        return "node-serialize function payload"
    if v.startswith("rO0AB") and _looks_base64(v):
        return "Java serialized object (base64)"
    if v[:4].encode("latin-1", "ignore").startswith(_JAVA_MAGIC):
        return "Java serialized object (raw)"
    if v.startswith("BAh") and _looks_base64(v):
        return "Ruby Marshal object (base64)"
    if len(v) >= 8 and _PHP_SERIALIZED.match(v):
        return "PHP serialized object"
    return None


def _viewstate_verdict(source, value):
    """Classify a __VIEWSTATE field, or return None when there is nothing to report.

    Fires only on the exact __VIEWSTATE field with a non-empty value that base64-decodes to an
    unencrypted ObjectStateFormatter stream. ViewStateMac has been mandatory since .NET 4.5, so
    a well-formed ViewState is normally integrity-protected; this is reported as a low-severity
    information/tamper hint, never as a confirmed deserialization sink.
    """
    if source != _VIEWSTATE_SOURCE:
        return None
    v = (value or "").strip()
    if len(v) < 8 or not _looks_base64(v):
        return None
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw.startswith(_VIEWSTATE_PLAINTEXT_MARKER):
        return None
    return _VIEWSTATE_FMT


@register
class SerializedObjects(Check):
    name = "web.serialized_objects"
    title = "Serialized-object blobs in cookies, tokens and hidden fields"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        base = ctx.target.base_url()
        if not base:
            return
        pages = self._pages(ctx, base)
        emitted = 0
        seen_keys = set()
        for page in pages:
            resp = ctx.http.get(page)
            if resp is None:
                continue
            for source, value in self._candidates(resp):
                fmt = self._detect(source, value)
                if fmt is None:
                    continue
                key = (source, fmt)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                emitted += 1
                if emitted > 6:
                    return
                yield self._finding(page, source, fmt, value)

    def _detect(self, source, value):
        verdict = _viewstate_verdict(source, value)
        if verdict is not None:
            return verdict
        return _classify_blob(value)

    def _pages(self, ctx, base):
        pages = [base]
        cap = _AGGRESSIVE_CRAWL_CAP if ctx.profile is Profile.AGGRESSIVE else _SAFE_CRAWL_CAP
        try:
            discovered = _discover(ctx, cap, set())
        except Exception:
            discovered = []
        for url, _params in discovered:
            if url not in pages:
                pages.append(url)
            if len(pages) >= 5:
                break
        return pages

    def _candidates(self, resp):
        out = []
        try:
            for cookie in resp.cookies:
                if cookie.value:
                    out.append((f"cookie:{cookie.name}", cookie.value))
        except Exception:
            pass
        body = resp.text or ""
        viewstate_seen = False
        for tag in _HIDDEN_INPUT.findall(body):
            type_m = _INPUT_TYPE.search(tag)
            input_type = _unquote_attr(type_m.group(1)).lower() if type_m else ""
            name_m = _INPUT_NAME.search(tag)
            value_m = _INPUT_VALUE.search(tag)
            name = _unquote_attr(name_m.group(1)) if name_m else ""
            value = _unquote_attr(value_m.group(1)) if value_m else ""
            if name == "__VIEWSTATE" and value and not viewstate_seen:
                viewstate_seen = True
                out.append((_VIEWSTATE_SOURCE, value))
                continue
            if input_type == "hidden" and value:
                out.append((f"hidden:{name or '?'}", value))
        for href in _SO_LINK.findall(body):
            try:
                query = urlsplit(href).query
            except ValueError:
                continue
            for pair in query.split("&"):
                if "=" not in pair:
                    continue
                key, _, val = pair.partition("=")
                if val:
                    out.append((f"query:{key}", val))
        out.extend(self._json_strings(resp, body))
        return out

    def _json_strings(self, resp, body):
        content_type = (resp.headers.get("content-type", "") or "").lower()
        stripped = body.lstrip()
        if "json" not in content_type and not stripped.startswith(("{", "[")):
            return []
        import json

        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return []
        found = []
        stack = [data]
        steps = 0
        while stack and steps < 500:
            steps += 1
            item = stack.pop()
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, str):
                        found.append((f"json:{k}", v))
                    elif isinstance(v, (dict, list)):
                        stack.append(v)
            elif isinstance(item, list):
                for v in item:
                    if isinstance(v, str):
                        found.append(("json:[]", v))
                    elif isinstance(v, (dict, list)):
                        stack.append(v)
        return found

    def _finding(self, page, source, fmt, value):
        if fmt == _VIEWSTATE_FMT:
            return self._viewstate_finding(page, source, value)
        return Finding(
            check=self.name,
            title=f"Serialized-object blob exposed via {source}",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=_INTEGRITY_CATEGORY,
            cwe="CWE-502",
            description=f"A value round-tripped through the client ({source}) is a native {fmt}. Serialized "
            "objects sent to and accepted from the client are a classic insecure-deserialization surface: if "
            "the server deserializes attacker-modified data, it can lead to remote code execution or object "
            "injection.",
            remediation="Do not deserialize untrusted client data with native serializers. Use a plain data "
            "format (JSON) with strict schema validation, and integrity-protect any client-held state with a "
            "server-side MAC or move it server-side entirely.",
            location=f"{page} [{source}]",
            evidence=f"{source}: {fmt}; prefix={escape(value[:24])}",
            references=[
                "https://cwe.mitre.org/data/definitions/502.html",
                "https://owasp.org/www-project-top-ten/2021/A08_2021-Software_and_Data_Integrity_Failures/",
            ],
        )

    def _viewstate_finding(self, page, source, value):
        return Finding(
            check=self.name,
            title="ASP.NET ViewState is transmitted unencrypted",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            category=_INTEGRITY_CATEGORY,
            cwe="CWE-502",
            description="The __VIEWSTATE field on this page base64-decodes to an unencrypted "
            "ObjectStateFormatter stream, so any client can read the server-side control state it "
            "carries (and any application data stashed in it). ViewStateMac has been mandatory "
            "since .NET 4.5, so this is normally integrity-protected - but the MAC was not verified "
            "here, and on a legacy runtime with the MAC disabled a tampered ViewState is a direct "
            "insecure-deserialization sink.",
            remediation="Set ViewStateEncryptionMode=\"Always\" so the state is not readable by the "
            "client, keep ViewStateMac enabled with a per-application machineKey, and never place "
            "secrets or trust decisions in ViewState.",
            location=f"{page} [{source}]",
            evidence=f"{source}: unencrypted ObjectStateFormatter (\\xff\\x01); "
            f"prefix={escape(value[:24])}",
            references=[
                "https://cwe.mitre.org/data/definitions/502.html",
                "https://learn.microsoft.com/en-us/aspnet/whitepapers/aspnet4/breaking-changes",
            ],
        )
