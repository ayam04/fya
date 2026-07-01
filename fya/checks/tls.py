from __future__ import annotations

import socket
import ssl
import warnings
from datetime import datetime, timezone

from ..models import Confidence, Finding, Profile, ScanContext, Severity, TargetKind
from ..registry import Check, register

_TIMEOUT = 6.0
_EXPIRY_WINDOW_DAYS = 30
_CATEGORY = "A02:2021 Cryptographic Failures"
_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def _https_ports(ctx):
    ports = [443]
    if ctx.target.scheme == "https" and ctx.target.port and ctx.target.port not in ports:
        ports.append(ctx.target.port)
    return ports


def _parse_cert_time(value):
    if not value:
        return None
    try:
        return datetime.strptime(value, _CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _fetch_verified_cert(host, port):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return "ok", tls.getpeercert(), None
    except ssl.SSLCertVerificationError as exc:
        return "verify_error", None, str(exc)
    except ssl.SSLError as exc:
        return "ssl_error", None, str(exc)
    except (socket.timeout, ConnectionError, OSError):
        return "unreachable", None, None


def _fetch_permissive_cert(host, port):
    context = ssl._create_unverified_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                decoded = tls.getpeercert()
                return decoded, der
    except (ssl.SSLError, socket.timeout, ConnectionError, OSError):
        return None, None


def _decode_der(der):
    if not der:
        return {}
    try:
        from cryptography.x509 import load_der_x509_certificate
    except ImportError:
        return _decode_der_legacy(der)
    try:
        from cryptography.x509.oid import NameOID

        cert = load_der_x509_certificate(der)

        def _rdns(name):
            entries = []
            for attr in name.get_attributes_for_oid(NameOID.COMMON_NAME):
                entries.append((("commonName", attr.value),))
            return tuple(entries)

        try:
            not_after = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

        return {
            "subject": _rdns(cert.subject),
            "issuer": _rdns(cert.issuer),
            "notAfter": not_after.strftime(_CERT_DATE_FORMAT).replace("UTC", "GMT"),
            "notBefore": not_before.strftime(_CERT_DATE_FORMAT).replace("UTC", "GMT"),
        }
    except Exception:
        return {}


def _decode_der_legacy(der):
    if not der:
        return {}
    try:
        import os
        import tempfile

        pem = ssl.DER_cert_to_PEM_cert(der)
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(pem)
            return ssl._ssl._test_decode_cert(path)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    except (ssl.SSLError, OSError, ValueError, AttributeError):
        return {}


def _cert_subject_cn(cert):
    if not cert:
        return ""
    for entry in cert.get("subject", ()):
        for key, value in entry:
            if key == "commonName":
                return value
    return ""


def _cert_issuer_cn(cert):
    if not cert:
        return ""
    for entry in cert.get("issuer", ()):
        for key, value in entry:
            if key == "commonName":
                return value
    return ""


def _is_self_signed(cert):
    if not cert:
        return False
    subject = tuple(sorted(tuple(sorted(e)) for e in cert.get("subject", ())))
    issuer = tuple(sorted(tuple(sorted(e)) for e in cert.get("issuer", ())))
    return bool(subject) and subject == issuer


@register
class TLSCertificate(Check):
    name = "tls.certificate"
    title = "TLS certificate validity"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        host = ctx.target.host
        if not host:
            return
        seen = set()
        for port in _https_ports(ctx):
            if port in seen:
                continue
            seen.add(port)
            yield from self._check_port(ctx, host, port)

    def _check_port(self, ctx, host, port):
        location = f"{host}:{port}"
        status, cert, detail = _fetch_verified_cert(host, port)
        if status == "unreachable":
            return

        if status == "ok":
            yield from self._evaluate_cert(cert, location, verified=True)
            return

        decoded, der = _fetch_permissive_cert(host, port)
        if not decoded and der:
            decoded = _decode_der(der)

        lowered = (detail or "").lower()
        if "hostname" in lowered or "match" in lowered or "ip address mismatch" in lowered:
            yield Finding(
                check=self.name,
                title="TLS certificate hostname mismatch",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=_CATEGORY,
                cwe="CWE-295",
                description="The presented certificate does not match the requested hostname, so clients "
                "cannot cryptographically confirm they are talking to the intended server.",
                remediation="Install a certificate whose subject or subjectAltName covers the served hostname.",
                location=location,
                evidence=(detail or "")[:300],
                references=["https://cwe.mitre.org/data/definitions/295.html"],
            )
        elif _is_self_signed(decoded) or "self signed" in lowered or "self-signed" in lowered:
            yield Finding(
                check=self.name,
                title="Self-signed or untrusted TLS certificate",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=_CATEGORY,
                cwe="CWE-295",
                description="The certificate does not chain to a trusted certificate authority (it appears "
                "self-signed or issued by an untrusted issuer), so its authenticity cannot be validated.",
                remediation="Obtain a certificate from a publicly trusted certificate authority.",
                location=location,
                evidence=f"issuer CN: {_cert_issuer_cn(decoded)}; {(detail or '')[:200]}",
                references=["https://cwe.mitre.org/data/definitions/295.html"],
            )
        elif "expired" in lowered:
            yield Finding(
                check=self.name,
                title="Expired TLS certificate",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category=_CATEGORY,
                cwe="CWE-295",
                description="The certificate presented by the server has expired, so browsers will reject it "
                "and the connection cannot be trusted.",
                remediation="Renew and deploy a current certificate, and automate renewal to prevent recurrence.",
                location=location,
                evidence=(detail or "")[:300],
                references=["https://cwe.mitre.org/data/definitions/295.html"],
            )
        elif decoded:
            yield from self._evaluate_cert(decoded, location, verified=False)

    def _evaluate_cert(self, cert, location, verified):
        if not cert:
            return
        not_after = _parse_cert_time(cert.get("notAfter"))
        not_before = _parse_cert_time(cert.get("notBefore"))
        now = datetime.now(timezone.utc)
        subject_cn = _cert_subject_cn(cert)

        if not_after is not None:
            if not_after < now:
                yield Finding(
                    check=self.name,
                    title="Expired TLS certificate",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category=_CATEGORY,
                    cwe="CWE-295",
                    description="The server certificate expired on "
                    f"{not_after.isoformat()} and is no longer valid.",
                    remediation="Renew and deploy a current certificate, and automate renewal.",
                    location=location,
                    evidence=f"notAfter: {cert.get('notAfter')}; subject CN: {subject_cn}",
                    references=["https://cwe.mitre.org/data/definitions/295.html"],
                )
            else:
                days_left = (not_after - now).days
                if days_left <= _EXPIRY_WINDOW_DAYS:
                    yield Finding(
                        check=self.name,
                        title="TLS certificate expiring soon",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=_CATEGORY,
                        cwe="CWE-295",
                        description=f"The server certificate expires in {days_left} day(s) "
                        f"(on {not_after.isoformat()}). Expiry will break TLS for all clients.",
                        remediation="Renew the certificate ahead of expiry and automate renewal.",
                        location=location,
                        evidence=f"notAfter: {cert.get('notAfter')}; subject CN: {subject_cn}",
                        references=["https://cwe.mitre.org/data/definitions/295.html"],
                    )

        if not_before is not None and not_before > now:
            yield Finding(
                check=self.name,
                title="TLS certificate not yet valid",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category=_CATEGORY,
                cwe="CWE-295",
                description="The server certificate has a notBefore date in the future, so clients will "
                "reject it until that time.",
                remediation="Deploy a certificate whose validity period has already started.",
                location=location,
                evidence=f"notBefore: {cert.get('notBefore')}; subject CN: {subject_cn}",
                references=["https://cwe.mitre.org/data/definitions/295.html"],
            )


@register
class TLSWeakProtocol(Check):
    name = "tls.weak_protocol"
    title = "Weak TLS protocol versions"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def run(self, ctx: ScanContext):
        host = ctx.target.host
        if not host:
            return
        legacy = self._legacy_versions()
        if not legacy:
            return
        seen = set()
        for port in _https_ports(ctx):
            if port in seen:
                continue
            seen.add(port)
            for label, version in legacy:
                if self._handshake_succeeds(host, port, version):
                    yield Finding(
                        check=self.name,
                        title=f"Legacy protocol {label} is enabled",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category=_CATEGORY,
                        cwe="CWE-327",
                        description=f"The server completed a handshake using {label}, a deprecated protocol "
                        "with known cryptographic weaknesses that should no longer be accepted.",
                        remediation="Disable TLS 1.0 and TLS 1.1 and require TLS 1.2 or higher.",
                        location=f"{host}:{port}",
                        evidence=f"{label} handshake succeeded on port {port}",
                        references=["https://cwe.mitre.org/data/definitions/327.html"],
                    )

    def _legacy_versions(self):
        versions = []
        tls_version = getattr(ssl, "TLSVersion", None)
        if tls_version is None:
            return versions
        v10 = getattr(tls_version, "TLSv1", None)
        v11 = getattr(tls_version, "TLSv1_1", None)
        if v10 is not None:
            versions.append(("TLSv1.0", v10))
        if v11 is not None:
            versions.append(("TLSv1.1", v11))
        return versions

    def _handshake_succeeds(self, host, port, version):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context = ssl._create_unverified_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version
        except (ValueError, AttributeError, ssl.SSLError):
            return False
        try:
            with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=host):
                    return True
        except (ssl.SSLError, socket.timeout, ConnectionError, OSError):
            return False


@register
class TLSHttpsUpgrade(Check):
    name = "tls.https_upgrade"
    title = "Missing HTTP to HTTPS upgrade"
    target_kinds = (TargetKind.WEB,)
    min_profile = Profile.PASSIVE

    def applies(self, ctx: ScanContext) -> bool:
        return super().applies(ctx) and ctx.target.scheme == "http"

    def run(self, ctx: ScanContext):
        host = ctx.target.host
        if not host:
            return
        if not self._https_reachable(host, 443):
            return

        base = ctx.target.base_url()
        if not base:
            return
        response = ctx.http.get(base, allow_redirects=False)
        if response is None:
            return

        location = response.headers.get("location", "") or ""
        status = response.status_code
        redirects_to_https = status in (301, 302, 303, 307, 308) and location.lower().startswith("https://")
        if redirects_to_https:
            return

        yield Finding(
            check=self.name,
            title="HTTP not redirected to HTTPS",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=_CATEGORY,
            cwe="CWE-319",
            description="HTTPS is reachable on this host, but the plaintext HTTP root does not redirect to "
            "HTTPS. Traffic can remain in cleartext and is exposed to interception and downgrade.",
            remediation="Redirect all HTTP requests to HTTPS with a 301 and enable HSTS.",
            location=base,
            evidence=f"HTTP status {status}; Location: {location or '(none)'}",
            references=["https://cwe.mitre.org/data/definitions/319.html"],
        )

    def _https_reachable(self, host, port):
        context = ssl._create_unverified_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=host):
                    return True
        except (ssl.SSLError, socket.timeout, ConnectionError, OSError):
            return False
