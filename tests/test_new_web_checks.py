from __future__ import annotations

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile

_EXPECTED = {
    "web.js_secrets",
    "web.source_map_exposure",
    "web.vcs_exposure",
    "web.exposed_config_secrets",
    "web.directory_listing",
    "web.ssrf",
    "web.nosql_injection",
    "web.xpath_ldap_ssi_injection",
    "web.modern_headers",
    "web.cookie_scope",
    "web.cors_advanced",
    "web.cache_poison_headers",
    "web.url_override_headers",
    "api.graphql_hardening",
}


def test_new_web_checks_fire(live_server):
    target = detect_target(live_server)
    result = run_scan(target, profile=Profile.AGGRESSIVE, detect_external=False)
    names = {f.check for f in result.findings}
    missing = _EXPECTED - names
    assert not missing, f"missing: {sorted(missing)}; fired: {sorted(names)}"
    assert not result.errors, result.errors
