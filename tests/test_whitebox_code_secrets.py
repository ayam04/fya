from __future__ import annotations

import functools
import shutil
import subprocess

import pytest

from fya.detect import detect_target
from fya.engine import run_scan
from fya.models import Profile

_FAKE_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
    "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==\n"
    "-----END RSA PRIVATE KEY-----\n"
)
_FAKE_CERT = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBkTCB+wIJAOxs5vUq0V6nMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n"
    "-----END CERTIFICATE-----\n"
)


def _scan(tmp_path, files):
    for rel, content in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    result = run_scan(detect_target(str(tmp_path)), profile=Profile.PASSIVE, detect_external=False)
    assert not result.errors, result.errors
    return result


def _hits(result, check_name):
    return [f for f in result.findings if f.check == check_name]


# ----------------------------------------------------------------------------------
# whitebox.committed_key_material
# ----------------------------------------------------------------------------------

def test_committed_key_material_fires(tmp_path):
    result = _scan(tmp_path, {
        "deploy/id_rsa": _FAKE_PRIVATE_KEY,
        ".npmrc": "//registry.npmjs.org/:_authToken=npm_abcdefgh12345678\n",
        ".env.production": "DATABASE_PASSWORD=s3cr3t-prod-value\nDEBUG=0\n",
    })
    findings = _hits(result, "whitebox.committed_key_material")
    locations = {f.location for f in findings}
    assert "deploy/id_rsa" in locations
    assert ".npmrc" in locations
    assert ".env.production" in locations
    key_finding = next(f for f in findings if f.location == "deploy/id_rsa")
    assert key_finding.evidence == "-----BEGIN RSA PRIVATE KEY-----"
    assert "MIIBOgIBAAJBAKj34" not in key_finding.evidence


def test_committed_key_material_service_account_json(tmp_path):
    sa = (
        '{\n  "type": "service_account",\n  "project_id": "demo",\n'
        '  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIBfake\\n-----END PRIVATE KEY-----\\n",\n'
        '  "client_email": "svc@demo.iam.gserviceaccount.com"\n}\n'
    )
    result = _scan(tmp_path, {"config/service-account.json": sa})
    findings = _hits(result, "whitebox.committed_key_material")
    assert {f.location for f in findings} == {"config/service-account.json"}


def test_committed_key_material_reports_git_remote_credential(tmp_path):
    result = _scan(tmp_path, {
        ".git/config": (
            '[remote "origin"]\n'
            "\turl = https://ci-bot:ghp_abcdefghijklmnopqrstuvwx@github.com/acme/app.git\n"
        ),
    })
    findings = _hits(result, "whitebox.committed_key_material")
    assert ".git/config" in {f.location for f in findings}
    remote = next(f for f in findings if f.location == ".git/config")
    # The token is the secret being reported; it must never be echoed back in full.
    assert "ghp_abcdefghijklmnopqrstuvwx" not in remote.evidence


@pytest.mark.skipif(not shutil.which("git"), reason="needs git on PATH")
def test_committed_key_material_skips_untracked_files_in_a_real_repo(tmp_path):
    # The tracked-file filter only engages when `git ls-files` actually answers, which needs a
    # real repository: a hand-made .git directory is not one, and git versions disagree about
    # that. Build a genuine repo so the suppression is exercised deterministically.
    for rel, content in {
        "committed/id_rsa": _FAKE_PRIVATE_KEY,
        "untracked/id_rsa": _FAKE_PRIVATE_KEY,
    }.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    run = functools.partial(subprocess.run, cwd=str(tmp_path), check=True, capture_output=True)
    run(["git", "init", "-q"])
    run(["git", "add", "committed/id_rsa"])

    result = run_scan(detect_target(str(tmp_path)), profile=Profile.PASSIVE, detect_external=False)
    assert not result.errors, result.errors
    locations = {f.location for f in _hits(result, "whitebox.committed_key_material")}
    assert "committed/id_rsa" in locations
    assert "untracked/id_rsa" not in locations


def test_committed_key_material_silent_on_public_material(tmp_path):
    result = _scan(tmp_path, {
        "certs/server.pem": _FAKE_CERT,
        "certs/public.key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ==\n-----END PUBLIC KEY-----\n",
        ".env.example": "DATABASE_PASSWORD=${DB_PASSWORD}\nAPI_KEY=<your-key-here>\n",
        ".npmrc": "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nregistry=https://registry.npmjs.org/\n",
        "infra/terraform.tfstate.example": '{"resources": []}\n',
    })
    assert not _hits(result, "whitebox.committed_key_material")


def test_committed_key_material_silent_on_dev_default_env_values(tmp_path):
    # The canonical docker-compose dev defaults are not live credentials and must not be
    # reported as "rotate this and rewrite history".
    result = _scan(tmp_path, {
        ".env": (
            "POSTGRES_PASSWORD=postgres\n"
            "SECRET_KEY=changeme-in-production\n"
            "API_TOKEN=your-token-here\n"
            "SESSION_SECRET=replace-me\n"
            "SMTP_PASSWORD=password\n"
        ),
    })
    assert not _hits(result, "whitebox.committed_key_material")


def test_committed_key_material_env_confidence_is_medium(tmp_path):
    result = _scan(tmp_path, {".env": "STRIPE_SECRET=sk_live_51H8xQ2eZvKYlo2C\n"})
    findings = _hits(result, "whitebox.committed_key_material")
    assert [f.location for f in findings] == [".env"]
    # Recognised by shape alone, so it must not claim behavioural confirmation.
    assert findings[0].confidence.name == "MEDIUM"


def test_committed_key_material_respects_gitignore_fallback(tmp_path):
    result = _scan(tmp_path, {
        ".gitignore": "id_rsa\nsecrets/\n",
        "id_rsa": _FAKE_PRIVATE_KEY,
        "secrets/deploy.pem": _FAKE_PRIVATE_KEY,
    })
    assert not _hits(result, "whitebox.committed_key_material")


# ----------------------------------------------------------------------------------
# whitebox.sql_string_building
# ----------------------------------------------------------------------------------

def test_sql_string_building_fires(tmp_path):
    result = _scan(tmp_path, {
        "app/db.py": (
            "import sqlite3\n"
            "\n"
            "def get_user(conn, uid):\n"
            "    cur = conn.cursor()\n"
            '    cur.execute("SELECT * FROM users WHERE id = " + uid)\n'
            "    return cur.fetchone()\n"
        ),
        "web/query.js": (
            "async function findUser(conn, name) {\n"
            "  const rows = await conn.query(`SELECT * FROM users WHERE name = '${name}'`);\n"
            "  return rows[0];\n"
            "}\n"
        ),
    })
    findings = _hits(result, "whitebox.sql_string_building")
    locations = {f.location.split(":")[0] for f in findings}
    assert "app/db.py" in locations
    assert "web/query.js" in locations
    assert all(f.cwe == "CWE-89" for f in findings)


def test_sql_string_building_silent_on_parameterised_code(tmp_path):
    result = _scan(tmp_path, {
        "app/db.py": (
            "def get_user(conn, uid):\n"
            "    cur = conn.cursor()\n"
            '    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n'
            "    return cur.fetchone()\n"
        ),
        "web/query.js": (
            "async function findUser(conn, name) {\n"
            "  const rows = await conn.query('SELECT * FROM users WHERE name = ?', [name]);\n"
            "  return rows[0];\n"
            "}\n"
        ),
        "web/prisma.js": (
            "async function byId(prisma, id) {\n"
            "  return prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;\n"
            "}\n"
        ),
        "app/util.py": (
            "def greet(name):\n"
            '    return "hello " + name\n'
        ),
    })
    assert not _hits(result, "whitebox.sql_string_building")


def test_sql_string_building_silent_on_qmark_and_named_paramstyles(tmp_path):
    # sqlite3/qmark and named paramstyles are correct parameterisation; an unrelated .format()
    # or concatenation on a neighbouring line must not turn them into a HIGH finding.
    result = _scan(tmp_path, {
        "app/store.py": (
            "def add(cur, name, ts):\n"
            '    cur.execute("INSERT INTO events (name, ts) VALUES (?, ?)", (name, ts))\n'
            '    log.debug("inserted event {}".format(name))\n'
        ),
        "app/lookup.py": (
            "def one(cur, uid, name):\n"
            '    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))\n'
            '    return "hello " + name\n'
        ),
        "app/named.py": (
            "def named(cur, uid):\n"
            '    cur.execute("SELECT * FROM users WHERE id = :uid", {"uid": uid})\n'
            '    log.info("done {}".format(uid))\n'
        ),
    })
    assert not _hits(result, "whitebox.sql_string_building")


def test_sql_string_building_fires_on_every_python_interpolation_form(tmp_path):
    result = _scan(tmp_path, {
        "app/fstring.py": (
            "def by_id(conn, uid):\n"
            '    conn.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
        ),
        "app/percent.py": (
            "def by_id(conn, uid):\n"
            '    conn.execute("SELECT * FROM users WHERE id = %s" % uid)\n'
        ),
        "app/format.py": (
            "def by_id(conn, uid):\n"
            '    conn.execute("SELECT * FROM users WHERE id = {}".format(uid))\n'
        ),
    })
    locations = {f.location.split(":")[0] for f in _hits(result, "whitebox.sql_string_building")}
    assert locations == {"app/fstring.py", "app/percent.py", "app/format.py"}


# ----------------------------------------------------------------------------------
# whitebox.auth_verification_disabled
# ----------------------------------------------------------------------------------

def test_auth_verification_disabled_fires(tmp_path):
    result = _scan(tmp_path, {
        "src/client.py": (
            "import jwt\n"
            "import requests\n"
            "\n"
            "def read_claims(token):\n"
            '    return jwt.decode(token, options={"verify_signature": False})\n'
            "\n"
            "def fetch(url):\n"
            "    return requests.get(url, verify=False)\n"
        ),
        "src/httpclient.go": (
            "package client\n"
            "\n"
            "func newTransport() *http.Transport {\n"
            "\treturn &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n"
            "}\n"
        ),
    })
    findings = _hits(result, "whitebox.auth_verification_disabled")
    locations = {f.location.split(":")[0] for f in findings}
    assert "src/client.py" in locations
    assert "src/httpclient.go" in locations
    assert {f.cwe for f in findings} & {"CWE-347", "CWE-295"}


def test_auth_verification_disabled_silent_on_safe_code(tmp_path):
    result = _scan(tmp_path, {
        "src/api_client.py": (
            "import hmac\n"
            "import jwt\n"
            "import requests\n"
            "\n"
            "def read_claims(token, key):\n"
            '    return jwt.decode(token, key, algorithms=["RS256"])\n'
            "\n"
            "def check(mac_value, expected):\n"
            "    return hmac.compare_digest(mac_value, expected)\n"
            "\n"
            "def fetch(url):\n"
            "    return requests.get(url, timeout=10)\n"
        ),
        "src/httpclient.go": (
            "package client\n"
            "\n"
            "func newTransport(pool *x509.CertPool) *http.Transport {\n"
            "\treturn &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}\n"
            "}\n"
        ),
    })
    assert not _hits(result, "whitebox.auth_verification_disabled")


def test_auth_verification_disabled_skips_test_files(tmp_path):
    result = _scan(tmp_path, {
        "src/client_test.go": (
            "package client\n"
            "\n"
            "func TestAgainstSelfSigned(t *testing.T) {\n"
            "\tcfg := &tls.Config{InsecureSkipVerify: true}\n"
            "\t_ = cfg\n"
            "}\n"
        ),
    })
    assert not _hits(result, "whitebox.auth_verification_disabled")


def test_auth_verification_disabled_scans_files_whose_name_contains_test_or_spec(tmp_path):
    # "introspection" contains spec, "attestation" contains test, "token_inspector" contains
    # spec. These are exactly the files where signature verification lives.
    result = _scan(tmp_path, {
        "auth/oauth_introspection.py": (
            "import jwt\n"
            "\n"
            "def read(token):\n"
            '    return jwt.decode(token, options={"verify_signature": False})\n'
        ),
        "sig/attestation.go": (
            "package sig\n"
            "\n"
            "func transport() *http.Transport {\n"
            "\treturn &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n"
            "}\n"
        ),
        "src/token_inspector.ts": (
            "function agent() {\n"
            "  return new https.Agent({ rejectUnauthorized: false });\n"
            "}\n"
        ),
    })
    locations = {
        f.location.split(":")[0] for f in _hits(result, "whitebox.auth_verification_disabled")
    }
    assert locations == {
        "auth/oauth_introspection.py",
        "sig/attestation.go",
        "src/token_inspector.ts",
    }


def test_auth_verification_disabled_still_skips_conventional_test_files(tmp_path):
    result = _scan(tmp_path, {
        "tests/test_client.py": (
            "import jwt\n"
            "\n"
            "def test_read(tok):\n"
            '    jwt.decode(tok, options={"verify_signature": False})\n'
        ),
        "src/client.spec.ts": (
            "it('accepts self signed', () => {\n"
            "  const a = new https.Agent({ rejectUnauthorized: false });\n"
            "});\n"
        ),
    })
    assert not _hits(result, "whitebox.auth_verification_disabled")


def test_auth_verification_disabled_timing_cmp_ignores_lookalike_identifiers(tmp_path):
    result = _scan(tmp_path, {
        "app/machines.go": (
            "package app\n"
            "\n"
            "func same(machineID string, req Req) bool {\n"
            "\tif machineID == req.MachineID {\n"
            "\t\treturn true\n"
            "\t}\n"
            "\treturn false\n"
            "}\n"
        ),
        "app/middleware.js": (
            "function auth(tokenType) {\n"
            "  if (tokenType !== 'Bearer') { return false; }\n"
            "  return true;\n"
            "}\n"
        ),
        "app/secrets_manager.js": (
            "function pick(secretName) {\n"
            "  if (secretName === 'prod/db/password') { return 1; }\n"
            "  return 0;\n"
            "}\n"
        ),
        "app/Fleet.java": (
            "class Fleet {\n"
            "  boolean eq(Machine machine, Machine other) {\n"
            "    return machine.equals(other.machine);\n"
            "  }\n"
            "}\n"
        ),
    })
    assert not _hits(result, "whitebox.auth_verification_disabled")


def test_auth_verification_disabled_timing_cmp_still_fires_on_real_secrets(tmp_path):
    result = _scan(tmp_path, {
        "app/verify.py": (
            "def check(signature, expected):\n"
            "    if signature == expected:\n"
            "        return True\n"
            "    return False\n"
        ),
        "app/verify.js": (
            "function check(csrfToken, expected) {\n"
            "  return csrfToken === expected;\n"
            "}\n"
        ),
    })
    findings = _hits(result, "whitebox.auth_verification_disabled")
    assert {f.location.split(":")[0] for f in findings} == {"app/verify.py", "app/verify.js"}
    assert all(f.cwe == "CWE-208" for f in findings)


# ----------------------------------------------------------------------------------
# whitebox.weak_crypto_usage
# ----------------------------------------------------------------------------------

def test_weak_crypto_usage_fires(tmp_path):
    result = _scan(tmp_path, {
        "src/crypto_util.py": (
            "import random\n"
            "from Crypto.Cipher import AES\n"
            "\n"
            "def encrypt(key, data):\n"
            "    cipher = AES.new(key, AES.MODE_ECB)\n"
            "    return cipher.encrypt(data)\n"
            "\n"
            "def make_reset_token():\n"
            "    return str(random.randint(100000, 999999))\n"
        ),
    })
    findings = _hits(result, "whitebox.weak_crypto_usage")
    titles = " ".join(f.title for f in findings)
    assert "ECB" in titles
    assert "RNG" in titles
    assert all(f.location.startswith("src/crypto_util.py:") for f in findings)


def test_weak_crypto_usage_fires_on_node_legacy_cipher(tmp_path):
    result = _scan(tmp_path, {
        "lib/seal.js": (
            "const crypto = require('crypto');\n"
            "function seal(key, data) {\n"
            "  const c = crypto.createCipher('aes-256-cbc', key);\n"
            "  return c.update(data, 'utf8', 'hex') + c.final('hex');\n"
            "}\n"
        ),
    })
    findings = _hits(result, "whitebox.weak_crypto_usage")
    assert any("createCipher" in f.title for f in findings)


def test_weak_crypto_usage_silent_on_modern_code(tmp_path):
    result = _scan(tmp_path, {
        "src/safe_crypto.py": (
            "import os\n"
            "import secrets\n"
            "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
            "\n"
            "def make_reset_token():\n"
            "    return secrets.token_urlsafe(32)\n"
            "\n"
            "def encrypt(key, data):\n"
            "    iv = os.urandom(16)\n"
            "    worker = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()\n"
            "    return iv + worker.update(data) + worker.finalize()\n"
        ),
        "web/anim.js": (
            "function jitter(base) {\n"
            "  return base + Math.random() * 25;\n"
            "}\n"
        ),
    })
    assert not _hits(result, "whitebox.weak_crypto_usage")


def test_weak_crypto_usage_silent_on_unbound_rng_near_security_words(tmp_path):
    # Math.random()/rand.Intn for jitter, DOM keys or shard selection must not fire just
    # because "session"/"reset" happens to appear within the same three-line window.
    result = _scan(tmp_path, {
        "app/retry.js": (
            "function backoff(attempt) {\n"
            "  const delay = 2 ** attempt * 100 + Math.random() * 50;\n"
            "  logger.warn('retrying session refresh in ' + delay);\n"
            "}\n"
        ),
        "app/forms.js": (
            "function resetForm() {\n"
            "  const id = Math.random().toString(36);\n"
            "  return id;\n"
            "}\n"
        ),
        "app/shard.go": (
            "package app\n"
            "\n"
            "func pick(shards []string) string {\n"
            "\tidx := rand.Intn(len(shards)) // pick shard for session\n"
            "\treturn shards[idx]\n"
            "}\n"
        ),
    })
    assert not _hits(result, "whitebox.weak_crypto_usage")


def test_weak_crypto_usage_fires_when_rng_is_bound_to_a_security_value(tmp_path):
    result = _scan(tmp_path, {
        "app/issue.js": (
            "function issue(user) {\n"
            "  const sessionToken = Math.random().toString(36);\n"
            "  return sessionToken;\n"
            "}\n"
        ),
        "app/csrf.js": (
            "const payload = {\n"
            "  csrfToken: Math.random().toString(16),\n"
            "};\n"
        ),
        "app/Salt.java": (
            "public class Salt {\n"
            "  void fill(byte[] salt) {\n"
            "    new Random().nextBytes(salt);\n"
            "  }\n"
            "}\n"
        ),
    })
    findings = _hits(result, "whitebox.weak_crypto_usage")
    assert {f.location.split(":")[0] for f in findings} == {
        "app/issue.js", "app/csrf.js", "app/Salt.java",
    }
    assert all(f.cwe == "CWE-338" for f in findings)
