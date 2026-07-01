from __future__ import annotations

import re
import sys
import zipfile

SECRETS = {
    "AWS access key id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Google API key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "Firebase database URL": re.compile(r"https?://[a-z0-9.\-]+\.firebaseio\.com"),
    "Slack token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
}

CLEARTEXT = re.compile(r"http://[a-zA-Z0-9._\-]+(?:/[^\s\"'<>\\]*)?")
LOCAL_HINTS = ("://localhost", "://127.0.0.1", "://10.0.2.2", "://schemas.android.com")

SCANNABLE_SUFFIXES = (".dex", ".arsc", ".xml", ".json", ".properties", ".txt", ".js", ".html", ".so", ".cfg", ".yaml", ".yml")
SCANNABLE_PREFIXES = ("assets/", "res/raw/", "res/values")
MAX_BYTES = 6 * 1024 * 1024
MAX_FILES = 4000
MAX_PER_PATTERN = 8


def should_scan(name: str) -> bool:
    lowered = name.lower()
    if lowered.endswith(SCANNABLE_SUFFIXES):
        return True
    if any(lowered.startswith(prefix) for prefix in SCANNABLE_PREFIXES):
        return True
    return lowered == "classes.dex"


def redact(token: str) -> str:
    return token[:6] + "..." if len(token) > 10 else token


def scan(path: str) -> int:
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"error: could not open {path} as an apk ({exc})")
        return 2

    secret_hits = []
    cleartext_hits = []
    seen_urls = set()
    counts = {label: 0 for label in SECRETS}

    with archive:
        for name in archive.namelist()[:MAX_FILES]:
            if not should_scan(name):
                continue
            try:
                info = archive.getinfo(name)
            except KeyError:
                continue
            if info.file_size > MAX_BYTES:
                continue
            try:
                text = archive.read(name).decode("utf-8", "ignore")
            except (OSError, zipfile.BadZipFile, RuntimeError):
                continue
            for label, pattern in SECRETS.items():
                if counts[label] >= MAX_PER_PATTERN:
                    continue
                for match in pattern.finditer(text):
                    counts[label] += 1
                    secret_hits.append((label, name, redact(match.group(0))))
                    if counts[label] >= MAX_PER_PATTERN:
                        break
            if len(cleartext_hits) < MAX_PER_PATTERN:
                for match in CLEARTEXT.finditer(text):
                    url = match.group(0)
                    if any(hint in url.lower() for hint in LOCAL_HINTS) or url in seen_urls:
                        continue
                    seen_urls.add(url)
                    cleartext_hits.append((name, url))
                    if len(cleartext_hits) >= MAX_PER_PATTERN:
                        break

    print(f"apk_scan: {path}")
    print(f"secrets: {len(secret_hits)}   cleartext urls: {len(cleartext_hits)}")
    if secret_hits:
        print("\n[HIGH] hardcoded secrets (MASVS-STORAGE, CWE-798)")
        for label, name, value in secret_hits:
            print(f"  {label} in {name}: {value}")
    if cleartext_hits:
        print("\n[LOW] cleartext http endpoints (MASVS-NETWORK, CWE-319)")
        for name, url in cleartext_hits:
            print(f"  {url}  ({name})")
    if not secret_hits and not cleartext_hits:
        print("\nno hardcoded secrets or cleartext urls in scanned entries")
    print("\nnote: run androguard or apkanalyzer for AndroidManifest analysis")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python apk_scan.py <path-to.apk>")
        sys.exit(1)
    sys.exit(scan(sys.argv[1]))
