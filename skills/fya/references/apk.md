# Android APK static analysis (methodology reference)

This reference tells Claude how to reproduce, by hand and non-destructively, the
static checks that `fya/checks/apk.py` performs on an Android APK. Everything here
is read-only static analysis. You unpack a local file, grep its contents, and
parse its manifest. Nothing is installed on a device and no traffic is generated,
so this is always safe to run against an APK you are authorized to inspect.

Two families of checks exist, matching the source:

1. Content scanning (`apk.hardcoded_secrets`, `apk.cleartext_urls`) reads the APK
   as a zip and pattern-matches file bytes. This needs no dependencies.
2. Manifest analysis (`apk.manifest`) parses `AndroidManifest.xml` for insecure
   flags, exported components, low `minSdkVersion`, and dangerous permissions.
   This needs a binary-XML aware tool (androguard or apkanalyzer), because the
   manifest inside an APK is compiled binary XML, not plain text.

## Getting the APK and setting scope

You need the `.apk` file on local disk. If the target ships as an `.aab`
(App Bundle) or as split APKs, analyze the base APK; for split APKs merge or
inspect each split, since secrets and manifest entries can live in any of them.
Only analyze packages you are authorized to test. Static analysis is inert, but
respect the same authorization boundary you would for a live target.

Confirm the file is a real zip before anything else. An APK is a zip archive:

```bash
file app.apk
unzip -l app.apk | head -40
```

If `unzip -l` errors, the file is not a valid APK and every check should report
that and stop, exactly as the code does when `zipfile.ZipFile` raises
`BadZipFile` (it emits a single INFO finding and returns).

## Step 0: run the bundled no-dependency helper first

Before reaching for any external tool, run the bundled scanner. It reproduces the
secret and cleartext-URL logic from `apk.py` using only the Python standard
library, so it works in any environment with a Python interpreter:

```bash
python skills/fya/scripts/apk_scan.py app.apk
```

It prints HIGH secret findings and LOW cleartext-URL findings with the same
patterns, the same per-pattern cap of 8, the same 4000-file scan limit, the same
6 MB per-entry size cap, and the same redaction (`first 6 chars + "..."` for
tokens longer than 10 chars) as the check code. It does NOT do manifest analysis;
that requires the tools in the manifest section below. Use the helper for a fast
first pass, then follow up with the manual probes to confirm and to cover the
manifest.

---

## Check 1: Hardcoded secrets in APK contents

**What and why.** Detects credentials shipped inside the package (AWS keys, Google
API keys, private key blocks, Firebase database URLs, Slack tokens). Anything
baked into an APK is trivially recoverable by unzipping, so an embedded secret is
effectively already leaked and must be treated as compromised.

**Which files are scanned.** The code only reads entries whose name (lowercased)
ends in one of `.dex .arsc .xml .json .properties .txt .js .html .so .cfg .yaml
.yml`, or starts with `assets/`, `res/raw/`, or `res/values`, or is exactly
`classes.dex`. It skips entries larger than 6 MB and scans at most 4000 entries.
Bytes are decoded as UTF-8 with errors ignored, so matching works even inside
`.dex` and `.so` binaries.

**Non-destructive probe.** Unpack once, then grep for each pattern. These are the
exact regexes from the source:

```bash
mkdir apk_unpacked && unzip -o -q app.apk -d apk_unpacked

# AWS access key id
grep -rEoa 'AKIA[0-9A-Z]{16}' apk_unpacked/

# Google API key
grep -rEoa 'AIza[0-9A-Za-z_\-]{35}' apk_unpacked/

# Private key block
grep -rEoa -- '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' apk_unpacked/

# Firebase database URL
grep -rEoa 'https?://[a-z0-9.\-]+\.firebaseio\.com' apk_unpacked/

# Slack token
grep -rEoa 'xox[baprs]-[0-9A-Za-z\-]{10,}' apk_unpacked/
```

The `-a` flag makes grep treat binary (`.dex`, `.so`) as text, matching the
code's decode-and-scan behavior. On Windows PowerShell, prefer the bundled helper
or use `Select-String -Pattern` with the same regexes.

Python fallback (mirrors the check without unpacking to disk):

```python
import re, zipfile
pats = {
  "AWS": re.compile(rb"AKIA[0-9A-Z]{16}"),
  "Google": re.compile(rb"AIza[0-9A-Za-z_\-]{35}"),
  "PrivKey": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
  "Firebase": re.compile(rb"https?://[a-z0-9.\-]+\.firebaseio\.com"),
  "Slack": re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}"),
}
z = zipfile.ZipFile("app.apk")
for n in z.namelist()[:4000]:
    data = z.read(n)
    for label, p in pats.items():
        for m in p.finditer(data):
            print(label, n, m.group(0)[:6], b"...")
```

**Detection signal.** A regex match inside any scanned entry confirms the finding.
Report the file it was found in and a redacted token (first 6 characters plus
`...`). There is no baseline step for this check: the patterns are specific enough
that a match is the signal on its own.

**False-positive discipline.** Confidence is MEDIUM in the code, not HIGH, on
purpose. A structural match (`AKIA...`, `AIza...`) proves the string is present,
not that it is a live, privileged credential. Google `AIza` keys in particular
are often client API keys that are meant to ship and are restricted by referrer
or package (still worth flagging, but not automatically catastrophic). Do not
claim exploitation from a match alone; report the location and recommend rotation
and verification. Note that `firebaseio.com` also matches under the cleartext
check only if it is `http://`; here the Firebase pattern flags the URL as a
hardcoded backend reference regardless of scheme.

**Severity / mapping.** Severity HIGH, confidence MEDIUM. MASVS category
MASVS-STORAGE. CWE-798 (Use of Hard-coded Credentials).

---

## Check 2: Cleartext HTTP URLs in APK contents

**What and why.** Detects plaintext `http://` endpoints referenced anywhere in the
package. Traffic to such endpoints can be intercepted or tampered with on the
network path.

**Non-destructive probe.** Same unpack, then:

```bash
grep -rEoa 'http://[a-zA-Z0-9._\-]+(/[^[:space:]"'"'"'<>\\]*)?' apk_unpacked/ \
  | sort -u
```

Or use the Python fallback with `re.compile(rb"http://[a-zA-Z0-9._\-]+...")`.

**Detection signal.** A unique `http://` URL that is NOT a local or schema host.
The code dedupes URLs (`seen` set) and caps output at 8, so report distinct
endpoints only.

**False-positive discipline.** The check explicitly ignores URLs containing
`://localhost`, `://127.0.0.1`, `://10.0.2.2` (the Android emulator loopback), or
`://schemas.android.com` (XML namespace declarations, not network calls). Filter
these out before reporting or you will drown in namespace noise. A cleartext URL
in the package proves the app references an HTTP endpoint; it does not prove that
endpoint is actually contacted at runtime, so keep confidence MEDIUM.

**Severity / mapping.** Severity LOW, confidence MEDIUM. MASVS category
MASVS-NETWORK. CWE-319 (Cleartext Transmission of Sensitive Information).

---

## Check 3: Android manifest configuration

The manifest inside an APK is compiled binary XML. You cannot grep it as text, so
you need a tool that decodes it. The check uses androguard; the equivalent CLI is
`apkanalyzer` from the Android SDK, or `aapt2 dump badging` / `apktool` for
partial coverage.

Install one of:

```bash
pip install androguard          # Python, what the check uses
# or use the Android SDK:
#   $ANDROID_HOME/cmdline-tools/latest/bin/apkanalyzer manifest print app.apk
```

Dump the decoded manifest once with androguard so all sub-checks share it:

```python
from androguard.core.apk import APK
import logging; logging.getLogger("androguard").setLevel(logging.ERROR)
apk = APK("app.apk")
xml = apk.get_android_manifest_axml().get_xml().decode()
print(xml)
print("min_sdk:", apk.get_min_sdk_version())
print("perms:", apk.get_permissions())
```

Or, without Python, print the decoded manifest with apkanalyzer:

```bash
apkanalyzer manifest print app.apk
apkanalyzer manifest min-sdk app.apk
apkanalyzer manifest permissions app.apk
```

**Graceful degradation.** If neither androguard nor apkanalyzer is available, say
so and stop the manifest sub-checks, exactly as the code does: when the
`androguard` import fails it emits one INFO finding ("Manifest analysis skipped")
and returns. Do not fabricate manifest findings from a binary blob you cannot
decode. The content checks (1 and 2) still run without any tool.

The following sub-checks all read attributes on the decoded manifest. Note the
code reads booleans with `str(value).strip().lower() == "true"`.

### 3a. Debuggable application

**Signal.** `application@android:debuggable == "true"`. A debuggable release lets
anyone attach a debugger, read process memory, and manipulate the running app.

```bash
apkanalyzer manifest print app.apk | grep -i 'android:debuggable'
```

Report only when the attribute is present AND true. Severity HIGH, confidence
HIGH. MASVS-CODE. CWE-489 (Active Debug Code).

### 3b. allowBackup enabled

**Signal.** `application@android:allowBackup == "true"`. App data can be pulled via
`adb backup` on unlocked or rooted devices, exposing stored data.

```bash
apkanalyzer manifest print app.apk | grep -i 'android:allowBackup'
```

Severity MEDIUM, confidence HIGH. MASVS-STORAGE. CWE-530 (Exposure of Backup File
to Unauthorized Control Sphere).

### 3c. Cleartext traffic / missing network security config

Two distinct findings, mutually exclusive in the code:

- If `application@android:usesCleartextTraffic == "true"`: cleartext is explicitly
  permitted. Severity MEDIUM, confidence HIGH.
- Else if `usesCleartextTraffic` is absent AND there is no
  `android:networkSecurityConfig`: no policy is declared and, depending on target
  SDK, cleartext may be allowed by default. Severity MEDIUM, confidence LOW (this
  is a "depends on defaults" finding, so keep confidence low and phrase it as
  conditional).

```bash
apkanalyzer manifest print app.apk | grep -iE 'usesCleartextTraffic|networkSecurityConfig'
```

Both map to MASVS-NETWORK, CWE-319.

### 3d. Exported components without a permission guard

**What and why.** An exported activity, activity-alias, service, receiver, or
provider with no permission requirement can be invoked directly by any other app
on the device.

**The exact rule from the code** (do not simplify it):

For each `<activity> <activity-alias> <service> <receiver> <provider>` node that
has an `android:name`:

1. Read `android:exported`.
   - If it is present and NOT true: skip (developer explicitly closed it).
   - If it is present and true: it is exported.
   - If it is absent: it counts as exported ONLY when the node contains an
     `<intent-filter>` child (the implicit-exported-by-default rule). No
     intent-filter and no explicit `exported` means skip.
2. Then, if the node has an `android:permission` attribute, skip it (it is
   guarded). Only unguarded exported components are reported.

The evidence string distinguishes the two cases: `exported=true, no permission`
versus `exported by default via intent-filter, no permission`. Output is capped at
8 components.

Inspect the decoded manifest and apply the rule per node:

```bash
apkanalyzer manifest print app.apk
# For each component, check: android:exported, presence of <intent-filter>,
# and android:permission, following the rule above.
```

**False-positive discipline.** The implicit-export rule is the common trap: a
component with an intent-filter and no `android:exported` IS exported on older
target SDKs, but a component with `android:exported="false"` is closed even if it
has an intent-filter, and one guarded by `android:permission` is not freely
invocable. Apply all three conditions before reporting. Confidence is MEDIUM
because reachability and actual impact depend on what the component does.

Severity MEDIUM, confidence MEDIUM. MASVS-PLATFORM. CWE-926 (Improper Export of
Android Application Components).

### 3e. Low minSdkVersion

**Signal.** `minSdkVersion < 24`. Older Android versions lack current platform
hardening and get no security updates.

```bash
apkanalyzer manifest min-sdk app.apk
```

Report only if the parsed integer is below 24. If the value is missing or
non-numeric, the code returns nothing, so do not report. Severity LOW, confidence
HIGH. MASVS-PLATFORM. (No CWE assigned in the code.)

### 3f. Dangerous permissions requested

**Signal.** The app requests one or more permissions from this sensitive set:
READ_SMS, SEND_SMS, RECEIVE_SMS, READ_CONTACTS, WRITE_CONTACTS,
ACCESS_FINE_LOCATION, ACCESS_BACKGROUND_LOCATION, RECORD_AUDIO, CAMERA,
READ_CALL_LOG, READ_PHONE_STATE, READ_EXTERNAL_STORAGE, WRITE_EXTERNAL_STORAGE,
SYSTEM_ALERT_WINDOW, REQUEST_INSTALL_PACKAGES.

```bash
apkanalyzer manifest permissions app.apk
```

The code emits a single consolidated finding listing the flagged permissions
(deduped, sorted, first 8 shown), not one per permission.

**False-positive discipline.** This is an informational hygiene finding, not a
vulnerability. Requesting a dangerous permission is often legitimate (a camera app
needs CAMERA). Report it as "confirm each is required and justified," matching the
remediation text. Severity LOW, confidence HIGH. MASVS-PLATFORM. (No CWE assigned
in the code.)

---

## Summary of mappings

| Check | Severity | Confidence | MASVS | CWE |
|---|---|---|---|---|
| Hardcoded secrets | HIGH | MEDIUM | MASVS-STORAGE | CWE-798 |
| Cleartext HTTP URLs | LOW | MEDIUM | MASVS-NETWORK | CWE-319 |
| Debuggable | HIGH | HIGH | MASVS-CODE | CWE-489 |
| allowBackup | MEDIUM | HIGH | MASVS-STORAGE | CWE-530 |
| Cleartext traffic permitted | MEDIUM | HIGH | MASVS-NETWORK | CWE-319 |
| No network security config | MEDIUM | LOW | MASVS-NETWORK | CWE-319 |
| Exported component, unguarded | MEDIUM | MEDIUM | MASVS-PLATFORM | CWE-926 |
| Low minSdkVersion (< 24) | LOW | HIGH | MASVS-PLATFORM | none |
| Dangerous permissions | LOW | HIGH | MASVS-PLATFORM | none |

References: https://mas.owasp.org/MASVS/ and https://mas.owasp.org/MASTG/
