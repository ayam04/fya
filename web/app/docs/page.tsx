import { CodeBlock } from "@/components/CodeBlock"
import { Callout } from "@/components/Callout"
import { DocsMobileNav } from "@/components/DocsMobileNav"

export const metadata = {
  title: "fya docs - usage and reference",
  description:
    "Install fya, scan a web server or an APK, run it as a Claude skill, pick a mode and profile, run authenticated and scoped scans, gate CI with a baseline, and read the full check catalog.",
}

const VERSION = "0.5.0"

const changelog = [
  [
    "0.5.0",
    "16 new attack techniques and a codebase-wide bug sweep",
    [
      "New web checks: client-side JS secret exposure, exposed source maps, dumpable .git/.svn/.hg/.bzr repos, exposed config and credential files, directory listing, and advanced CORS bypasses (null origin, prefix/suffix match bugs).",
      "New injection and SSRF checks: signature-based SSRF (cloud metadata and file://), MongoDB-style NoSQL injection, and XPath/LDAP/SSI injection.",
      "New header checks: unkeyed forwarded-header cache poisoning, X-Original-URL/X-Rewrite-URL access-control bypass, missing COOP/CORP/Permissions-Policy, and cookie prefix and scope misuse.",
      "New GraphQL hardening check: field-suggestion leakage, query batching, and GET/CSRF execution.",
      "New mobile and source checks: insecure WebView JavaScript bridge, unverified App Links, weak custom-permission guards, and dangerous GitHub Actions workflow patterns (pwn-request and script injection).",
      "Fixed 15 bugs found by an adversarial audit, including a CLI crash on malformed ports, false-positive sensitive-file detection, missed form-target and CDN-versioned library discovery, and two external-tool integrations (nikto, testssl) that silently never fired.",
    ],
  ],
  [
    "0.4.0",
    "Black, gray, and white-box test strategies",
    [
      "New black-box mode: input fuzzing and robustness. Malformed, oversized, wrong-type, unicode, null-byte, and format-string payloads that surface crashes and leaked stack traces.",
      "New gray-box mode: IDOR detection and auth-bypass probing of protected routes.",
      "New white-box mode: point fya at a source directory. Scans for hardcoded secrets and risky sinks (eval, exec, shell=True, pickle, disabled TLS verification), and folds in semgrep or bandit when installed.",
      "Reports now group findings by test strategy, in the console, HTML, and Markdown.",
      "Load, stress, and network-chaos testing are deliberately excluded. They are denial-of-service shaped. Use k6, Locust, or Toxiproxy for those.",
    ],
  ],
]

const nav = [
  ["install", "Installation"],
  ["whats-new", "What's new"],
  ["quickstart", "Quickstart"],
  ["skill", "Claude skill"],
  ["targets", "Targets"],
  ["modes", "Scan modes"],
  ["profiles", "Profiles"],
  ["auth", "Authentication and scope"],
  ["baseline", "Baseline and CI"],
  ["reports", "Reports"],
  ["checks", "Checks catalog"],
  ["tools", "External tools"],
  ["docker", "Docker"],
  ["responsible", "Responsible use"],
]

const modes = [
  ["auto", "Everything that applies to the detected target. The default."],
  ["recon", "Passive, read-only reconnaissance."],
  ["web", "Web app: headers, TLS, active web checks, and API."],
  ["api", "API surface plus supporting web checks."],
  ["mobile", "Android APK static analysis."],
  ["blackbox", "No internals: input fuzzing and robustness plus outside-in web checks."],
  ["graybox", "Partial knowledge: IDOR, auth bypass, and API contract probing."],
  ["whitebox", "Source access: static analysis of a code directory."],
  ["full", "Everything, aggressive, including external tool handoff."],
]

const profiles = [
  ["passive", "Read-only. Headers, TLS, cookies, disclosure, fingerprinting."],
  ["safe", "Non-destructive active probes. Reflection, error signatures, CORS. The default."],
  ["aggressive", "Heavier probing and external-tool handoff. Still non-destructive."],
]

const reports = [
  ["console", "The default. A colored summary table in your terminal."],
  ["json", "Machine-readable output for pipelines and dashboards."],
  ["sarif", "Upload to GitHub code scanning. Includes fingerprints for de-duplication."],
  ["markdown", "Drop into issues, wikis, or pull requests."],
  ["html", "A self-contained, shareable page."],
]

const checks = [
  ["Web passive", "passive", ["web.security_headers", "web.version_disclosure", "web.insecure_cookies"]],
  ["Web active", "safe", ["web.reflected_xss", "web.sql_injection", "web.open_redirect", "web.path_traversal", "web.cors_misconfig", "web.cors_advanced", "web.dangerous_methods", "web.sensitive_files"]],
  ["Web advanced", "safe / aggressive", ["web.ssti", "web.csrf", "web.host_header", "web.crlf", "web.cache_poison_headers", "web.url_override_headers"]],
  ["Web secrets & files", "safe", ["web.js_secrets", "web.source_map_exposure", "web.vcs_exposure", "web.exposed_config_secrets", "web.directory_listing"]],
  ["Web SSRF & injection", "safe", ["web.ssrf", "web.nosql_injection", "web.xpath_ldap_ssi_injection"]],
  ["Web hardening", "passive", ["web.csp_weaknesses", "web.jwt_weak_algorithm", "web.jwt_missing_expiry", "web.jwt_sensitive_claims", "web.frontend_libraries", "web.modern_headers", "web.cookie_scope", "web.security_txt", "web.robots_sensitive_paths"]],
  ["Black box", "safe", ["blackbox.input_fuzzing"]],
  ["Gray box", "safe", ["graybox.idor", "graybox.auth_bypass"]],
  ["White box (source)", "passive / safe", ["whitebox.hardcoded_secrets", "whitebox.dangerous_patterns", "whitebox.cicd_misconfig", "whitebox.static_analysis"]],
  ["TLS", "passive", ["tls.certificate", "tls.weak_protocol", "tls.https_upgrade"]],
  ["API", "safe", ["api.docs_exposure", "api.graphql_introspection", "api.graphql_hardening", "api.verbose_errors", "api.admin_endpoints"]],
  ["APK static", "passive", ["apk.hardcoded_secrets", "apk.cleartext_urls", "apk.manifest", "apk.webview_config"]],
  ["Integrations", "aggressive", ["integrations.nuclei", "integrations.nikto", "integrations.nmap", "integrations.sqlmap", "integrations.tls"]],
]

function Code({ children }: { children: React.ReactNode }) {
  return <code className="rounded bg-white/[0.07] px-1.5 py-0.5 font-mono text-[13px] text-ink">{children}</code>
}

function H2({ id, children }: { id: string; children: string }) {
  return (
    <h2 id={id} className="font-display mt-16 mb-4 scroll-mt-36 border-b border-line pb-2 text-2xl font-semibold tracking-tight lg:scroll-mt-28">
      {children}
    </h2>
  )
}

const p = "mb-4 text-[15px] leading-relaxed text-ink/80"
const th = "py-2 pr-6 text-left font-medium text-muted"
const td = "py-2.5 align-top text-ink/80"
const mono = "py-2.5 pr-6 align-top font-mono text-[13px] text-brand2"

export default function Docs() {
  return (
    <div className="mx-auto grid max-w-5xl gap-10 px-5 pb-16 pt-28 lg:grid-cols-[210px_1fr]">
      <aside className="hidden lg:block">
        <nav className="sticky top-24 space-y-0.5 text-sm">
          <div className="mb-3 text-xs font-medium uppercase tracking-wide text-muted">Documentation</div>
          {nav.map(([id, label]) => (
            <a key={id} href={`#${id}`} className="block rounded-md px-2.5 py-1.5 text-muted transition-colors hover:bg-white/5 hover:text-ink">
              {label}
            </a>
          ))}
        </nav>
      </aside>

      <article className="min-w-0 max-w-3xl">
        <DocsMobileNav items={nav} />
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-display text-4xl font-semibold tracking-tight">Documentation</h1>
          <a
            href="#whats-new"
            className="rounded-full border border-brand/30 bg-brand/10 px-2.5 py-1 font-mono text-xs font-medium text-brand shadow-[0_0_20px_-8px_rgba(255,77,77,0.7)]"
          >
            v{VERSION}
          </a>
        </div>
        <p className="mt-3 text-lg text-muted">Everything to install fya, scan your app, and wire it into CI.</p>
        <div className="mt-6">
          <Callout tone="warn">
            fya performs active security testing. Only scan systems you own or are explicitly authorized in writing
            to test. Any non-local target requires <Code>--i-am-authorized</Code>.
          </Callout>
        </div>

        <H2 id="install">Installation</H2>
        <p className={p}>fya needs Python 3.9 or newer. The core install pulls only requests and rich.</p>
        <CodeBlock code={"pip install fya\npip install \"fya[apk]\"       # Android APK manifest analysis\npip install \"fya[browser]\"   # headless-browser crawler for SPAs"} />
        <p className={p + " mt-4"}>From a clone, with the test tooling:</p>
        <CodeBlock code={"git clone https://github.com/ayam04/fya\ncd fya\npip install -e \".[dev]\""} />

        <H2 id="whats-new">What&apos;s new</H2>
        {changelog.map(([version, title, items]) => (
          <div key={version as string} className="rounded-xl border border-line bg-surface/40 p-5">
            <div className="mb-3 flex items-baseline gap-3">
              <span className="rounded-md bg-brand/15 px-2 py-0.5 font-mono text-[13px] font-semibold text-brand">
                v{version as string}
              </span>
              <h3 className="text-base font-semibold">{title as string}</h3>
            </div>
            <ul className="space-y-2">
              {(items as string[]).map((item) => (
                <li key={item} className="flex gap-2.5 text-[15px] leading-relaxed text-ink/80">
                  <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-brand/70" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}

        <H2 id="quickstart">Quickstart</H2>
        <p className={p}>Point fya at a local server or an APK. Localhost needs no authorization flag.</p>
        <CodeBlock code={"fya scan http://127.0.0.1:8000\nfya scan ./app-release.apk\n\nfya scan http://127.0.0.1:8000 -o report.html   # shareable report\nfya scan http://127.0.0.1:8000 --fail-on high    # exit non-zero in CI\nfya tools                                         # list detectable external tools"} />
        <p className={p + " mt-4"}>Try it against the bundled deliberately-vulnerable app in the repo:</p>
        <CodeBlock code={"python examples/vulnerable_app.py            # starts on http://127.0.0.1:5001\nfya scan http://127.0.0.1:5001 --mode full -o report.html"} />

        <H2 id="skill">The Claude skill</H2>
        <p className={p}>
          Prefer to stay in Claude? fya ships as a skill that makes Claude run the same non-destructive scan
          itself, with no package to install. It confirms you own the target, runs the checks, and reports in the
          chat.
        </p>
        <p className={p}>Install it by copying one folder into your Claude skills directory:</p>
        <CodeBlock code={"git clone https://github.com/ayam04/fya\ncp -r fya/skills/fya ~/.claude/skills/fya"} />
        <p className={p + " mt-4"}>
          On Windows the destination is <Code>%USERPROFILE%\.claude\skills\fya</Code>. Then just ask Claude:
        </p>
        <CodeBlock code={"scan http://localhost:3000 for vulnerabilities\ncheck ./app-release.apk for security issues"} />
        <p className={p + " mt-4"}>
          Claude confirms the target and authorization, picks a mode and profile, runs the OWASP-mapped checks, and
          applies the same false-positive discipline as the CLI. It is fully agentic: it drives the probes with its
          own tools, so it works even where the package is not installed.
        </p>

        <H2 id="targets">Targets</H2>
        <p className={p}>
          fya detects the target automatically. A path ending in <Code>.apk</Code> (or any zip containing an
          AndroidManifest) is analyzed statically. A local directory is treated as source and analyzed white-box.
          Anything else is a web target; a bare host defaults to <Code>http</Code> for localhost and private
          addresses and <Code>https</Code> otherwise.
        </p>
        <CodeBlock code={"fya scan http://127.0.0.1:8000    # web target\nfya scan ./app-release.apk        # android package\nfya scan ./my-service             # source directory, white-box"} />

        <H2 id="modes">Scan modes</H2>
        <p className={p}>
          A mode selects which family of checks runs. Pick one with <Code>--mode</Code>, refine with{" "}
          <Code>--only</Code> and <Code>--skip</Code>, or choose from a menu with <Code>--interactive</Code>. List
          them with <Code>fya modes</Code>.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead><tr className="border-b border-line"><th className={th}>Mode</th><th className={th + " pr-0"}>What it runs</th></tr></thead>
            <tbody>
              {modes.map(([m, d]) => (
                <tr key={m} className="border-b border-line"><td className={mono}>{m}</td><td className={td}>{d}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4">
          <Callout tone="warn">
            Load, stress, and network-chaos testing are deliberately out of scope. They are
            denial-of-service shaped and break the non-destructive guarantee. Use k6, Locust, or
            Toxiproxy for those, on infrastructure you own.
          </Callout>
        </div>

        <H2 id="profiles">Profiles</H2>
        <p className={p}>
          A profile sets how hard fya probes, independent of the mode. Request pacing adapts automatically and slows
          down on errors, timeouts, and slow responses. fya never floods a target or runs denial-of-service
          payloads.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead><tr className="border-b border-line"><th className={th}>Profile</th><th className={th + " pr-0"}>Behavior</th></tr></thead>
            <tbody>
              {profiles.map(([m, d]) => (
                <tr key={m} className="border-b border-line"><td className={mono}>{m}</td><td className={td}>{d}</td></tr>
              ))}
            </tbody>
          </table>
        </div>

        <H2 id="auth">Authentication and scope</H2>
        <p className={p}>Scan behind a login, and keep the scan inside a boundary with scope and budget controls.</p>
        <CodeBlock code={"# authenticated\nfya scan https://staging.example.com --i-am-authorized \\\n  -H \"Authorization: Bearer $TOKEN\"\nfya scan http://127.0.0.1:8000 --cookie \"session=abc123\"\n\n# scope and budget\nfya scan http://127.0.0.1:8000 --include '/app' --exclude '/logout'\nfya scan http://127.0.0.1:8000 --max-requests 500\n\n# render JS and single-page apps (needs the [browser] extra)\nfya scan http://127.0.0.1:8000 --spa"} />

        <H2 id="baseline">Baseline and CI</H2>
        <p className={p}>Record the findings you have accepted, then fail the build only on new ones.</p>
        <CodeBlock code={"fya scan http://127.0.0.1:8000 --write-baseline .fya-baseline.json\nfya scan http://127.0.0.1:8000 --baseline .fya-baseline.json --fail-on high"} />

        <H2 id="reports">Reports</H2>
        <p className={p}>
          Format is inferred from the <Code>-o</Code> extension, or set it with <Code>--format</Code>. Use{" "}
          <Code>--fail-on</Code> to return a non-zero exit code.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead><tr className="border-b border-line"><th className={th}>Format</th><th className={th + " pr-0"}>Use it for</th></tr></thead>
            <tbody>
              {reports.map(([m, d]) => (
                <tr key={m} className="border-b border-line"><td className={mono}>{m}</td><td className={td}>{d}</td></tr>
              ))}
            </tbody>
          </table>
        </div>

        <H2 id="checks">Checks catalog</H2>
        <p className={p}>
          58 checks across thirteen areas, each mapped to the OWASP Top 10 or MASVS and a CWE. Every check runs
          only at or above its minimum profile.
        </p>
        <div className="space-y-4">
          {checks.map(([area, prof, names]) => (
            <div key={area as string} className="rounded-xl border border-line bg-surface/40 p-5">
              <div className="mb-3 flex items-baseline justify-between gap-3">
                <h3 className="text-base font-semibold">{area}</h3>
                <span className="font-mono text-xs text-muted">min profile: {prof}</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {(names as string[]).map((n) => (
                  <span key={n} className="rounded-md border border-line bg-white/[0.03] px-2 py-1 font-mono text-[12px] text-ink/75">
                    {n}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>

        <H2 id="tools">External tools</H2>
        <p className={p}>
          If any of these are on your <Code>PATH</Code>, fya runs them and folds their results into one normalized
          report. If not, it falls back to built-in checks. Check what is detected with <Code>fya tools</Code>.
        </p>
        <p className={p}>
          <Code>nuclei</Code> <Code>nikto</Code> <Code>sqlmap</Code> <Code>nmap</Code> <Code>testssl.sh</Code>{" "}
          <Code>sslyze</Code> <Code>jadx</Code> <Code>apkleaks</Code>
        </p>

        <H2 id="docker">Docker</H2>
        <p className={p}>The image bundles nmap, so external-tool handoff works out of the box.</p>
        <CodeBlock code={"docker build -t fya .\ndocker run --rm --network host fya scan http://127.0.0.1:8000"} />

        <H2 id="responsible">Responsible use</H2>
        <p className={p}>
          fya performs active security testing. Only scan systems you own or are explicitly authorized in writing to
          test. Scanning a non-local target requires <Code>--i-am-authorized</Code>. Scans are non-destructive by
          default, with no flooding and no denial-of-service payloads. You are responsible for how you use this
          tool.
        </p>
      </article>
    </div>
  )
}
