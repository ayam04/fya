import { CodeBlock } from "@/components/CodeBlock"

export const metadata = {
  title: "fya docs - usage and reference",
  description: "Install fya, scan a web server or an APK, pick a mode and profile, run authenticated and scoped scans, gate CI with a baseline, and read the full check catalog.",
}

const nav = [
  ["install", "Installation"],
  ["quickstart", "Quickstart"],
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
  ["Web active", "safe", ["web.reflected_xss", "web.sql_injection", "web.open_redirect", "web.path_traversal", "web.cors_misconfig", "web.dangerous_methods", "web.sensitive_files"]],
  ["Web advanced", "safe / aggressive", ["web.ssti", "web.csrf", "web.host_header", "web.crlf"]],
  ["Web hardening", "passive", ["web.csp_weaknesses", "web.jwt_weak_algorithm", "web.jwt_missing_expiry", "web.jwt_sensitive_claims", "web.frontend_libraries", "web.security_txt", "web.robots_sensitive_paths"]],
  ["TLS", "passive", ["tls.certificate", "tls.weak_protocol", "tls.https_upgrade"]],
  ["API", "safe", ["api.docs_exposure", "api.graphql_introspection", "api.verbose_errors", "api.admin_endpoints"]],
  ["APK static", "passive", ["apk.hardcoded_secrets", "apk.cleartext_urls", "apk.manifest"]],
  ["Integrations", "aggressive", ["integrations.nuclei", "integrations.nikto", "integrations.nmap", "integrations.sqlmap", "integrations.tls"]],
]

function Code({ children }: { children: React.ReactNode }) {
  return <code className="rounded bg-code px-1.5 py-0.5 font-mono text-[13px] text-ink">{children}</code>
}

function H2({ id, children }: { id: string; children: string }) {
  return (
    <h2 id={id} className="mt-16 mb-4 scroll-mt-24 border-b border-line pb-2 text-2xl font-semibold tracking-tight">
      {children}
    </h2>
  )
}

const p = "mb-4 text-[15px] leading-relaxed text-ink/90"

export default function Docs() {
  return (
    <div className="mx-auto grid max-w-6xl gap-10 px-5 py-12 lg:grid-cols-[220px_1fr]">
      <aside className="hidden lg:block">
        <nav className="sticky top-24 space-y-1 text-sm">
          <div className="mb-3 text-xs font-medium uppercase tracking-wide text-muted">Documentation</div>
          {nav.map(([id, label]) => (
            <a key={id} href={`#${id}`} className="block rounded-md px-2.5 py-1.5 text-muted transition hover:bg-code hover:text-ink">
              {label}
            </a>
          ))}
        </nav>
      </aside>

      <article className="min-w-0 max-w-3xl">
        <h1 className="text-3xl font-semibold tracking-tight">Documentation</h1>
        <p className="mt-3 text-lg text-muted">
          Everything to install fya, scan your app, and wire it into CI. Only scan systems you own or are
          explicitly authorized to test.
        </p>

        <H2 id="install">Installation</H2>
        <p className={p}>fya needs Python 3.9 or newer. The core install pulls only requests and rich.</p>
        <CodeBlock code={"pip install fya\npip install \"fya[apk]\"       # Android APK manifest analysis\npip install \"fya[browser]\"   # headless-browser crawler for SPAs"} />
        <p className={p + " mt-4"}>From a clone, with the test tooling:</p>
        <CodeBlock code={"git clone https://github.com/ayam04/fya\ncd fya\npip install -e \".[dev]\""} />

        <H2 id="quickstart">Quickstart</H2>
        <p className={p}>Point fya at a local server or an APK. Localhost needs no authorization flag.</p>
        <CodeBlock code={"fya scan http://127.0.0.1:8000\nfya scan ./app-release.apk\n\nfya scan http://127.0.0.1:8000 -o report.html   # shareable report\nfya scan http://127.0.0.1:8000 --fail-on high    # exit non-zero in CI\nfya tools                                         # list detectable external tools"} />
        <p className={p + " mt-4"}>Try it against the bundled deliberately-vulnerable app in the repo:</p>
        <CodeBlock code={"python examples/vulnerable_app.py            # starts on http://127.0.0.1:5001\nfya scan http://127.0.0.1:5001 --mode full -o report.html"} />

        <H2 id="targets">Targets</H2>
        <p className={p}>
          fya detects the target automatically. A path ending in <Code>.apk</Code> (or any zip containing an
          AndroidManifest) is analyzed statically. Anything else is treated as a web target; a bare host defaults
          to <Code>http</Code> for localhost and private addresses and <Code>https</Code> otherwise.
        </p>

        <H2 id="modes">Scan modes</H2>
        <p className={p}>
          A mode selects which family of checks runs. Pick one with <Code>--mode</Code>, refine with
          <Code>--only</Code> and <Code>--skip</Code>, or choose from a menu with <Code>--interactive</Code>.
          List them with <Code>fya modes</Code>.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left text-muted">
                <th className="py-2 pr-6 font-medium">Mode</th>
                <th className="py-2 font-medium">What it runs</th>
              </tr>
            </thead>
            <tbody>
              {modes.map(([m, d]) => (
                <tr key={m} className="border-b border-line">
                  <td className="py-2.5 pr-6 align-top font-mono text-[13px] text-brand-ink">{m}</td>
                  <td className="py-2.5 text-ink/90">{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <H2 id="profiles">Profiles</H2>
        <p className={p}>
          A profile sets how hard fya probes, independent of the mode. Request pacing adapts automatically and
          slows down on errors, timeouts, and slow responses. fya never floods a target or runs denial-of-service
          payloads.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left text-muted">
                <th className="py-2 pr-6 font-medium">Profile</th>
                <th className="py-2 font-medium">Behavior</th>
              </tr>
            </thead>
            <tbody>
              {profiles.map(([m, d]) => (
                <tr key={m} className="border-b border-line">
                  <td className="py-2.5 pr-6 align-top font-mono text-[13px] text-brand-ink">{m}</td>
                  <td className="py-2.5 text-ink/90">{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <H2 id="auth">Authentication and scope</H2>
        <p className={p}>
          Scan behind a login by passing session credentials, and keep the scan inside a boundary with scope and
          budget controls.
        </p>
        <CodeBlock code={"# authenticated\nfya scan https://staging.example.com --i-am-authorized \\\n  -H \"Authorization: Bearer $TOKEN\"\nfya scan http://127.0.0.1:8000 --cookie \"session=abc123\"\n\n# scope and budget\nfya scan http://127.0.0.1:8000 --include '/app' --exclude '/logout'\nfya scan http://127.0.0.1:8000 --max-requests 500\n\n# render JS and single-page apps (needs the [browser] extra)\nfya scan http://127.0.0.1:8000 --spa"} />
        <p className={p + " mt-4"}>
          Any non-local target requires <Code>--i-am-authorized</Code>. <Code>--include</Code> and
          <Code>--exclude</Code> take path regexes, and <Code>--max-requests</Code> caps total HTTP requests.
        </p>

        <H2 id="baseline">Baseline and CI</H2>
        <p className={p}>
          Record the findings you have accepted, then fail the build only on new ones. This keeps
          <Code>--fail-on</Code> useful in a pipeline without drowning in known issues.
        </p>
        <CodeBlock code={"# record once\nfya scan http://127.0.0.1:8000 --write-baseline .fya-baseline.json\n\n# in CI: suppress the baseline, fail only on new high findings\nfya scan http://127.0.0.1:8000 --baseline .fya-baseline.json --fail-on high"} />

        <H2 id="reports">Reports</H2>
        <p className={p}>
          Format is inferred from the <Code>-o</Code> extension, or set it with <Code>--format</Code>. Use
          <Code>--fail-on {"{low,medium,high,critical}"}</Code> to return a non-zero exit code.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left text-muted">
                <th className="py-2 pr-6 font-medium">Format</th>
                <th className="py-2 font-medium">Use it for</th>
              </tr>
            </thead>
            <tbody>
              {reports.map(([m, d]) => (
                <tr key={m} className="border-b border-line">
                  <td className="py-2.5 pr-6 align-top font-mono text-[13px] text-brand-ink">{m}</td>
                  <td className="py-2.5 text-ink/90">{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <H2 id="checks">Checks catalog</H2>
        <p className={p}>
          36 checks across eight areas, each mapped to the OWASP Top 10 or MASVS and a CWE. Every check runs only
          at or above its minimum profile.
        </p>
        <div className="space-y-4">
          {checks.map(([area, prof, names]) => (
            <div key={area as string} className="rounded-xl border border-line p-5">
              <div className="mb-3 flex items-baseline justify-between gap-3">
                <h3 className="text-base font-semibold">{area}</h3>
                <span className="font-mono text-xs text-muted">min profile: {prof}</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {(names as string[]).map((n) => (
                  <span key={n} className="rounded-md border border-line bg-code px-2 py-1 font-mono text-[12px] text-ink/80">
                    {n}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>

        <H2 id="tools">External tools</H2>
        <p className={p}>
          If any of these are on your <Code>PATH</Code>, fya runs them and folds their results into one
          normalized report. If not, it falls back to built-in checks. Check what is detected with
          <Code>fya tools</Code>.
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
          fya performs active security testing. Only scan systems you own or are explicitly authorized in writing
          to test. Scanning a target that is not local requires <Code>--i-am-authorized</Code>. Scans are
          non-destructive by default, with no flooding and no denial-of-service payloads. You are responsible for
          how you use this tool.
        </p>
      </article>
    </div>
  )
}
