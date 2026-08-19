import Link from "next/link"
import { CodeBlock } from "@/components/CodeBlock"
import { Callout } from "@/components/Callout"
import { DocsMobileNav } from "@/components/DocsMobileNav"

export const metadata = {
  title: "Docs — usage and reference",
  description:
    "Install fya, scan a web server or an APK, run it as a Claude skill, pick a mode and profile, run authenticated and scoped scans, gate CI with a baseline, and read the full 91-check catalog.",
}

const VERSION = "0.6.0"

const nav = [
  ["install", "Installation"],
  ["quickstart", "Quickstart"],
  ["skill", "Claude skill"],
  ["targets", "Targets"],
  ["modes", "Scan modes"],
  ["profiles", "Profiles"],
  ["auth", "Authentication & scope"],
  ["baseline", "Baseline & CI"],
  ["reports", "Reports"],
  ["checks", "Checks catalog"],
  ["tools", "External tools"],
  ["docker", "Docker"],
  ["responsible", "Responsible use"],
  ["license", "Licensing"],
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

const checks: [string, string, string[]][] = [
  ["web passive", "passive", ["web.security_headers", "web.version_disclosure", "web.insecure_cookies"]],
  ["web active", "safe", ["web.reflected_xss", "web.sql_injection", "web.open_redirect", "web.path_traversal", "web.cors_misconfig", "web.cors_advanced", "web.dangerous_methods", "web.sensitive_files"]],
  ["web advanced", "safe / aggressive", ["web.ssti", "web.csrf", "web.host_header", "web.crlf", "web.cache_poison_headers", "web.url_override_headers"]],
  ["web advanced injection", "safe / aggressive", ["web.command_injection", "web.xxe_injection", "web.blind_sql_injection", "web.lfi_wrappers", "web.json_nosql_operators"]],
  ["web ssrf & injection", "safe", ["web.ssrf", "web.nosql_injection", "web.xpath_ldap_ssi_injection"]],
  ["web secrets & files", "safe", ["web.js_secrets", "web.source_map_exposure", "web.vcs_exposure", "web.exposed_config_secrets", "web.directory_listing"]],
  ["web exposure & debug", "safe / aggressive", ["web.debug_info_pages", "web.backup_files"]],
  ["web crypto & tokens", "safe", ["web.jwt_weak_secret", "web.jwt_header_injection", "web.mixed_content", "web.serialized_objects"]],
  ["web hardening", "passive", ["web.csp_weaknesses", "web.jwt_weak_algorithm", "web.jwt_missing_expiry", "web.jwt_sensitive_claims", "web.frontend_libraries", "web.modern_headers", "web.cookie_scope", "web.security_txt", "web.robots_sensitive_paths"]],
  ["black box", "safe", ["blackbox.input_fuzzing"]],
  ["gray box", "safe", ["graybox.idor", "graybox.auth_bypass"]],
  ["white box (source)", "passive / safe", ["whitebox.hardcoded_secrets", "whitebox.dangerous_patterns", "whitebox.cicd_misconfig", "whitebox.static_analysis", "whitebox.committed_key_material", "whitebox.weak_crypto_usage", "whitebox.sql_string_building", "whitebox.auth_verification_disabled"]],
  ["white box (iac & supply chain)", "passive", ["whitebox.dockerfile_hardening", "whitebox.compose_hardening", "whitebox.k8s_workload_security", "whitebox.terraform_exposure", "whitebox.insecure_package_source", "whitebox.actions_supply_chain"]],
  ["tls", "passive", ["tls.certificate", "tls.weak_protocol", "tls.https_upgrade", "tls.certificate_strength"]],
  ["api", "safe", ["api.docs_exposure", "api.graphql_introspection", "api.graphql_hardening", "api.verbose_errors", "api.admin_endpoints", "api.actuator_exposure", "api.oidc_misconfig", "api.soap_wsdl_exposure"]],
  ["apk static", "passive", ["apk.hardcoded_secrets", "apk.cleartext_urls", "apk.manifest", "apk.webview_config"]],
  ["apk manifest & config", "passive", ["apk.network_security_config", "apk.provider_exposure", "apk.backup_rules", "apk.deeplink_surface", "apk.signing_scheme"]],
  ["apk code & build", "passive", ["apk.weak_crypto", "apk.insecure_tls_code", "apk.build_hardening"]],
  ["integrations", "aggressive", ["integrations.nuclei", "integrations.nikto", "integrations.nmap", "integrations.sqlmap", "integrations.tls"]],
]

function Code({ children }: { children: React.ReactNode }) {
  return <code className="mono rounded bg-white/[0.06] px-1 py-0.5 text-[13px] text-ink">{children}</code>
}

function H2({ id, n, children }: { id: string; n: string; children: string }) {
  return (
    <div className="mt-16 scroll-mt-24 lg:scroll-mt-20">
      <div className="mono flex items-baseline gap-3 text-[12px] text-faint">
        <span className="text-crit">{n}</span>
        <span className="h-px flex-1 bg-line" />
      </div>
      <h2 id={id} className="mono mt-3 scroll-mt-24 text-[15px] font-semibold uppercase tracking-[0.16em] text-ink lg:scroll-mt-20">
        {children}
      </h2>
    </div>
  )
}

const p = "mb-4 text-[15px] leading-relaxed text-muted"
const th = "mono py-2 pr-6 text-left text-[12px] font-medium uppercase tracking-wider text-faint"
const td = "py-2.5 align-top text-[14px] text-muted"
const monoCell = "mono py-2.5 pr-6 align-top text-[13px] text-info"

export default function Docs() {
  return (
    <div className="mx-auto grid max-w-6xl grid-cols-1 gap-12 px-4 pb-16 pt-24 sm:px-6 lg:grid-cols-[220px_1fr]">
      <aside className="hidden lg:block">
        <nav className="sticky top-24 text-sm">
          <div className="mono mb-3 text-[11px] font-medium uppercase tracking-[0.16em] text-faint">Contents</div>
          <div className="space-y-0.5">
            {nav.map(([id, label], i) => (
              <a
                key={id}
                href={`#${id}`}
                className="mono flex items-baseline gap-2.5 rounded px-2 py-1.5 text-[13px] text-muted transition-colors hover:bg-white/[0.04] hover:text-ink"
              >
                <span className="text-faint">{String(i + 1).padStart(2, "0")}</span>
                {label}
              </a>
            ))}
          </div>
        </nav>
      </aside>

      <article className="min-w-0 max-w-3xl">
        <DocsMobileNav items={nav} />

        <div className="mono flex items-center gap-4 text-[11px] tracking-[0.12em] text-faint">
          <span className="text-muted">FYA(1)</span>
          <span className="h-px flex-1 bg-line" />
          <span className="hidden uppercase sm:inline">User Manual</span>
          <span className="hidden h-px flex-1 bg-line sm:block" />
          <span className="text-muted">FYA(1)</span>
        </div>

        <div className="mt-8 flex flex-wrap items-center gap-3">
          <h1 className="mono text-3xl font-bold tracking-tight">Documentation</h1>
          <Link
            href="/changelog"
            className="mono border border-crit/40 bg-crit/10 px-2 py-0.5 text-[12px] font-medium text-crit"
          >
            v{VERSION}
          </Link>
        </div>
        <p className="mt-3 text-[15px] text-muted">Everything to install fya, scan your app, and wire it into CI.</p>
        <div className="mt-6">
          <Callout tone="warn">
            fya performs active security testing. Only scan systems you own or are explicitly authorized in writing to
            test. Any non-local target requires <Code>--i-am-authorized</Code>.
          </Callout>
        </div>

        <H2 id="install" n="01">Installation</H2>
        <p className={p}>fya needs Python 3.9 or newer. The core install pulls only requests and rich.</p>
        <CodeBlock code={"pip install fya\npip install \"fya[apk]\"       # Android APK manifest analysis\npip install \"fya[browser]\"   # headless-browser crawler for SPAs"} />
        <p className={p + " mt-4"}>From a clone, with the test tooling:</p>
        <CodeBlock code={"git clone https://github.com/ayam04/fya\ncd fya\npip install -e \".[dev]\""} />

        <H2 id="quickstart" n="02">Quickstart</H2>
        <p className={p}>Point fya at a local server or an APK. Localhost needs no authorization flag.</p>
        <CodeBlock code={"fya scan http://127.0.0.1:8000\nfya scan ./app-release.apk\n\nfya scan http://127.0.0.1:8000 -o report.html   # shareable report\nfya scan http://127.0.0.1:8000 --fail-on high    # exit non-zero in CI\nfya tools                                         # list detectable external tools"} />
        <p className={p + " mt-4"}>
          New in v{VERSION}: 33 more checks (91 total) and per-check selection. See the{" "}
          <Link href="/changelog" className="text-crit hover:text-high">
            changelog
          </Link>{" "}
          for the full history.
        </p>
        <p className={p + " mt-4"}>Try it against the bundled deliberately-vulnerable app in the repo:</p>
        <CodeBlock code={"python examples/vulnerable_app.py            # starts on http://127.0.0.1:5001\nfya scan http://127.0.0.1:5001 --mode full -o report.html"} />

        <H2 id="skill" n="03">The Claude skill</H2>
        <p className={p}>
          Prefer to stay in Claude? fya ships as a skill that makes Claude run the same non-destructive scan itself,
          with no package to install. It confirms you own the target, runs the checks, and reports in the chat.
        </p>
        <p className={p}>Install it by copying one folder into your Claude skills directory:</p>
        <CodeBlock code={"git clone https://github.com/ayam04/fya\ncp -r fya/skills/fya ~/.claude/skills/fya"} />
        <p className={p + " mt-4"}>
          On Windows the destination is <Code>%USERPROFILE%\.claude\skills\fya</Code>. Then just ask Claude:
        </p>
        <CodeBlock label="claude" code={"scan http://localhost:3000 for vulnerabilities\ncheck ./app-release.apk for security issues"} />
        <p className={p + " mt-4"}>
          Claude confirms the target and authorization, picks a mode and profile, runs the OWASP-mapped checks, and
          applies the same false-positive discipline as the CLI. It is fully agentic: it drives the probes with its own
          tools, so it works even where the package is not installed.
        </p>

        <H2 id="targets" n="04">Targets</H2>
        <p className={p}>
          fya detects the target automatically. A path ending in <Code>.apk</Code> (or any zip containing an
          AndroidManifest) is analyzed statically. A local directory is treated as source and analyzed white-box.
          Anything else is a web target; a bare host defaults to <Code>http</Code> for localhost and private addresses
          and <Code>https</Code> otherwise.
        </p>
        <CodeBlock code={"fya scan http://127.0.0.1:8000    # web target\nfya scan ./app-release.apk        # android package\nfya scan ./my-service             # source directory, white-box"} />

        <H2 id="modes" n="05">Scan modes</H2>
        <p className={p}>
          A mode selects which family of checks runs. Pick one with <Code>--mode</Code>, refine with <Code>--only</Code>{" "}
          and <Code>--skip</Code> (each accepts a category or a single check id), or choose from a menu with{" "}
          <Code>--interactive</Code>. List them with <Code>fya modes</Code>.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-line">
                <th className={th}>Mode</th>
                <th className={th + " pr-0"}>What it runs</th>
              </tr>
            </thead>
            <tbody>
              {modes.map(([m, d]) => (
                <tr key={m} className="border-b border-line">
                  <td className={monoCell}>{m}</td>
                  <td className={td}>{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-4">
          <Callout tone="warn">
            Load, stress, and network-chaos testing are deliberately out of scope. They are denial-of-service shaped and
            break the non-destructive guarantee. Use k6, Locust, or Toxiproxy for those, on infrastructure you own.
          </Callout>
        </div>

        <H2 id="profiles" n="06">Profiles</H2>
        <p className={p}>
          A profile sets how hard fya probes, independent of the mode. Request pacing adapts automatically and slows
          down on errors, timeouts, and slow responses. fya never floods a target or runs denial-of-service payloads.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-line">
                <th className={th}>Profile</th>
                <th className={th + " pr-0"}>Behavior</th>
              </tr>
            </thead>
            <tbody>
              {profiles.map(([m, d]) => (
                <tr key={m} className="border-b border-line">
                  <td className={monoCell}>{m}</td>
                  <td className={td}>{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <H2 id="auth" n="07">Authentication &amp; scope</H2>
        <p className={p}>Scan behind a login, and keep the scan inside a boundary with scope and budget controls.</p>
        <CodeBlock code={"# authenticated\nfya scan https://staging.example.com --i-am-authorized \\\n  -H \"Authorization: Bearer $TOKEN\"\nfya scan http://127.0.0.1:8000 --cookie \"session=abc123\"\n\n# scope and budget\nfya scan http://127.0.0.1:8000 --include '/app' --exclude '/logout'\nfya scan http://127.0.0.1:8000 --max-requests 500\n\n# render JS and single-page apps (needs the [browser] extra)\nfya scan http://127.0.0.1:8000 --spa"} />

        <H2 id="baseline" n="08">Baseline &amp; CI</H2>
        <p className={p}>Record the findings you have accepted, then fail the build only on new ones.</p>
        <CodeBlock code={"fya scan http://127.0.0.1:8000 --write-baseline .fya-baseline.json\nfya scan http://127.0.0.1:8000 --baseline .fya-baseline.json --fail-on high"} />

        <H2 id="reports" n="09">Reports</H2>
        <p className={p}>
          Format is inferred from the <Code>-o</Code> extension, or set it with <Code>--format</Code>. Use{" "}
          <Code>--fail-on</Code> to return a non-zero exit code.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-line">
                <th className={th}>Format</th>
                <th className={th + " pr-0"}>Use it for</th>
              </tr>
            </thead>
            <tbody>
              {reports.map(([m, d]) => (
                <tr key={m} className="border-b border-line">
                  <td className={monoCell}>{m}</td>
                  <td className={td}>{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <H2 id="checks" n="10">Checks catalog</H2>
        <p className={p}>
          91 checks across 19 areas, each mapped to the OWASP Top 10 or MASVS and a CWE. Every check runs only at or
          above its minimum profile.
        </p>
        <div className="mt-6 divide-y divide-line border-y border-line">
          {checks.map(([area, prof, names]) => (
            <div key={area} className="py-5">
              <div className="mb-3 flex items-baseline justify-between gap-3">
                <h3 className="mono text-[14px] font-semibold text-ink">{area}</h3>
                <span className="mono text-[11px] text-faint">min: {prof}</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {names.map((n) => (
                  <span key={n} className="mono border border-line bg-panel px-2 py-1 text-[12px] text-muted">
                    {n}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>

        <H2 id="tools" n="11">External tools</H2>
        <p className={p}>
          If any of these are on your <Code>PATH</Code>, fya runs them and folds their results into one normalized
          report. If not, it falls back to built-in checks. Check what is detected with <Code>fya tools</Code>.
        </p>
        <div className="flex flex-wrap gap-1.5">
          {["nuclei", "nikto", "sqlmap", "nmap", "testssl.sh", "sslyze", "jadx", "apkleaks"].map((t) => (
            <span key={t} className="mono border border-line bg-panel px-2 py-1 text-[13px] text-info">
              {t}
            </span>
          ))}
        </div>

        <H2 id="docker" n="12">Docker</H2>
        <p className={p}>The image bundles nmap, so external-tool handoff works out of the box.</p>
        <CodeBlock code={"docker build -t fya .\ndocker run --rm --network host fya scan http://127.0.0.1:8000"} />

        <H2 id="responsible" n="13">Responsible use</H2>
        <p className={p}>
          fya performs active security testing. Only scan systems you own or are explicitly authorized in writing to
          test. Scanning a non-local target requires <Code>--i-am-authorized</Code>. Scans are non-destructive by
          default, with no flooding and no denial-of-service payloads. You are responsible for how you use this tool.
        </p>

        <H2 id="license" n="14">Licensing</H2>
        <p className={p}>
          fya is dual-licensed. It is <b className="text-ink">free for noncommercial and personal use</b> under the{" "}
          <a href="https://polyformproject.org/licenses/noncommercial/1.0.0" className="text-crit hover:text-high">
            PolyForm Noncommercial License 1.0.0
          </a>
          , which covers hobby projects, research, education, personal study, and nonprofit or government use.
        </p>
        <p className={p}>
          <b className="text-ink">Commercial use requires a paid license</b> — using fya in, or for, a for-profit
          company&apos;s products, services, or internal operations. To obtain one, contact{" "}
          <Code>ayamullahkhan04@gmail.com</Code>. Versions before 0.5.0 were released under the MIT License and remain
          available under those terms.
        </p>
      </article>
    </div>
  )
}
