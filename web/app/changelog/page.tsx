import type { Metadata } from "next"
import Link from "next/link"

export const metadata: Metadata = {
  title: "Changelog",
  description:
    "Every release of fya, the open-source security scanner: new checks, false-positive fixes, and CLI changes.",
}

type Group = { kind: "Added" | "Changed" | "Fixed"; items: string[] }
type Release = { version: string; date: string; headline: string; groups: Group[] }

// Mirrors CHANGELOG.md in the repository root, which stays the canonical record for the package.
const releases: Release[] = [
  {
    version: "0.6.0",
    date: "2026-08-18",
    headline: "33 new checks, a false-positive gate over every one of them, and per-check selection.",
    groups: [
      {
        kind: "Added",
        items: [
          "33 new checks, taking the catalog from 58 to 91. Every one ships with a positive test and a negative test that proves it stays silent on a hardened app.",
          "Advanced injection: OS command injection confirmed by an arithmetic oracle rather than reflection, XXE via two-stage entity expansion, boolean-blind SQLi confirmed across two SQL syntaxes, PHP stream wrappers, and JSON NoSQL operator injection.",
          "Exposure: Spring Boot actuator endpoints including heap dumps, phpinfo and server-status and Werkzeug console pages, backup and editor copies of live source files, OIDC discovery misconfiguration, and exposed SOAP and WSDL endpoints.",
          "Crypto and tokens: JWT signed with a guessable secret (tested offline, costing the target no requests), jku, x5u and kid header injection, certificate key size and signature algorithm and validity window, mixed content, and serialized Java, PHP and ASP.NET ViewState blobs.",
          "Infrastructure as code and supply chain: Dockerfile and Compose hardening, Kubernetes workload security, Terraform exposure, insecure package sources, and pwn-request and script injection in GitHub Actions workflows.",
          "Source analysis: committed key material, weak crypto usage, SQL built by string concatenation, and disabled certificate verification.",
          "Android: network security config, exported content providers, backup rules, deep-link hijacking surface, v1-only signing and debug certificates, weak crypto constants, insecure TLS code, and build hardening.",
          "fya checks lists the full catalog, with --only to filter by category and --json for machine output.",
          "--only and --skip now accept an individual check id as well as a category, so --only web.ssrf and --skip web.backup_files both work.",
          "A binary AndroidManifest.xml decoder, so the new manifest checks run without androguard installed.",
        ],
      },
      {
        kind: "Changed",
        items: [
          "run_scan() accepts an exclude set, and its categories argument now matches either a category or a single check id.",
          "CI gates on mypy in addition to ruff and the test suite.",
        ],
      },
      {
        kind: "Fixed",
        items: [
          "web.json_nosql_operators treated any sub-500 status change as evidence of injection, so an API that correctly rejected the operator object (a FastAPI or Pydantic 422, a DRF 400) was reported as vulnerable. It now requires the response to move toward success, and reports a body-only differential at low confidence.",
          "web.json_nosql_operators picked its probe field from an unordered set, so whether the check fired at all varied with the interpreter hash seed.",
          "The false-positive control test covered only 8 checks; it now covers 23, including every new dynamic check.",
          "New checks' tests ran the whole battery per test, which made results depend on concurrent load and the suite intermittently red. Each test now scopes its scan to the checks it exercises.",
          "base_url() and Target.host could be None and were passed on unguarded in the passive, SSRF and crawling checks.",
          "The scanner is now clean under mypy across all 45 modules.",
        ],
      },
    ],
  },
  {
    version: "0.5.1",
    date: "2026-07-03",
    headline: "Commercial-license notice in the CLI.",
    groups: [{ kind: "Added", items: ["A commercial-license notice in the CLI banner, and COMMERCIAL-LICENSE.md."] }],
  },
  {
    version: "0.5.0",
    date: "2026-07-03",
    headline: "16 new attack techniques and an audit pass over the check implementations.",
    groups: [
      { kind: "Added", items: ["16 new attack techniques across the web, API, header and mobile areas."] },
      {
        kind: "Changed",
        items: [
          "Dual-licensed under PolyForm Noncommercial 1.0.0; commercial use requires a paid license.",
          "The website adapts to phones, with a hamburger section menu for the docs.",
        ],
      },
      { kind: "Fixed", items: ["15 bugs found in an audit of the check implementations."] },
    ],
  },
  {
    version: "0.4.0",
    date: "2026-07-02",
    headline: "Black, gray and white box as switchable modes, plus the Claude skill.",
    groups: [
      {
        kind: "Added",
        items: [
          "Black box, gray box and white box test strategies as switchable modes.",
          "A bundled Claude skill that performs the same methodology in a session with no package installed.",
          "A Next.js overview and documentation site.",
        ],
      },
      { kind: "Changed", items: ["The package version is single-sourced from fya/__init__.py."] },
    ],
  },
  {
    version: "0.3.0",
    date: "2026-07-01",
    headline: "Authenticated scanning, scope controls, and baseline suppression.",
    groups: [
      {
        kind: "Added",
        items: [
          "Authenticated scanning with --header, --cookie and --bearer.",
          "Scope controls to keep scans bounded: --include, --exclude and --max-requests.",
          "Baseline suppression: record known findings with --write-baseline, hide them later with --baseline.",
          "New checks: JWT weaknesses, Content-Security-Policy analysis, outdated JavaScript libraries, and security.txt and robots.txt discovery.",
          "An optional Playwright-based SPA crawler, and entry-point plugin support under the fya.checks group.",
        ],
      },
      {
        kind: "Fixed",
        items: ["Audit-driven false-positive fixes across reflected XSS, SSTI, CSRF, CORS and verbose-error detection."],
      },
    ],
  },
  {
    version: "0.2.0",
    date: "2026-07-01",
    headline: "Scan profiles, live progress, and machine-readable reports.",
    groups: [
      {
        kind: "Added",
        items: [
          "Scan profiles (passive, safe, aggressive) with per-check profile gating.",
          "Live progress reporting during a scan.",
          "JSON and Markdown report writers.",
        ],
      },
      { kind: "Changed", items: ["The check registry auto-discovers bundled checks."] },
    ],
  },
  {
    version: "0.1.0",
    date: "2026-07-01",
    headline: "First release.",
    groups: [
      {
        kind: "Added",
        items: [
          "Dynamic security scanner for localhost web servers and Android APKs.",
          "Passive web checks: security headers, server version disclosure, and insecure cookie flags.",
          "Command-line interface with target parsing for web and APK kinds.",
        ],
      },
    ],
  },
]

// Group labels read like a diff: added is a pass, fixed is a caution, changed is info.
const kindStyle: Record<Group["kind"], string> = {
  Added: "text-ok border-ok/30 bg-ok/10",
  Changed: "text-info border-info/30 bg-info/10",
  Fixed: "text-med border-med/30 bg-med/10",
}
const kindGlyph: Record<Group["kind"], string> = { Added: "+", Changed: "~", Fixed: "!" }

function fmt(date: string) {
  return new Date(date + "T00:00:00Z").toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  })
}

export default function Changelog() {
  return (
    <div className="mx-auto grid max-w-6xl grid-cols-1 gap-12 px-4 pb-24 pt-24 sm:px-6 lg:grid-cols-[200px_1fr]">
      <aside className="hidden lg:block">
        <nav className="sticky top-24 text-sm" aria-label="Releases">
          <div className="mono mb-3 text-[11px] font-medium uppercase tracking-[0.16em] text-faint">Releases</div>
          <div className="space-y-0.5">
            {releases.map((r, i) => (
              <a
                key={r.version}
                href={`#v${r.version}`}
                className="mono flex items-baseline justify-between rounded px-2 py-1.5 text-[13px] text-muted transition-colors hover:bg-white/[0.04] hover:text-ink"
              >
                <span>{r.version}</span>
                {i === 0 && <span className="text-[10px] uppercase tracking-wider text-crit">latest</span>}
              </a>
            ))}
          </div>
        </nav>
      </aside>

      <div className="min-w-0 max-w-3xl">
        <div className="mono flex items-center gap-4 text-[11px] tracking-[0.12em] text-faint">
          <span className="text-muted">FYA(1)</span>
          <span className="h-px flex-1 bg-line" />
          <span className="hidden uppercase sm:inline">Release History</span>
          <span className="hidden h-px flex-1 bg-line sm:block" />
          <span className="text-muted">FYA(1)</span>
        </div>

        <h1 className="mono mt-8 text-3xl font-bold tracking-tight">Changelog</h1>
        <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-muted">
          Every release of fya. New checks land with the tests that prove they fire on a broken app and stay quiet on a
          hardened one, so the entries below list the false-positive fixes as prominently as the features.
        </p>
        <div className="mono mt-5 flex flex-wrap gap-3 text-[13px]">
          <Link href="/docs#checks" className="text-crit hover:text-high">
            check catalog →
          </Link>
          <span className="text-line-strong">·</span>
          <a href="https://github.com/ayam04/fya/releases" className="text-muted transition-colors hover:text-ink">
            releases on github
          </a>
          <span className="text-line-strong">·</span>
          <a href="https://pypi.org/project/fya/" className="text-muted transition-colors hover:text-ink">
            pypi
          </a>
        </div>

        <div className="mt-14 space-y-16">
          {releases.map((r, i) => (
            <section key={r.version} id={`v${r.version}`} className="scroll-mt-24">
              <div className="flex flex-wrap items-baseline gap-3">
                <h2 className="mono text-2xl font-bold">
                  <span className="text-crit">v</span>
                  {r.version}
                </h2>
                {i === 0 && (
                  <span className="mono border border-crit/40 bg-crit/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.14em] text-crit">
                    latest
                  </span>
                )}
                <time dateTime={r.date} className="mono text-[13px] text-faint">
                  {fmt(r.date)}
                </time>
              </div>
              <p className="mt-2 max-w-2xl text-[15px] leading-relaxed text-ink/80">{r.headline}</p>
              <div className="rule mt-5" />

              <div className="mt-6 space-y-7">
                {r.groups.map((g) => (
                  <div key={g.kind}>
                    <span
                      className={
                        "mono inline-flex items-center gap-1.5 border px-2 py-0.5 text-[11px] font-medium uppercase tracking-[0.12em] " +
                        kindStyle[g.kind]
                      }
                    >
                      <span aria-hidden>{kindGlyph[g.kind]}</span>
                      {g.kind}
                    </span>
                    <ul className="mt-3 space-y-2.5">
                      {g.items.map((item) => (
                        <li key={item} className="flex gap-3 text-[14.5px] leading-relaxed text-muted">
                          <span aria-hidden className="mono mt-0.5 shrink-0 text-faint">
                            {kindGlyph[g.kind]}
                          </span>
                          <span className="max-w-2xl">{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </section>
          ))}
        </div>
      </div>
    </div>
  )
}
