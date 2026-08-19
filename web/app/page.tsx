import Link from "next/link"
import { CodeBlock } from "@/components/CodeBlock"
import { Callout } from "@/components/Callout"

/*
  DIRECTION — "the tool's own output."
  THESIS: fya proves vulns with the exact request and the receipt, so the page
    proves itself the same way — rendered as fya's scan report / Unix man page,
    refusing the near-black + neon-glow + Space-Grotesk hero the category ships.
  OWN-WORLD: mono report grammar; a functional severity palette (crit/med/low/
    ok/info) instead of one accent; flat hairlines; man-page masthead; bracketed
    terminal actions. No glow, no blur orbs, no bento cards, no pill CTAs.
  FIRST VIEWPORT: masthead → NAME → SYNOPSIS command with caret → primary action
    → a live finding report (summary, tally, findings, one expanded with proof).
  FORM: scan-report / man-page document, built inline, fully committed.
*/

// A real-shaped report from the bundled vulnerable app the docs reference.
// Illustrative finding data — labeled as the demo scan it is, not a customer claim.
const findings = [
  {
    sev: "HIGH",
    id: "web.sql_injection",
    title: "Error-based SQL injection in the product lookup",
    req: "GET /product?id=1%27+OR+%271%27%3D%271",
    proof: "row count 1 → 42, SQL error surfaced in the 200 body — boolean + error oracle agree",
    map: "CWE-89 · OWASP A03 Injection",
    fix: "Use parameterized queries. Never build SQL by string concatenation.",
  },
  { sev: "HIGH", id: "web.reflected_xss", title: "Search term reflected unescaped into HTML", map: "CWE-79 · A03" },
  { sev: "HIGH", id: "web.ssrf", title: "URL fetcher reaches the cloud metadata endpoint", map: "CWE-918 · A10" },
  { sev: "HIGH", id: "web.vcs_exposure", title: "Dumpable .git directory serves the full source", map: "CWE-527 · A05" },
  { sev: "MED", id: "web.cors_advanced", title: "Reflected Origin with credentials via suffix match", map: "CWE-942 · A05" },
]

const sevText: Record<string, string> = { HIGH: "text-crit", MED: "text-med", LOW: "text-low" }
const sevBox: Record<string, string> = {
  HIGH: "border-crit/40 bg-crit/10 text-crit",
  MED: "border-med/40 bg-med/10 text-med",
  LOW: "border-low/40 bg-low/10 text-low",
}

const capabilities = [
  {
    term: "one tool, three targets",
    body: "A running web server, an Android .apk, or a source directory — the same command. It detects which and runs only what fits.",
  },
  {
    term: "it actually breaks things",
    body: "Command injection, XXE, blind SQLi, SSTI, IDOR, a leaking .env, a heap dump on an open actuator, a debuggable APK. If it is there, you get the receipt that proves it.",
  },
  {
    term: "black, gray, and white box",
    body: "Fuzz inputs from outside, probe access control with partial knowledge, or scan the source and the infrastructure that ships it. Every finding maps to OWASP and a CWE.",
  },
  {
    term: "it does not cry wolf",
    body: "Every check is proven against a baseline and pinned by a test that keeps it silent on a hardened app. A confident wrong finding is worse than a missed one.",
  },
  {
    term: "built for real apps",
    body: "Authenticated scans, scoped crawls, request budgets, a CI baseline, per-check selection, and a headless browser for single-page apps.",
  },
  {
    term: "free for noncommercial use",
    body: "Free for personal, hobby, research, and nonprofit use under PolyForm Noncommercial. Commercial use needs a license. No dashboard, no agent, no account.",
  },
]

// times sum to 3.2s — the same run the hero report shows finishing.
const pipeline: [string, string, string][] = [
  ["detect", "Web server, .apk, or source directory. It decides; you do not configure it.", "0.1s"],
  ["fingerprint", "Reads the stack, framework, cookies, and whether it is a JSON API from the first responses.", "0.3s"],
  ["plan", "Picks only the checks that fit the target and the profile.", "0.1s"],
  ["break", "Runs non-destructive probes and paces to what the target tolerates. No flooding, ever.", "2.4s"],
  ["prove", "De-duplicates, maps each finding to OWASP and CWE, and keeps the receipts.", "0.2s"],
  ["report", "Console, JSON, SARIF, Markdown, or a self-contained HTML page.", "0.1s"],
]

const areas = [
  ["web.active", "Reflected XSS, error-based SQLi, open redirect, path traversal, CORS reflection, and advanced CORS bypasses."],
  ["web.injection", "OS command injection proven by an arithmetic oracle, XXE, boolean-blind SQLi, PHP stream wrappers, JSON NoSQL operators."],
  ["web.ssrf", "Signature-based SSRF (cloud metadata and file://), server-side template injection, and XPath, LDAP, and SSI injection."],
  ["web.exposure", "Spring Boot actuators and heap dumps, phpinfo and server-status, the Werkzeug console, and editor or backup copies of live source."],
  ["web.crypto", "JWT signed with a guessable secret, jku and x5u header injection, cert key size and algorithm, mixed content, serialized blobs."],
  ["web.secrets", "Secrets in client JavaScript, exposed source maps, dumpable .git and .svn repos, leaked config files, and directory listing."],
  ["web.hardening", "Security headers, cookie flags and prefix misuse, CSP holes, COOP, CORP and Permissions-Policy, outdated JS libraries."],
  ["blackbox / graybox", "Input fuzzing that surfaces crashes and stack traces, insecure direct object references, and routes reachable without auth."],
  ["whitebox.source", "Hardcoded secrets, committed key material, SQL built by string concat, weak crypto, and disabled certificate verification."],
  ["whitebox.iac", "Dockerfile and Compose hardening, Kubernetes workload security, Terraform exposure, and pwn-request in GitHub Actions."],
  ["api", "OpenAPI and Swagger exposure, GraphQL introspection and field suggestions, OIDC discovery, and exposed SOAP and WSDL."],
  ["apk", "Network security config and pinning gaps, exported providers, deep-link hijacking, v1 signing, debug certs, weak crypto."],
  ["tls / tools", "Certificate trust and expiry, weak protocols, and Nuclei, Nikto, nmap, sqlmap, and testssl folded into one report."],
]

const btnGhost =
  "mono inline-flex items-center gap-2 rounded-[3px] border border-line bg-panel px-4 py-2 text-[13px] text-ink transition-colors hover:border-line-strong hover:bg-panel2"

function PrimaryCta({ href, children }: { href: string; children: string }) {
  return (
    <Link
      href={href}
      className="mono group inline-flex items-center gap-2 rounded-[3px] bg-ink px-4 py-2 text-[13px] font-semibold text-bg transition hover:bg-white"
    >
      {children}
      <span className="transition-transform duration-200 group-hover:translate-x-1">→</span>
    </Link>
  )
}

function GithubCta() {
  return (
    <a href="https://github.com/ayam04/fya" className={btnGhost}>
      <span className="text-faint">$</span> github
    </a>
  )
}

function Masthead({ left, center, right }: { left: string; center: string; right: string }) {
  return (
    <div className="mono flex items-center gap-4 text-[11px] tracking-[0.12em] text-faint">
      <span className="text-muted">{left}</span>
      <span className="h-px flex-1 bg-line" />
      <span className="hidden uppercase sm:inline">{center}</span>
      <span className="hidden h-px flex-1 bg-line sm:block" />
      <span className="text-muted">{right}</span>
    </div>
  )
}

function SectionHead({ n, id, title, note }: { n: string; id: string; title: string; note?: string }) {
  return (
    <div id={id} className="scroll-mt-24">
      <div className="mono flex items-baseline gap-3 text-[12px] text-faint">
        <span className="text-crit">{n}</span>
        <span className="h-px flex-1 bg-line" />
        {note && <span className="hidden sm:inline">{note}</span>}
      </div>
      <h2 className="mono mt-3 text-[13px] font-semibold uppercase tracking-[0.2em] text-muted">{title}</h2>
    </div>
  )
}

export default function Home() {
  return (
    <div className="mx-auto max-w-6xl px-4 sm:px-6">
      {/* ── hero: NAME / SYNOPSIS / live report ─────────────────────────── */}
      <section className="pt-24 sm:pt-28">
        <Masthead left="FYA(1)" center="Security Scanner Manual" right="FYA(1)" />

        <div className="mt-10 grid grid-cols-1 gap-12 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.05fr)] lg:gap-10">
          {/* left: the manual entry */}
          <div className="min-w-0 max-w-xl">
            <div className="mono text-[12px] uppercase tracking-[0.2em] text-faint">Name</div>
            <h1 className="mono reveal mt-3 text-[26px] font-bold leading-[1.15] tracking-tight text-ink sm:text-[34px]">
              fya — point it at your app,
              <br />
              <span className="text-crit">it tries to break it.</span>
            </h1>

            <div className="mono mt-8 text-[12px] uppercase tracking-[0.2em] text-faint">Synopsis</div>
            <div className="mono mt-3 flex items-center overflow-x-auto whitespace-nowrap border border-line bg-panel px-3.5 py-3 text-[13px] leading-relaxed">
              <span className="text-ok">$&nbsp;</span>
              <span className="font-semibold text-crit">fya&nbsp;</span>
              <span className="text-ink">scan&nbsp;</span>
              <span className="text-info">&lt;target&gt;</span>
              <span className="hidden text-muted sm:inline">&nbsp;[--mode auto] [--profile safe]</span>
              <span className="caret ml-1 shrink-0" aria-hidden />
            </div>

            <p className="mt-6 max-w-md text-[15px] leading-relaxed text-muted">
              Point it at a web app, an APK, or a source directory. It finds the holes, proves each one with the
              exact request that triggered it, and hands you the line that fixes it.
            </p>

            <div className="mt-7 max-w-xs">
              <CodeBlock code="pip install fya" label="install" />
            </div>
            <div className="mt-4 flex flex-wrap gap-2.5">
              <PrimaryCta href="/docs">read the docs</PrimaryCta>
              <GithubCta />
            </div>
          </div>

          {/* right: the live finding report — prove, don't claim */}
          <div className="lift min-w-0 overflow-hidden rounded-md">
            <div className="mono flex items-center gap-3 border-b border-line px-4 py-2.5 text-[12px] text-faint">
              <span className="text-crit">▸</span>
              <span className="truncate text-muted">fya scan · report</span>
              <span className="h-px flex-1 bg-line" />
              <span className="shrink-0">v0.6.0</span>
            </div>

            <div className="p-4 sm:p-5">
              <div className="mono text-[12.5px] leading-relaxed">
                <div className="reveal break-words" style={{ animationDelay: "60ms" }}>
                  <span className="text-ok">$</span> <span className="font-semibold text-crit">fya</span> scan
                  http://localhost:5001 --mode full
                </div>
                <div className="reveal mt-1 break-words text-faint" style={{ animationDelay: "160ms" }}>
                  target 127.0.0.1:5001 · flask/werkzeug · profile safe · finished in 3.2s
                </div>
              </div>

              {/* tally — 7 found + 84 clean = 91 checks */}
              <div className="reveal mt-4 flex flex-wrap items-center gap-2" style={{ animationDelay: "260ms" }}>
                <span className="mono text-[13px] font-semibold text-ink">7 findings</span>
                <span className="mono border border-crit/40 bg-crit/10 px-1.5 py-0.5 text-[11px] font-semibold text-crit">
                  5 HIGH
                </span>
                <span className="mono border border-med/40 bg-med/10 px-1.5 py-0.5 text-[11px] font-semibold text-med">
                  2 MED
                </span>
                <span className="mono border border-ok/40 bg-ok/10 px-1.5 py-0.5 text-[11px] font-semibold text-ok">
                  84 PASS
                </span>
                <span className="mono ml-auto hidden text-[11px] text-faint sm:inline">owasp + cwe mapped</span>
              </div>

              {/* finding rows — 5 shown + 2 elided = the 7 in the tally */}
              <ul className="mt-4 divide-y divide-line border-y border-line">
                {findings.map((f, i) => (
                  <li
                    key={f.id}
                    className="reveal flex min-w-0 items-start gap-3 py-2.5 sm:items-center"
                    style={{ animationDelay: `${340 + i * 70}ms` }}
                  >
                    <span
                      className={"mono w-11 shrink-0 border px-1 py-0.5 text-center text-[10px] font-bold " + sevBox[f.sev]}
                    >
                      {f.sev}
                    </span>
                    <span className="mono mt-px hidden shrink-0 text-[12px] text-info sm:mt-0 sm:inline">{f.id}</span>
                    <span className="min-w-0 flex-1 text-[13px] leading-snug text-ink/80 sm:truncate">{f.title}</span>
                  </li>
                ))}
                <li
                  className="reveal flex items-center gap-3 py-2.5"
                  style={{ animationDelay: `${340 + findings.length * 70}ms` }}
                >
                  <span className="mono w-11 shrink-0 text-center text-[11px] text-faint">···</span>
                  <span className="mono min-w-0 flex-1 truncate text-[12px] text-faint">
                    + 2 more · 1 HIGH · 1 MED
                  </span>
                </li>
              </ul>

              {/* one finding expanded — the receipt */}
              <div className="reveal mt-4 border border-line bg-bg/60 p-3.5" style={{ animationDelay: "720ms" }}>
                <div className="mono flex items-center gap-2 text-[12px]">
                  <span className={"font-bold " + sevText[findings[0].sev]}>▸ {findings[0].id}</span>
                </div>
                <dl className="mono mt-2.5 space-y-1.5 text-[12px] leading-relaxed">
                  {(
                    [
                      ["req", <span className="text-ink/85">{findings[0].req}</span>],
                      ["proof", <span className="text-muted">{findings[0].proof}</span>],
                      ["map", <span className="text-med">{findings[0].map}</span>],
                      ["fix", <span className="text-ok">{findings[0].fix}</span>],
                    ] as [string, React.ReactNode][]
                  ).map(([k, v]) => (
                    <div key={k} className="flex gap-2">
                      <dt className="w-9 shrink-0 text-faint">{k}</dt>
                      <dd className="min-w-0 flex-1 break-words">{v}</dd>
                    </div>
                  ))}
                </dl>
              </div>
              <p className="mono mt-3 break-words text-[10.5px] text-faint">
                demo scan of the bundled vulnerable app · examples/vulnerable_app.py
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ── manifesto line ──────────────────────────────────────────────── */}
      <section className="mt-28 border-y border-line py-14">
        <p className="mono max-w-3xl text-[20px] font-semibold leading-snug tracking-tight sm:text-[26px]">
          Most scanners hedge.{" "}
          <span className="text-muted">
            fya shows you where it broke, the request that did it, and the line that fixes it.
          </span>
        </p>
      </section>

      {/* ── capabilities (DESCRIPTION) ──────────────────────────────────── */}
      <section className="mt-24">
        <SectionHead n="01" id="why" title="Description" note="what it is" />
        <dl className="mt-8 grid grid-cols-1 gap-x-12 gap-y-8 sm:grid-cols-2">
          {capabilities.map((c) => (
            <div key={c.term} className="border-t border-line pt-4">
              <dt className="mono text-[14px] font-semibold text-ink">
                <span className="text-crit">— </span>
                {c.term}
              </dt>
              <dd className="mt-2 text-[14px] leading-relaxed text-muted">{c.body}</dd>
            </div>
          ))}
        </dl>
      </section>

      {/* ── Claude skill ────────────────────────────────────────────────── */}
      <section id="skill" className="mt-24 scroll-mt-24">
        <SectionHead n="02" id="skill-head" title="Claude skill" note="no package required" />
        <div className="card mt-8 rounded-md p-6 sm:p-8">
          <h3 className="mono text-[17px] font-bold tracking-tight text-ink sm:text-[19px]">
            No terminal? Tell Claude to <span className="text-crit">break it.</span>
          </h3>
          <p className="mt-3 max-w-2xl text-[15px] leading-relaxed text-muted">
            fya ships as a Claude skill. Drop it into your setup and say what to scan. Claude confirms you own the
            target, runs the same non-destructive checks itself, and reports right in the chat — no package to install.
          </p>
          <div className="mt-7 grid grid-cols-1 gap-5 md:grid-cols-2">
            <div>
              <div className="mono mb-2 text-[12px] text-faint">1 — install the skill</div>
              <CodeBlock
                label="shell"
                code={"git clone https://github.com/ayam04/fya\ncp -r fya/skills/fya ~/.claude/skills/fya"}
              />
            </div>
            <div>
              <div className="mono mb-2 text-[12px] text-faint">2 — just ask</div>
              <CodeBlock
                label="claude"
                code={"scan http://localhost:3000 for vulnerabilities\ncheck ./app-release.apk for security issues"}
              />
            </div>
          </div>
          <Link href="/docs#skill" className="mono mt-6 inline-block text-[13px] text-crit hover:text-high">
            full skill setup in the docs →
          </Link>
        </div>
      </section>

      {/* ── how it works (pipeline) ─────────────────────────────────────── */}
      <section className="mt-24">
        <SectionHead n="03" id="how" title="How it works" note="detect → report" />
        <ol className="mt-8">
          {pipeline.map(([title, body, time], i) => (
            <li key={title} className="flex gap-5 border-t border-line py-5 last:border-b">
              <div className="mono w-8 shrink-0 text-[13px] text-crit">{String(i + 1).padStart(2, "0")}</div>
              <div className="min-w-0 flex-1">
                <h3 className="mono text-[14px] font-semibold text-ink">{title}</h3>
                <p className="mt-1.5 max-w-2xl text-[14px] leading-relaxed text-muted">{body}</p>
              </div>
              <div className="mono hidden shrink-0 items-baseline gap-2.5 self-center text-[12px] sm:flex" aria-hidden>
                <span className="text-ok">ok</span>
                <span className="w-9 text-right tabular-nums text-faint">{time}</span>
              </div>
            </li>
          ))}
        </ol>
      </section>

      {/* ── coverage ────────────────────────────────────────────────────── */}
      <section className="mt-24">
        <SectionHead n="04" id="coverage" title="What it checks" note="91 checks · 19 areas" />
        <div className="mt-8 grid grid-cols-1 gap-x-12 sm:grid-cols-2">
          {areas.map(([term, body], i) => (
            <div
              key={term}
              className={
                "flex min-w-0 gap-4 border-t border-line py-3.5 " +
                (i === areas.length - 1 ? "sm:border-b-0" : "")
              }
            >
              <span className="mono w-36 shrink-0 text-[12.5px] text-info sm:w-40">{term}</span>
              <span className="min-w-0 flex-1 text-[13px] leading-relaxed text-muted">{body}</span>
            </div>
          ))}
        </div>
        <div className="mt-6">
          <Link href="/docs#checks" className="mono text-[13px] text-crit hover:text-high">
            every check, with its OWASP and CWE mapping →
          </Link>
        </div>
      </section>

      {/* ── close ───────────────────────────────────────────────────────── */}
      <section className="mt-28">
        <div className="card rounded-md p-8 sm:p-12">
          <Masthead left="EXIT" center="ship the fix, not the incident report" right="1" />
          <h2 className="mono mt-8 max-w-2xl text-balance text-[24px] font-bold leading-tight tracking-tight sm:text-[32px]">
            Break your app before <span className="whitespace-nowrap text-crit">someone else does.</span>
          </h2>
          <p className="mt-4 max-w-xl text-[15px] leading-relaxed text-muted">
            Start with your localhost right now. It takes one command and a couple of seconds.
          </p>
          <div className="mt-7 max-w-xs">
            <CodeBlock code="pip install fya" label="install" />
          </div>
          <div className="mt-4 flex flex-wrap gap-2.5">
            <PrimaryCta href="/docs">read the docs</PrimaryCta>
            <GithubCta />
          </div>
          <div className="mt-8 max-w-2xl">
            <Callout tone="warn">
              Non-destructive by default. Localhost is fair game; any remote target needs an explicit{" "}
              <code className="mono whitespace-nowrap rounded bg-white/10 px-1 text-[12px]">--i-am-authorized</code>{" "}
              flag. Test only what you own.
            </Callout>
          </div>

          <div className="mono mt-8 flex flex-wrap items-center gap-x-2.5 gap-y-1 border-t border-line pt-6 text-[12px]">
            <span className="text-faint">SEE ALSO —</span>
            <Link href="/docs" className="text-info hover:text-ink">
              docs(1)
            </Link>
            <span className="text-faint">·</span>
            <Link href="/changelog" className="text-info hover:text-ink">
              changelog(1)
            </Link>
            <span className="text-faint">·</span>
            <a href="https://github.com/ayam04/fya" className="text-info hover:text-ink">
              github(1)
            </a>
            <span className="text-faint">·</span>
            <a href="https://pypi.org/project/fya/" className="text-info hover:text-ink">
              pypi(1)
            </a>
          </div>
        </div>
      </section>
    </div>
  )
}
