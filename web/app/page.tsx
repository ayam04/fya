import Link from "next/link"
import { CodeBlock } from "@/components/CodeBlock"
import { Callout } from "@/components/Callout"
import { Reveal } from "@/components/Reveal"

const icon = "h-5 w-5"

const features = [
  {
    svg: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={icon}>
        <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="4" /><path d="M12 1v3M12 20v3M1 12h3M20 12h3" />
      </svg>
    ),
    title: "One tool, two targets",
    body: "A running web server or an Android .apk, same command. It works out which one it is and runs only what fits.",
  },
  {
    svg: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={icon}>
        <path d="M13 2 3 14h7l-1 8 10-12h-7z" />
      </svg>
    ),
    title: "It actually breaks things",
    body: "Reflected XSS, SQLi, SSTI, open redirects, path traversal, CORS holes, a leaking .env, a debuggable APK. If it is there, you get the request that proves it.",
  },
  {
    svg: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={icon}>
        <path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z" /><path d="M9 12l2 2 4-4" />
      </svg>
    ),
    title: "36 checks, no guesswork",
    body: "Every finding maps to the OWASP Top 10 or MASVS and a CWE, with a fix. No vague risk scores, no filler.",
  },
  {
    svg: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={icon}>
        <path d="M22 12a10 10 0 1 1-6.6-9.4" /><path d="M12 12l6-3" /><circle cx="12" cy="12" r="1.6" fill="currentColor" stroke="none" />
      </svg>
    ),
    title: "It does not cry wolf",
    body: "Baselines, context-aware reflection, and honest severity. A confident wrong finding is worse than a missed one, so it earns every flag.",
  },
  {
    svg: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={icon}>
        <circle cx="8" cy="15" r="4" /><path d="M10.8 12.2 20 3M17 6l2 2M14 9l2 2" />
      </svg>
    ),
    title: "Built for real apps",
    body: "Authenticated scans, scoped crawls, request budgets, a CI baseline, and a headless browser for single-page apps.",
  },
  {
    svg: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className={icon}>
        <rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M13 15h4" />
      </svg>
    ),
    title: "Yours, free, no leash",
    body: "MIT licensed. No dashboard to buy, no agent to install, no account. It runs in your terminal or inside Claude.",
  },
]

const steps = [
  ["Detect", "Web server or .apk. It decides, you do not configure it."],
  ["Fingerprint", "Reads the stack, framework, cookies, and whether it is a JSON API from the first responses."],
  ["Plan", "Picks only the checks that fit the target and the profile."],
  ["Break", "Runs non-destructive probes and tunes pacing to what the target tolerates. No flooding, ever."],
  ["Prove", "De-duplicates, maps each finding to OWASP and CWE, and keeps the receipts."],
  ["Report", "Console, JSON, SARIF, Markdown, or a self-contained HTML page."],
]

const areas = [
  ["Web passive", "Security headers, server and version disclosure, weak cookie flags."],
  ["Web active", "Reflected XSS, error-based SQLi, open redirect, path traversal, CORS, dangerous methods, exposed files."],
  ["Web advanced", "Server-side template injection, missing CSRF token, Host header injection, CRLF injection."],
  ["Web hardening", "CSP holes, JWT algorithm and claims, outdated JS libraries, security.txt and robots.txt."],
  ["TLS", "Certificate trust and expiry, weak protocol versions, missing HTTP to HTTPS upgrade."],
  ["API", "OpenAPI and Swagger exposure, GraphQL introspection, verbose errors, unauthenticated admin endpoints."],
  ["APK static", "Hardcoded secrets, cleartext endpoints, and manifest sins via androguard."],
  ["Integrations", "Nuclei, Nikto, nmap, sqlmap, and testssl, folded into one report when installed."],
]

const primaryBtn =
  "cursor-pointer rounded-full bg-brand px-5 py-2.5 text-sm font-semibold text-white shadow-[0_0_36px_-6px_rgba(255,77,77,0.7)] transition hover:brightness-110"
const ghostBtn = "cursor-pointer rounded-full border border-line px-5 py-2.5 text-sm font-medium text-ink transition hover:bg-white/[0.05]"

export default function Home() {
  return (
    <>
      <section id="overview" className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-0 bg-grid opacity-50" />
        <div className="pointer-events-none absolute inset-x-0 top-0 h-[620px] hero-glow" />
        <div className="relative mx-auto max-w-5xl px-5 pb-16 pt-36 text-center sm:pt-40">
          <Reveal>
            <span className="inline-flex items-center gap-2 rounded-full border border-line bg-surface/60 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.18em] text-muted">
              <span className="h-1.5 w-1.5 rounded-full bg-brand" /> f*ck your app
            </span>
          </Reveal>
          <Reveal delay={60}>
            <h1 className="font-display mx-auto mt-6 max-w-3xl text-5xl font-semibold leading-[1.02] tracking-tight sm:text-7xl">
              Point it at your app.
              <br />
              <span className="text-gradient">It tries to break it.</span>
            </h1>
          </Reveal>
          <Reveal delay={120}>
            <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-muted">
              An open-source scanner that hunts your web app or Android APK the way an attacker would, then hands
              you the exact request that broke it and the line to fix. 36 OWASP-mapped checks. Non-destructive.
              Runs in your terminal or straight inside Claude.
            </p>
          </Reveal>
          <Reveal delay={180}>
            <div className="mx-auto mt-8 flex max-w-md flex-col items-center gap-4">
              <div className="w-full">
                <CodeBlock code="pip install fya" />
              </div>
              <div className="flex flex-wrap items-center justify-center gap-3">
                <Link href="/docs" className={primaryBtn}>
                  Read the docs
                </Link>
                <a href="https://github.com/ayam04/fya" className={ghostBtn}>
                  View on GitHub
                </a>
              </div>
            </div>
          </Reveal>
          <Reveal delay={260}>
            <div className="mx-auto mt-16 max-w-3xl">
              <div className="rounded-2xl border border-line bg-surface/50 p-2 shadow-2xl shadow-black/60">
                <img
                  src="/demo.gif"
                  alt="fya scanning a vulnerable web app in the terminal and finding XSS, SQL injection, CORS, CRLF, and an exposed .env"
                  className="w-full rounded-xl"
                />
              </div>
              <p className="mt-3 text-xs text-muted">A full scan of the bundled vulnerable app, start to seven high-severity findings.</p>
            </div>
          </Reveal>
        </div>
      </section>

      <section className="border-y border-line bg-surface/30">
        <div className="mx-auto max-w-5xl px-5 py-16">
          <Reveal>
            <p className="font-display text-2xl font-semibold leading-snug tracking-tight sm:text-4xl">
              Most scanners hedge.{" "}
              <span className="text-muted">
                fya shows you where it broke, the request that did it, and the line that fixes it.
              </span>
            </p>
          </Reveal>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-5 py-20 sm:py-24">
        <Reveal>
          <h2 className="font-display text-3xl font-semibold tracking-tight">Why fya</h2>
        </Reveal>
        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f, i) => (
            <Reveal key={f.title} delay={i * 60}>
              <div className="group h-full rounded-2xl border border-line bg-surface/40 p-6 transition duration-200 hover:border-brand/40 hover:bg-surface">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-line bg-white/[0.03] text-brand">
                  {f.svg}
                </div>
                <h3 className="font-display mt-4 text-lg font-semibold">{f.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted">{f.body}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      <section id="skill" className="mx-auto max-w-5xl px-5 pb-4">
        <Reveal>
          <div className="relative overflow-hidden rounded-3xl border border-line bg-surface/50 p-8 sm:p-12">
            <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-brand/10 blur-3xl" />
            <div className="relative">
              <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.18em] text-brand">
                <span className="h-1.5 w-1.5 rounded-full bg-brand" /> Run it inside Claude
              </div>
              <h2 className="font-display mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
                No terminal? Tell Claude to break it.
              </h2>
              <p className="mt-3 max-w-2xl text-muted">
                fya ships as a Claude skill. Drop it into your Claude setup and just say what to scan. Claude
                confirms you own the target, runs the same non-destructive checks itself, and reports right in the
                chat. No package required.
              </p>
              <div className="mt-8 grid gap-6 md:grid-cols-2">
                <div>
                  <div className="mb-2 text-sm font-semibold text-ink">1. Install the skill</div>
                  <CodeBlock code={"git clone https://github.com/ayam04/fya\ncp -r fya/skills/fya ~/.claude/skills/fya"} />
                </div>
                <div>
                  <div className="mb-2 text-sm font-semibold text-ink">2. Just ask</div>
                  <CodeBlock code={"scan http://localhost:3000 for vulnerabilities\ncheck ./app-release.apk for security issues"} />
                </div>
              </div>
              <Link href="/docs#skill" className="mt-8 inline-block text-sm font-medium text-brand hover:brightness-110">
                Full skill setup in the docs
              </Link>
            </div>
          </div>
        </Reveal>
      </section>

      <section className="mx-auto max-w-5xl px-5 py-20 sm:py-24">
        <Reveal>
          <h2 className="font-display text-3xl font-semibold tracking-tight">How it works</h2>
        </Reveal>
        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {steps.map(([title, body], i) => (
            <Reveal key={title} delay={i * 50}>
              <div className="h-full rounded-2xl border border-line bg-surface/40 p-6">
                <div className="font-display flex h-9 w-9 items-center justify-center rounded-lg bg-brand/10 text-sm font-semibold text-brand">
                  {String(i + 1).padStart(2, "0")}
                </div>
                <h3 className="font-display mt-4 text-lg font-semibold">{title}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{body}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      <section className="border-t border-line bg-surface/20">
        <div className="mx-auto max-w-5xl px-5 py-20 sm:py-24">
          <Reveal>
            <div className="flex flex-wrap items-end justify-between gap-4">
              <h2 className="font-display text-3xl font-semibold tracking-tight">What it checks</h2>
              <Link href="/docs#checks" className="text-sm text-brand hover:brightness-110">
                Full catalog in the docs
              </Link>
            </div>
          </Reveal>
          <div className="mt-10 grid gap-4 sm:grid-cols-2">
            {areas.map(([title, body], i) => (
              <Reveal key={title} delay={i * 40}>
                <div className="h-full rounded-xl border border-line bg-surface/40 p-5">
                  <div className="flex items-center gap-2">
                    <span className="h-1.5 w-1.5 rounded-full bg-brand" />
                    <h3 className="text-sm font-semibold">{title}</h3>
                  </div>
                  <p className="mt-2 text-sm leading-relaxed text-muted">{body}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      <section className="border-t border-line">
        <div className="mx-auto max-w-3xl px-5 py-24 text-center">
          <Reveal>
            <h2 className="font-display text-4xl font-semibold tracking-tight sm:text-5xl">
              Break your app before <span className="text-gradient">someone else does.</span>
            </h2>
            <p className="mx-auto mt-5 max-w-xl text-muted">
              Ship the fix, not the incident report. Start with your localhost right now.
            </p>
            <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
              <Link href="/docs" className={primaryBtn}>
                Get started
              </Link>
              <a href="https://github.com/ayam04/fya" className={ghostBtn}>
                Star on GitHub
              </a>
            </div>
            <div className="mx-auto mt-10 max-w-lg text-left">
              <Callout tone="warn">
                Non-destructive by default. Localhost is fair game; any remote target needs an explicit{" "}
                <code className="rounded bg-white/10 px-1 font-mono text-[13px]">--i-am-authorized</code> flag. Test
                only what you own.
              </Callout>
            </div>
          </Reveal>
        </div>
      </section>
    </>
  )
}
