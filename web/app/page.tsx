import Link from "next/link"
import { Target, Lightning, ShieldCheck, MagnifyingGlass, Key, TerminalWindow } from "@phosphor-icons/react/dist/ssr"
import { CodeBlock } from "@/components/CodeBlock"
import { Callout } from "@/components/Callout"
import { Reveal } from "@/components/Reveal"

const features = [
  {
    Icon: Target,
    span: "md:col-span-2",
    tint: false,
    title: "One tool, three targets",
    body: "A running web server, an Android .apk, or a source directory, same command. It works out which and runs only what fits.",
  },
  {
    Icon: Lightning,
    span: "md:col-span-4",
    tint: true,
    title: "It actually breaks things",
    body: "Reflected XSS, SQLi, SSTI, IDOR, input fuzzing, a leaking .env, hardcoded secrets in your source, a debuggable APK. If it is there, you get the receipt that proves it.",
  },
  {
    Icon: ShieldCheck,
    span: "md:col-span-3",
    tint: false,
    title: "Black, gray, and white box",
    body: "58 checks across all three. Fuzz inputs from outside, probe access control with partial knowledge, or scan the source itself. Every finding maps to OWASP and a CWE.",
  },
  {
    Icon: MagnifyingGlass,
    span: "md:col-span-3",
    tint: false,
    title: "It does not cry wolf",
    body: "Baselines, context-aware reflection, and honest severity. A confident wrong finding is worse than a missed one, so it earns every flag.",
  },
  {
    Icon: Key,
    span: "md:col-span-4",
    tint: true,
    title: "Built for real apps",
    body: "Authenticated scans, scoped crawls, request budgets, a CI baseline, and a headless browser for single-page apps.",
  },
  {
    Icon: TerminalWindow,
    span: "md:col-span-2",
    tint: false,
    title: "Free for noncommercial use",
    body: "Free for personal, hobby, research, and nonprofit use under PolyForm Noncommercial. Commercial use needs a license. No dashboard, no agent, no account.",
  },
]

const steps = [
  ["Detect", "Web server, .apk, or source directory. It decides, you do not configure it."],
  ["Fingerprint", "Reads the stack, framework, cookies, and whether it is a JSON API from the first responses."],
  ["Plan", "Picks only the checks that fit the target and the profile."],
  ["Break", "Runs non-destructive probes and tunes pacing to what the target tolerates. No flooding, ever."],
  ["Prove", "De-duplicates, maps each finding to OWASP and CWE, and keeps the receipts."],
  ["Report", "Console, JSON, SARIF, Markdown, or a self-contained HTML page."],
]

const areas = [
  ["Web active", "Reflected XSS, error-based SQLi, open redirect, path traversal, CORS reflection, and advanced CORS bypasses (null origin, prefix and suffix match bugs)."],
  ["Web advanced", "Server-side template injection, CSRF, Host header injection, CRLF, forwarded-header cache poisoning, and X-Original-URL access-control bypass."],
  ["SSRF & injection", "Signature-based SSRF (cloud metadata and file://), MongoDB-style NoSQL injection, and XPath, LDAP, and SSI injection."],
  ["Secrets & files", "Secrets in client-side JavaScript, exposed source maps, dumpable .git/.svn repos, leaked config and credential files, and directory listing."],
  ["Web passive & hardening", "Security headers, cookie flags and prefix misuse, CSP holes, COOP/CORP/Permissions-Policy, JWT weaknesses, and outdated JS libraries."],
  ["Black & gray box", "Input fuzzing that surfaces crashes and stack traces, insecure direct object references, and protected routes reachable without auth."],
  ["White box (source)", "Point it at a directory: hardcoded secrets, risky sinks, dangerous GitHub Actions workflows, and semgrep or bandit folded in."],
  ["API", "OpenAPI and Swagger exposure, GraphQL introspection, plus GraphQL field-suggestion leakage, batching, and GET/CSRF execution."],
  ["Mobile (APK)", "Hardcoded secrets, cleartext endpoints, manifest sins, insecure WebView bridges, unverified App Links, and weak custom permissions."],
  ["TLS & tools", "Certificate trust and expiry, weak protocols, and Nuclei, Nikto, nmap, sqlmap, and testssl folded into one report when installed."],
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
        <div className="relative mx-auto max-w-5xl px-5 pb-16 pt-28 text-center sm:pt-32">
          <Reveal>
            <span className="inline-flex items-center rounded-full border border-brand/30 bg-brand/10 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.18em] text-brand shadow-[0_0_24px_-8px_rgba(255,77,77,0.65)]">
              f*ck your app
            </span>
          </Reveal>
          <Reveal delay={60}>
            <h1 className="font-display mx-auto mt-6 max-w-3xl text-4xl font-semibold leading-[1.06] tracking-tight sm:text-6xl md:text-7xl">
              Point it at your app.
              <br />
              <span className="text-gradient">It tries to break it.</span>
            </h1>
          </Reveal>
          <Reveal delay={120}>
            <p className="mx-auto mt-6 max-w-xl text-lg leading-relaxed text-muted">
              Point it at a web app or an APK. It finds the holes, proves them with the exact request, and hands you
              the fix.
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
        <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-6">
          {features.map((f, i) => (
            <Reveal key={f.title} delay={i * 60} className={f.span}>
              <div
                className={
                  "group flex h-full flex-col rounded-2xl border border-line p-6 transition duration-200 hover:border-brand/40 " +
                  (f.tint ? "bg-gradient-to-br from-brand/[0.08] to-surface/30" : "bg-surface/40 hover:bg-surface")
                }
              >
                <f.Icon size={24} weight="duotone" className="text-brand" />
                <h3 className="font-display mt-4 text-lg font-semibold">{f.title}</h3>
                <p className="mt-2 max-w-md text-sm leading-relaxed text-muted">{f.body}</p>
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
              <div className="text-[11px] font-medium uppercase tracking-[0.18em] text-brand">Run it inside Claude</div>
              <h2 className="font-display mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
                No terminal? Tell Claude to break it.
              </h2>
              <p className="mt-3 max-w-2xl text-muted">
                fya ships as a Claude skill. Drop it into your setup and say what to scan. Claude confirms you own
                the target, runs the same non-destructive checks itself, and reports right in the chat.
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
        <ol className="mt-10">
          {steps.map(([title, body], i) => (
            <Reveal key={title} delay={i * 50}>
              <li className="flex gap-6 rounded-xl px-4 py-4 transition hover:bg-surface/40">
                <span className="font-display w-10 shrink-0 text-2xl font-semibold tabular-nums text-brand/45">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <div>
                  <h3 className="font-display text-lg font-semibold">{title}</h3>
                  <p className="mt-1 max-w-2xl text-sm leading-relaxed text-muted">{body}</p>
                </div>
              </li>
            </Reveal>
          ))}
        </ol>
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
                  <h3 className="text-sm font-semibold">{title}</h3>
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
                Read the docs
              </Link>
              <a href="https://github.com/ayam04/fya" className={ghostBtn}>
                View on GitHub
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
