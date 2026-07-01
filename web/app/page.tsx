import Link from "next/link"
import { CodeBlock } from "@/components/CodeBlock"
import { Mark } from "@/components/Mark"
import { Callout } from "@/components/Callout"

const features = [
  {
    title: "One tool, two targets",
    body: "A running web server or an Android .apk, same command. It works out which one it is and runs only what fits.",
  },
  {
    title: "It actually breaks things",
    body: "Reflected XSS, SQL injection, SSTI, open redirects, path traversal, CORS holes, a leaking .env, a debuggable APK. If it is there, you get the request that proves it.",
  },
  {
    title: "36 checks, no guesswork",
    body: "Every finding maps to the OWASP Top 10 or MASVS and a CWE, with a fix. No vague risk scores, no filler.",
  },
  {
    title: "It does not cry wolf",
    body: "Baselines, context-aware reflection, and honest severity. A confident wrong finding is worse than a missed one, so it earns every flag.",
  },
  {
    title: "Built for real apps",
    body: "Authenticated scans, scoped crawls, request budgets, a CI baseline, and a headless browser for single-page apps.",
  },
  {
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

export default function Home() {
  return (
    <>
      <section id="overview" className="mx-auto max-w-5xl px-5 pt-16 pb-16 sm:pt-24">
        <div className="mx-auto max-w-3xl text-center">
          <div className="mb-6 inline-flex items-center gap-2.5">
            <Mark size={46} className="rounded-xl" />
            <span className="text-sm font-medium uppercase tracking-[0.18em] text-muted">f*ck your app</span>
          </div>
          <h1 className="text-4xl font-semibold leading-[1.05] tracking-tight sm:text-6xl">
            Point it at your app.
            <br />
            <span className="text-brand">It tries to break it.</span>
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-muted">
            fya hunts your app the way an attacker would, then hands you the exact request that broke it and the
            line to fix. 36 OWASP-mapped checks for web apps and Android APKs. Open source, non-destructive, and it
            runs from your terminal or straight inside Claude.
          </p>
          <div className="mx-auto mt-8 max-w-md">
            <CodeBlock code="pip install fya" />
          </div>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link href="/docs" className="rounded-lg bg-brand px-5 py-2.5 text-sm font-medium text-white transition hover:bg-brand-ink">
              Read the docs
            </Link>
            <a href="https://github.com/ayam04/fya" className="rounded-lg border border-line px-5 py-2.5 text-sm font-medium transition hover:bg-code">
              View on GitHub
            </a>
          </div>
          <div className="mx-auto mt-6 max-w-lg text-left">
            <Callout tone="warn">
              Non-destructive by default. Localhost is fair game; any remote target needs an explicit{" "}
              <code className="rounded bg-white px-1 font-mono text-[13px]">--i-am-authorized</code> flag. Test only
              what you own.
            </Callout>
          </div>
        </div>
      </section>

      <section className="bg-ink text-white">
        <div className="mx-auto max-w-5xl px-5 py-16">
          <p className="text-2xl font-semibold leading-snug tracking-tight sm:text-3xl">
            Most scanners hedge. fya shows you where it broke, the request that did it, and the line that fixes it.
          </p>
          <p className="mt-4 max-w-2xl text-white/60">
            No dashboards. No agents. No 40-page PDF that says "consider reviewing your configuration." One command,
            real findings, mapped to OWASP, with proof.
          </p>
        </div>
      </section>

      <section className="border-b border-line bg-code/60">
        <div className="mx-auto grid max-w-5xl gap-5 px-5 py-14 md:grid-cols-2">
          <div className="rounded-xl border border-line bg-white p-6">
            <div className="text-xs font-medium uppercase tracking-wide text-muted">Web server</div>
            <p className="mt-2 mb-4 text-sm text-muted">Point it at a running app on localhost or a URL you own.</p>
            <CodeBlock code={"fya scan http://127.0.0.1:8000\nfya scan http://127.0.0.1:8000 --mode full"} />
          </div>
          <div className="rounded-xl border border-line bg-white p-6">
            <div className="text-xs font-medium uppercase tracking-wide text-muted">Android APK</div>
            <p className="mt-2 mb-4 text-sm text-muted">Rip a build apart for secrets and manifest sins.</p>
            <CodeBlock code={"fya scan ./app-release.apk\npip install \"fya[apk]\"  # manifest analysis"} />
          </div>
        </div>
      </section>

      <section id="skill" className="mx-auto max-w-5xl px-5 py-20">
        <div className="rounded-2xl border border-line bg-white p-8 sm:p-10">
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-brand">
            <span className="h-1.5 w-1.5 rounded-full bg-brand" />
            Run it inside Claude
          </div>
          <h2 className="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">
            No terminal? Tell Claude to break it.
          </h2>
          <p className="mt-3 max-w-2xl text-muted">
            fya ships as a Claude skill. Drop it into your Claude setup and just say what to scan. Claude confirms
            you own the target, runs the same non-destructive checks itself, and reports right in the chat. No
            package required.
          </p>
          <div className="mt-8 grid gap-6 md:grid-cols-2">
            <div>
              <div className="mb-2 text-sm font-semibold">1. Install the skill</div>
              <CodeBlock code={"git clone https://github.com/ayam04/fya\ncp -r fya/skills/fya ~/.claude/skills/fya"} />
              <p className="mt-2 text-xs text-muted">
                Copies one folder. On Windows, use{" "}
                <code className="rounded bg-code px-1 font-mono">%USERPROFILE%\\.claude\\skills</code>.
              </p>
            </div>
            <div>
              <div className="mb-2 text-sm font-semibold">2. Just ask</div>
              <CodeBlock code={"scan http://localhost:3000 for vulnerabilities\ncheck ./app-release.apk for security issues"} />
              <p className="mt-2 text-xs text-muted">
                Claude loads the skill, confirms scope, and runs the full OWASP-mapped scan.
              </p>
            </div>
          </div>
          <div className="mt-8">
            <Link href="/docs#skill" className="text-sm font-medium text-brand hover:text-brand-ink">
              Full skill setup in the docs
            </Link>
          </div>
        </div>
      </section>

      <section className="border-t border-line">
        <div className="mx-auto max-w-5xl px-5 py-20">
          <h2 className="text-2xl font-semibold tracking-tight">Why fya</h2>
          <div className="mt-8 grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2 lg:grid-cols-3">
            {features.map((f) => (
              <div key={f.title} className="bg-white p-6">
                <h3 className="text-base font-semibold">{f.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted">{f.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="border-t border-line bg-code/60">
        <div className="mx-auto max-w-5xl px-5 py-20">
          <h2 className="text-2xl font-semibold tracking-tight">How it works</h2>
          <ol className="mt-8 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
            {steps.map(([title, body], i) => (
              <li key={title} className="rounded-xl border border-line bg-white p-6">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand/10 text-sm font-semibold text-brand">
                  {i + 1}
                </div>
                <h3 className="mt-4 text-base font-semibold">{title}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-muted">{body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-5 py-20">
        <div className="flex flex-wrap items-end justify-between gap-4">
          <h2 className="text-2xl font-semibold tracking-tight">What it checks</h2>
          <Link href="/docs#checks" className="text-sm text-brand hover:text-brand-ink">
            Full catalog in the docs
          </Link>
        </div>
        <div className="mt-8 grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2">
          {areas.map(([title, body]) => (
            <div key={title} className="bg-white p-6">
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-brand" />
                <h3 className="text-sm font-semibold">{title}</h3>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-muted">{body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="border-t border-line">
        <div className="mx-auto max-w-3xl px-5 py-20 text-center">
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">Break your app before someone else does.</h2>
          <p className="mx-auto mt-4 max-w-xl text-muted">
            Ship the fix, not the incident report. Start with your localhost right now.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Link href="/docs" className="rounded-lg bg-brand px-5 py-2.5 text-sm font-medium text-white transition hover:bg-brand-ink">
              Get started
            </Link>
            <a href="https://github.com/ayam04/fya" className="rounded-lg border border-line px-5 py-2.5 text-sm font-medium transition hover:bg-code">
              Star on GitHub
            </a>
          </div>
        </div>
      </section>
    </>
  )
}
