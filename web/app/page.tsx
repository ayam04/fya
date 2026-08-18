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
    body: "Command injection, XXE, blind SQLi, SSTI, IDOR, a leaking .env, a heap dump on an open actuator, a debuggable APK. If it is there, you get the receipt that proves it.",
  },
  {
    Icon: ShieldCheck,
    span: "md:col-span-3",
    tint: false,
    title: "Black, gray, and white box",
    body: "91 checks across all three. Fuzz inputs from outside, probe access control with partial knowledge, or scan the source and the infrastructure that ships it. Every finding maps to OWASP and a CWE.",
  },
  {
    Icon: MagnifyingGlass,
    span: "md:col-span-3",
    tint: false,
    title: "It does not cry wolf",
    body: "Every check is proven against a baseline and pinned by a test that keeps it silent on a hardened app. A confident wrong finding is worse than a missed one.",
  },
  {
    Icon: Key,
    span: "md:col-span-4",
    tint: true,
    title: "Built for real apps",
    body: "Authenticated scans, scoped crawls, request budgets, a CI baseline, per-check selection, and a headless browser for single-page apps.",
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
  ["Web active", "Reflected XSS, error-based SQLi, open redirect, path traversal, CORS reflection, and advanced CORS bypasses."],
  ["Advanced injection", "OS command injection proven by an arithmetic oracle, XXE, boolean-blind SQLi, PHP stream wrappers, and JSON NoSQL operator injection."],
  ["SSRF and template", "Signature-based SSRF (cloud metadata and file://), server-side template injection, and XPath, LDAP, and SSI injection."],
  ["Exposure and debug", "Spring Boot actuator endpoints and heap dumps, phpinfo and server-status pages, the Werkzeug console, and editor or backup copies of live source files."],
  ["Crypto and tokens", "JWT signed with a guessable secret, jku and x5u header injection, certificate key size and signature algorithm, mixed content, and serialized object blobs."],
  ["Secrets and files", "Secrets in client-side JavaScript, exposed source maps, dumpable .git and .svn repos, leaked config files, and directory listing."],
  ["Passive and hardening", "Security headers, cookie flags and prefix misuse, CSP holes, COOP, CORP and Permissions-Policy, and outdated JS libraries."],
  ["Black and gray box", "Input fuzzing that surfaces crashes and stack traces, insecure direct object references, and protected routes reachable without auth."],
  ["Source analysis", "Hardcoded secrets, committed key material, SQL built by string concatenation, weak crypto, and disabled certificate verification."],
  ["IaC and supply chain", "Dockerfile and Compose hardening, Kubernetes workload security, Terraform exposure, insecure package sources, and pwn-request or script injection in GitHub Actions."],
  ["API", "OpenAPI and Swagger exposure, GraphQL introspection and field-suggestion leakage, OIDC discovery misconfiguration, and exposed SOAP and WSDL endpoints."],
  ["Mobile (APK)", "Network security config and pinning gaps, exported content providers, deep-link hijacking, v1-only signing, debug certificates, weak crypto, and insecure TLS code."],
  ["TLS and tools", "Certificate trust and expiry, weak protocols, and Nuclei, Nikto, nmap, sqlmap, and testssl folded into one report when installed."],
]

const primaryBtn =
  "cursor-pointer rounded-full bg-brand px-5 py-2.5 text-sm font-semibold text-white shadow-[0_0_36px_-6px_rgba(255,77,77,0.7)] transition hover:brightness-110"
const ghostBtn =
  "cursor-pointer rounded-full border border-line px-5 py-2.5 text-sm font-medium text-ink transition hover:border-line-strong hover:bg-white/[0.05]"

export default function Home() {
  return (
    <>
      <section id="overview" className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-0 bg-scan opacity-60" />
        <div className="pointer-events-none absolute inset-x-0 top-0 h-[620px] hero-glow" />
        <div className="relative mx-auto max-w-5xl px-5 pb-16 pt-28 text-center sm:pt-32">
          <Reveal>
            <span className="inline-flex items-center rounded-full border border-brand/30 bg-brand/10 px-3 py-1 text-[11px] font-medium uppercase tracking-[0.18em] text-brand shadow-[0_0_24px_-8px_rgba(255,77,77,0.65)]">
              f*ck your app
            </span>
          </Reveal>
          <Reveal delay={60}>
            <h1 className="font-display mx-auto mt-6 max-w-3xl text-4xl font-semibold leading-[1.06] sm:text-6xl md:text-7xl">
              Point it at your app.
              <br />
              <span className="text-brand">It tries to break it.</span>
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
              <div className="panel-raised overflow-hidden rounded-2xl bg-surface/60 p-2">
                <img
                  src="/demo.svg"
                  alt="fya scanning a web app in the terminal and finding reflected XSS, SQL injection, SSRF, an exposed .git repo, and a CORS bypass, each mapped to OWASP and CWE"
                  className="w-full rounded-xl"
                />
              </div>
              <p className="mt-3 text-xs text-muted">
                A full scan of the bundled vulnerable app, start to seven high-severity findings.
              </p>
            </div>
          </Reveal>
        </div>
      </section>

      <section className="border-y border-line bg-surface/30">
        <div className="mx-auto max-w-5xl px-5 py-16">
          <Reveal>
            <p className="font-display text-2xl font-semibold leading-snug sm:text-4xl">
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
          <h2 className="font-display text-3xl font-semibold">Why fya</h2>
        </Reveal>
        <Reveal delay={80}>
          <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-6">
            {features.map((f) => (
              <div
                key={f.title}
                className={
                  "group flex h-full flex-col rounded-2xl border border-line p-6 transition duration-200 hover:border-brand/40 " +
                  f.span +
                  " " +
                  (f.tint ? "bg-gradient-to-br from-brand/[0.08] to-surface/30" : "bg-surface/40 hover:bg-surface")
                }
              >
                <f.Icon size={24} weight="duotone" className="text-brand" />
                <h3 className="font-display mt-4 text-lg font-semibold">{f.title}</h3>
                <p className="mt-2 max-w-md text-sm leading-relaxed text-muted">{f.body}</p>
              </div>
            ))}
          </div>
        </Reveal>
      </section>

      <section id="skill" className="mx-auto max-w-5xl px-5 pb-4">
        <Reveal>
          <div className="relative overflow-hidden rounded-3xl border border-line bg-surface/50 p-8 sm:p-12">
            <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-brand/10 blur-3xl" />
            <div className="relative">
              <div className="text-[11px] font-medium uppercase tracking-[0.18em] text-brand">Run it inside Claude</div>
              <h2 className="font-display mt-3 text-3xl font-semibold sm:text-4xl">
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
          <h2 className="font-display text-3xl font-semibold">How it works</h2>
        </Reveal>
        <Reveal delay={80}>
          <ol className="mt-10">
            {steps.map(([title, body], i) => (
              <li key={title} className="flex gap-6 rounded-xl px-4 py-4 transition hover:bg-surface/40">
                <span className="font-display w-10 shrink-0 text-2xl font-semibold tabular-nums text-brand/45">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <div>
                  <h3 className="font-display text-lg font-semibold">{title}</h3>
                  <p className="mt-1 max-w-2xl text-sm leading-relaxed text-muted">{body}</p>
                </div>
              </li>
            ))}
          </ol>
        </Reveal>
      </section>

      <section className="border-t border-line bg-surface/20">
        <div className="mx-auto max-w-5xl px-5 py-20 sm:py-24">
          <Reveal>
            <div className="flex flex-wrap items-end justify-between gap-4">
              <h2 className="font-display text-3xl font-semibold">What it checks</h2>
              <Link href="/docs#checks" className="text-sm text-brand hover:brightness-110">
                All 91 checks in the docs
              </Link>
            </div>
          </Reveal>
          <Reveal delay={80}>
            <div className="mt-10 grid gap-4 sm:grid-cols-2">
              {areas.map(([title, body]) => (
                <div key={title} className="h-full rounded-xl border border-line bg-surface/40 p-5">
                  <h3 className="text-sm font-semibold">{title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-muted">{body}</p>
                </div>
              ))}
            </div>
          </Reveal>
        </div>
      </section>

      <section className="border-t border-line">
        <div className="mx-auto max-w-3xl px-5 py-24 text-center">
          <Reveal>
            <h2 className="font-display text-4xl font-semibold sm:text-5xl">
              Break your app before <span className="text-brand">someone else does.</span>
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
