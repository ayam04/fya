import Link from "next/link"
import { CodeBlock } from "@/components/CodeBlock"

const features = [
  {
    title: "One tool, two targets",
    body: "Point it at a running web server or an Android .apk with the same command. It detects which it is and runs only what applies.",
  },
  {
    title: "Adaptive by design",
    body: "It fingerprints the stack, tunes payloads and request pacing, and backs off on errors. No flooding, no denial of service.",
  },
  {
    title: "36 checks, OWASP-mapped",
    body: "Web, API, TLS, and APK static analysis, every finding tagged to the OWASP Top 10 or MASVS with a CWE id.",
  },
  {
    title: "Orchestrates, not reinvents",
    body: "Uses Nuclei, Nikto, sqlmap, nmap, and testssl when they are installed, and falls back to built-in checks when they are not.",
  },
  {
    title: "Fits real apps and CI",
    body: "Authenticated scans, scope and request budgets, a baseline file to suppress known findings, and an optional headless-browser crawler for SPAs.",
  },
  {
    title: "CI-ready reports",
    body: "Console, JSON, SARIF for GitHub code scanning, Markdown, and a self-contained HTML page. Exit non-zero with --fail-on.",
  },
]

const steps = [
  ["Detect", "Decide whether the target is a web server or an .apk."],
  ["Fingerprint", "Read the stack, framework, cookies, and whether it is a JSON API from the first responses."],
  ["Select", "Run only the checks that apply to that target kind and profile."],
  ["Tune", "Adjust payloads, pacing, and concurrency to what the target tolerates."],
  ["Normalize", "Map every finding to OWASP and CWE, then de-duplicate."],
  ["Report", "Emit to console, JSON, SARIF, Markdown, or a shareable HTML page."],
]

const areas = [
  ["Web passive", "Security headers, server and version disclosure, insecure cookie flags."],
  ["Web active", "Reflected XSS, error-based SQLi, open redirect, path traversal, CORS, dangerous methods, sensitive files."],
  ["Web advanced", "Server-side template injection, missing CSRF token, Host header injection, CRLF injection."],
  ["Web hardening", "CSP policy weaknesses, JWT algorithm and claims, outdated JS libraries, security.txt and robots.txt."],
  ["TLS", "Certificate validity and trust, weak protocol versions, missing HTTP to HTTPS upgrade."],
  ["API", "OpenAPI and Swagger exposure, GraphQL introspection, verbose errors, unauthenticated admin endpoints."],
  ["APK static", "Hardcoded secrets, cleartext endpoints, and manifest issues via androguard."],
  ["Integrations", "Nuclei, Nikto, nmap, sqlmap, and testssl handoff, normalized into one report."],
]

export default function Home() {
  return (
    <>
      <section id="overview" className="mx-auto max-w-6xl px-5 pt-16 pb-14 sm:pt-24">
        <div className="mx-auto max-w-3xl text-center">
          <div className="mb-7 inline-flex items-center gap-2.5">
            <img src="/icon.svg" alt="" width={46} height={46} className="rounded-xl" />
            <span className="text-2xl font-semibold tracking-tight">
              fya<span className="text-brand">_</span>
            </span>
          </div>
          <h1 className="text-4xl font-semibold leading-[1.1] tracking-tight sm:text-6xl">
            Point it at your app.
            <br />
            <span className="text-brand">It tries to break it.</span>
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-muted">
            fya is an open-source, dynamic security scanner. Give it a localhost server or an Android
            APK and it detects the target, fingerprints it, tunes its own scan, and runs 36
            OWASP-mapped checks. Free, MIT licensed, and it runs from your terminal.
          </p>
          <div className="mx-auto mt-8 max-w-md">
            <CodeBlock code="pip install fya" />
          </div>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link href="/docs" className="rounded-lg bg-brand px-5 py-2.5 text-sm font-medium text-white transition hover:bg-brand-ink">
              Read the docs
            </Link>
            <a
              href="https://github.com/ayam04/fya"
              className="rounded-lg border border-line px-5 py-2.5 text-sm font-medium transition hover:bg-code"
            >
              View on GitHub
            </a>
          </div>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-xs text-muted">
            <span>v0.3.0</span>
            <span className="text-line">|</span>
            <span>MIT license</span>
            <span className="text-line">|</span>
            <span>Python 3.9+</span>
            <span className="text-line">|</span>
            <span>36 checks</span>
          </div>
        </div>
      </section>

      <section className="border-y border-line bg-code/60">
        <div className="mx-auto grid max-w-6xl gap-5 px-5 py-14 md:grid-cols-2">
          <div className="rounded-xl border border-line bg-white p-6">
            <div className="text-xs font-medium uppercase tracking-wide text-muted">Web server</div>
            <p className="mt-2 mb-4 text-sm text-muted">Scan a running app on localhost or a URL you own.</p>
            <CodeBlock code={"fya scan http://127.0.0.1:8000\nfya scan http://127.0.0.1:8000 --mode full"} />
          </div>
          <div className="rounded-xl border border-line bg-white p-6">
            <div className="text-xs font-medium uppercase tracking-wide text-muted">Android APK</div>
            <p className="mt-2 mb-4 text-sm text-muted">Static-analyze a mobile build for secrets and manifest issues.</p>
            <CodeBlock code={"fya scan ./app-release.apk\npip install \"fya[apk]\"  # manifest analysis"} />
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-6xl px-5 py-20">
        <h2 className="text-2xl font-semibold tracking-tight">Why fya</h2>
        <div className="mt-8 grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f) => (
            <div key={f.title} className="bg-white p-6">
              <h3 className="text-base font-semibold">{f.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted">{f.body}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="border-t border-line bg-code/60">
        <div className="mx-auto max-w-6xl px-5 py-20">
          <h2 className="text-2xl font-semibold tracking-tight">How it adapts per target</h2>
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

      <section className="mx-auto max-w-6xl px-5 py-20">
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
          <h2 className="text-3xl font-semibold tracking-tight">Break your app before someone else does.</h2>
          <p className="mx-auto mt-4 max-w-xl text-muted">
            Non-destructive by default. Localhost is allowed out of the box, and any remote target needs an
            explicit authorization flag.
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
