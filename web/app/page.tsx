import Link from "next/link"
import Image from "next/image"
import { CodeBlock } from "@/components/CodeBlock"
import { Callout } from "@/components/Callout"
import { softwareApplication, faq } from "./structured-data.mjs"

const targets = [
  {
    kind: "web",
    cmd: "fya scan http://localhost:3000",
    body: "Fuzzes inputs, walks the routes, probes access control. Command injection proven by an arithmetic oracle. SSRF reaches cloud metadata.",
  },
  {
    kind: "apk",
    cmd: "fya scan app-release.apk",
    body: "Unpacks the manifest and the DEX. Exported providers, deep-link hijacking, v1 signing, debug certificates.",
  },
  {
    kind: "source",
    cmd: "fya scan ./services",
    body: "Reads the code and the infrastructure. Hardcoded secrets, SQL by concatenation, Docker and Kubernetes hardening, pwn-request in Actions.",
  },
]

const pipeline: [string, string][] = [
  ["detect", "Decides whether the target is a server, an APK, or a source tree."],
  ["fingerprint", "Reads stack, framework, and cookies from the first responses."],
  ["plan", "Selects only the checks that fit the target and the profile."],
  ["break", "Runs non-destructive probes, paced to what the target tolerates."],
  ["prove", "De-duplicates, maps to OWASP and CWE, and keeps the receipts."],
  ["report", "Writes console, JSON, SARIF, Markdown, or a self-contained HTML page."],
]

// Severity is the site's color system turned into report grammar. A scan
// report prints its key; the home page does the same. Colors are the real
// tokens from globals.css, applied the way the report applies them.
const legend: [string, string][] = [
  ["crit / high", "bg-crit"],
  ["medium", "bg-med"],
  ["low", "bg-low"],
  ["pass", "bg-ok"],
  ["note", "bg-info"],
]

const coverage: [string, string, [string, string][]][] = [
  [
    "web",
    "45 checks",
    [
      ["injection", "Command injection, XXE, boolean-blind SQLi, SSTI, XPath, LDAP, PHP stream wrappers, JSON NoSQL operators."],
      ["exposure", "Actuators and heap dumps, phpinfo, the Werkzeug console, backup copies of live source."],
      ["secrets", "Keys in client JavaScript, source maps, dumpable .git and .svn, leaked config, directory listing."],
      ["crypto", "JWT signed with a guessable secret, jku and x5u header injection, certificate strength, serialized blobs."],
      ["hardening", "Security headers, cookie flags, CSP holes, COOP and CORP, outdated JS libraries."],
    ],
  ],
  [
    "mobile and source",
    "29 checks",
    [
      ["apk", "Network security config, exported providers, deep-link hijacking, v1 signing, debug certs, weak crypto."],
      ["whitebox", "Hardcoded secrets, committed key material, SQL string concatenation, disabled certificate verification."],
      ["iac", "Dockerfile and Compose hardening, Kubernetes workload security, Terraform exposure, GitHub Actions."],
    ],
  ],
  [
    "api and transport",
    "17 checks",
    [
      ["api", "OpenAPI and Swagger exposure, GraphQL introspection, OIDC discovery, SOAP and WSDL."],
      ["tls", "Certificate trust and expiry, weak protocols, key size, mixed content."],
      ["tools", "Nuclei, Nikto, nmap, sqlmap, and testssl folded into one report when they are installed."],
    ],
  ],
]

function PrimaryCta({ href, children }: { href: string; children: string }) {
  return (
    <Link
      href={href}
      className="mono group inline-flex items-center gap-2 rounded-[3px] bg-ink px-4 py-2.5 text-[13px] font-semibold text-bg transition hover:bg-white"
    >
      {children}
      <span className="transition-transform duration-200 group-hover:translate-x-1">&rarr;</span>
    </Link>
  )
}

function GithubCta() {
  return (
    <a
      href="https://github.com/ayam04/fya"
      className="mono inline-flex items-center gap-2 rounded-[3px] border border-line bg-panel px-4 py-2.5 text-[13px] text-ink transition-colors hover:border-line-strong hover:bg-panel2"
    >
      <span className="text-faint">$</span> github
    </a>
  )
}

export default function Home() {
  return (
    <div className="mx-auto max-w-6xl px-4 sm:px-6">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(softwareApplication) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faq) }}
      />
      <section className="grid grid-cols-1 items-center gap-10 pt-24 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)] xl:gap-14">
        <div className="min-w-0">
          <h1 className="mono reveal text-[30px] font-bold leading-[1.12] tracking-tight text-ink sm:text-[34px]">
            Point it at your app.
            <br />
            <span className="text-crit">It tries to break it.</span>
          </h1>

          <div className="mono reveal mt-7 flex items-center overflow-x-auto whitespace-nowrap border border-line bg-panel px-3.5 py-3 text-[13px]" style={{ animationDelay: "80ms" }}>
            <span className="text-ok">$&nbsp;</span>
            <span className="font-semibold text-crit">fya&nbsp;</span>
            <span className="text-ink">scan&nbsp;</span>
            <span className="text-info">&lt;target&gt;</span>
            <span className="caret ml-1 shrink-0" aria-hidden />
          </div>

          <div className="reveal mt-7 flex flex-wrap gap-2.5" style={{ animationDelay: "140ms" }}>
            <PrimaryCta href="/docs">read the docs</PrimaryCta>
            <GithubCta />
          </div>
        </div>

        <figure className="reveal lift min-w-0 overflow-hidden rounded-md" style={{ animationDelay: "200ms" }}>
          <Image
            src="/demo-web-scan.svg"
            alt="fya scanning a local Flask app in the terminal, reporting high severity SQL injection, reflected XSS, SSRF to cloud metadata, an exposed .git directory, and a CORS bypass, each mapped to a CWE and an OWASP category"
            width={1238}
            height={1221}
            priority
            className="h-auto w-full"
          />
        </figure>
      </section>

      <section className="mt-20 grid grid-cols-2 gap-y-8 border-y border-line py-8 sm:grid-cols-4">
        {(
          [
            ["91", "checks, each with a test that keeps it silent on a hardened app"],
            ["3", "target kinds from one command"],
            ["6", "report formats including SARIF"],
            ["0", "accounts, agents, or dashboards"],
          ] as [string, string][]
        ).map(([n, label]) => (
          <div key={label} className="min-w-0 px-1">
            <div className="mono text-[30px] font-bold leading-none tracking-tight text-ink tabular-nums">{n}</div>
            <div className="mt-2.5 max-w-[22ch] text-[12.5px] leading-relaxed text-muted">{label}</div>
          </div>
        ))}
      </section>

      <section className="card mt-20 flex flex-col gap-4 rounded-md p-5 sm:flex-row sm:items-center sm:justify-between sm:p-6">
        <div className="mono shrink-0 text-[12px] font-medium uppercase tracking-[0.14em] text-faint">severity</div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          {legend.map(([label, swatch]) => (
            <span key={label} className="mono flex items-center gap-2 text-[12px] text-muted">
              <span aria-hidden className={"h-2.5 w-2.5 rounded-[2px] " + swatch} />
              {label}
            </span>
          ))}
        </div>
      </section>

      <section id="targets" className="mt-20 scroll-mt-24">
        <h2 className="mono text-[19px] font-bold tracking-tight text-ink sm:text-[24px]">
          One command. Three kinds of target.
        </h2>

        <div className="mt-9 grid grid-cols-1 gap-px overflow-hidden rounded-md border border-line bg-line md:grid-cols-3">
          {targets.map((t) => (
            <div key={t.kind} className="min-w-0 bg-panel p-5 sm:p-6">
              <div className="mono text-[13px] font-bold text-crit">{t.kind}</div>
              <div className="mono mt-3 overflow-x-auto whitespace-nowrap text-[12px] text-ink/85">
                <span className="text-ok">$ </span>
                {t.cmd}
              </div>
              <p className="mt-3.5 text-[13.5px] leading-relaxed text-muted">{t.body}</p>
            </div>
          ))}
        </div>

        <figure className="lift mt-5 overflow-hidden rounded-md">
          <Image
            src="/demo-apk-scan.svg"
            alt="fya scanning an Android APK in the terminal, listing manifest and DEX findings mapped to OWASP MASVS"
            width={1238}
            height={367}
            className="h-auto w-full"
          />
          <figcaption className="mono border-t border-line px-4 py-2.5 text-[11.5px] text-faint">
            An APK scan, captured from a real run.
          </figcaption>
        </figure>
      </section>

      <section className="mt-20">
        <h2 className="mono text-[19px] font-bold tracking-tight text-ink sm:text-[24px]">
          What happens after you hit enter.
        </h2>
        <div className="mt-8 max-w-3xl divide-y divide-line border-y border-line">
          {pipeline.map(([title, body]) => (
            <div key={title} className="grid grid-cols-1 gap-1 py-4 sm:grid-cols-[120px_1fr] sm:items-baseline sm:gap-6">
              <div className="mono text-[14px] font-semibold text-ink">{title}</div>
              <p className="mono text-[13.5px] leading-relaxed text-muted">{body}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="coverage" className="mt-20 scroll-mt-24">
        <h2 className="mono text-[19px] font-bold tracking-tight text-ink sm:text-[24px]">
          Every check maps to OWASP and a CWE.
        </h2>

        <div className="mt-9 grid grid-cols-1 gap-8 lg:grid-cols-3 lg:gap-10">
          {coverage.map(([group, count, rows]) => (
            <div key={group} className="min-w-0">
              <div className="mono flex items-baseline gap-3 border-b border-line-strong pb-2.5">
                <span className="text-[14px] font-bold text-ink">{group}</span>
                <span className="ml-auto text-[12px] text-crit tabular-nums">{count}</span>
              </div>
              <dl className="mt-4 space-y-4">
                {rows.map(([term, body]) => (
                  <div key={term} className="min-w-0">
                    <dt className="mono text-[12.5px] text-info">{term}</dt>
                    <dd className="mt-1 text-[13px] leading-relaxed text-muted">{body}</dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>

        <div className="mt-9 flex flex-wrap items-center gap-x-6 gap-y-3">
          <Link href="/docs#checks" className="mono text-[13px] text-crit hover:text-high">
            the full catalog, check by check &rarr;
          </Link>
          <a href="/sample-report.html" className="mono text-[13px] text-info hover:text-ink">
            open a real HTML report &rarr;
          </a>
        </div>
      </section>

      <section id="skill" className="card mt-20 scroll-mt-24 rounded-md p-6 sm:p-9">
        <h2 className="mono text-[19px] font-bold tracking-tight text-ink sm:text-[24px]">
          No terminal? Tell Claude to <span className="text-crit">break it.</span>
        </h2>
        <p className="mt-3.5 max-w-2xl text-[15px] leading-relaxed text-muted">
          fya ships as a Claude skill. Drop it into your setup and say what to scan. Claude confirms you own
          the target, runs the same non-destructive checks, and reports back in the chat with no package to install.
        </p>
        <div className="mt-8 grid grid-cols-1 gap-5 md:grid-cols-2">
          <div className="min-w-0">
            <div className="mono mb-2 text-[12px] text-faint">install</div>
            <CodeBlock
              label="shell"
              code={"git clone https://github.com/ayam04/fya\ncp -r fya/skills/fya ~/.claude/skills/fya"}
            />
          </div>
          <div className="min-w-0">
            <div className="mono mb-2 text-[12px] text-faint">ask</div>
            <CodeBlock
              label="claude"
              code={"scan http://localhost:3000 for vulnerabilities\ncheck ./app-release.apk for security issues"}
            />
          </div>
        </div>
        <Link href="/docs#skill" className="mono mt-6 inline-block text-[13px] text-crit hover:text-high">
          full skill setup in the docs &rarr;
        </Link>
      </section>

      <section className="mt-20">
        <h2 className="mono max-w-2xl text-balance text-[26px] font-bold leading-tight tracking-tight sm:text-[34px]">
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
        <div className="mt-10 max-w-2xl">
          <Callout tone="warn">
            Non-destructive by default. Localhost is fair game. Any remote target needs an explicit{" "}
            <code className="mono whitespace-nowrap rounded bg-white/10 px-1 text-[12px]">--i-am-authorized</code>{" "}
            flag. Test only what you own.
          </Callout>
        </div>
      </section>
    </div>
  )
}