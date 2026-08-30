import Image from "next/image"
import Link from "next/link"
import type { ReactNode } from "react"
import { CodeBlock } from "@/components/CodeBlock"
import { Callout } from "@/components/Callout"
import { softwareApplication, faq } from "./structured-data.mjs"

// The Wanted register. This page is a poster that reads like a docket: the
// name says itself, the evidence ships in stamped plates, and every number is
// a real count from the docs catalog or a real capture. No invented precision.

function Stamp({ children, ok, tilt = -1 }: { children: ReactNode; ok?: boolean; tilt?: number }) {
  return (
    <span
      className={
        "mono inline-flex items-center gap-2 border bg-bg px-2.5 py-1 text-[10.5px] font-semibold uppercase " +
        "tracking-[0.18em] " +
        (ok ? "border-ok text-ok" : "border-[#ff4b5a] text-[#ff4b5a]")
      }
      style={{ transform: `rotate(${tilt}deg)` }}
    >
      <span
        aria-hidden
        className="inline-block h-[7px] w-[7px] bg-[#ff4b5a]"
        style={ok ? { background: "#3ddc84" } : undefined}
      />
      {children}
    </span>
  )
}

function Plate({
  fig,
  cap,
  src,
  alt,
  w,
  h,
}: {
  fig: string
  cap: string
  src: string
  alt: string
  w: number
  h: number
}) {
  return (
    <figure className="relative border border-line bg-panel">
      <span aria-hidden className="absolute -left-2.5 -top-2.5 h-5 w-5 border-l-2 border-t-2 border-[#ff4b5a]" />
      <span aria-hidden className="absolute -right-2.5 -top-2.5 h-5 w-5 border-r-2 border-t-2 border-[#ff4b5a]" />
      <span aria-hidden className="absolute -bottom-2.5 -left-2.5 h-5 w-5 border-b-2 border-l-2 border-[#ff4b5a]" />
      <span aria-hidden className="absolute -bottom-2.5 -right-2.5 h-5 w-5 border-b-2 border-r-2 border-[#ff4b5a]" />
      <div className="mono flex flex-wrap items-baseline gap-x-3 gap-y-1 border-b border-line px-4 py-2.5 text-[10.5px]">
        <span className="font-bold text-[#ff4b5a]">{fig}</span>
        <span className="text-faint">{cap}</span>
      </div>
      <Image src={src} alt={alt} width={w} height={h} priority className="h-auto w-full" />
    </figure>
  )
}

const targets = [
  {
    kind: "web",
    cmd: "fya scan http://localhost:3000",
    body: "Fuzzes inputs, walks the routes, probes access control. Injections proven by an arithmetic oracle.",
  },
  {
    kind: "apk",
    cmd: "fya scan app-release.apk",
    body: "Unpacks the manifest and the DEX. Exported providers, deep-link hijacking, v1 signing, debug certs.",
  },
  {
    kind: "source",
    cmd: "fya scan ./services",
    body: "Reads the code and the infrastructure. Hardcoded secrets, SQL by concatenation, weak IaC.",
  },
]

const pipeline: [string, string][] = [
  ["detect", "a server, an APK, or a source tree"],
  ["fingerprint", "the stack, from the first responses"],
  ["plan", "only the checks that fit the target"],
  ["break", "non-destructive probes, paced to what it tolerates"],
  ["prove", "dedup, OWASP and CWE, receipts kept"],
  ["report", "console, JSON, SARIF, Markdown, or HTML"],
]

const legend: [string, string][] = [
  ["crit / high", "#ff4b5a"],
  ["medium", "#f0a63c"],
  ["low", "#e6c94a"],
  ["pass", "#3ddc84"],
  ["note", "#5cc4f0"],
]

export default function Home() {
  return (
    <div className="mx-auto max-w-6xl px-5 sm:px-6">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(softwareApplication) }} />
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(faq) }} />

      {/* the poster */}
      <section className="relative overflow-hidden pb-24 pt-28">
        <div
          aria-hidden
          className="pointer-events-none absolute -right-16 -top-10 select-none whitespace-nowrap text-[34vw] font-extrabold leading-none tracking-[-0.06em] text-[#ff4b5a] opacity-[0.05]"
          style={{ transform: "rotate(-8deg)" }}
        >
          F***
        </div>

        <div className="relative">
          <Stamp>security scanner</Stamp>

          <h1 className="mt-7 text-[clamp(3.8rem,13vw,8.75rem)] font-extrabold leading-[0.9] tracking-[-0.05em]">
            f*** your
            <br />
            <span className="text-crit">app.</span>
          </h1>

          <p className="mono max-w-lg text-[13px] leading-[1.7] text-muted">
            POINT IT AT YOUR APP. IT TRIES TO BREAK IT.
            <br />
            THAT IS THE WHOLE THING.
          </p>

          <div className="mt-10 flex flex-wrap items-center gap-5">
            <Link
              href="/docs"
              className="bg-[#ff4b5a] px-6 py-3 text-[14px] font-bold text-bg transition-colors hover:bg-[#ff6b76]"
            >
              read the docs &rarr;
            </Link>
            <span className="mono text-[13.5px] text-ink">
              <span className="text-ok">$ </span>pip install fya
            </span>
          </div>

          <p className="mono mt-10 text-[11.5px] text-faint">
            non-destructive. receipts, not he-said.
          </p>
        </div>
      </section>

      {/* the docket: web scan, real output */}
      <section>
        <Stamp tilt={1.5}>caught on camera</Stamp>
        <div className="mono mt-4 text-[11px] uppercase tracking-[0.14em] text-faint">
          docket 001 / subject: a local flask app / plea: guilty, proven
        </div>
        <div className="mt-4">
          <Plate
            fig="EXHIBIT A"
            cap="a real scan of a real app. nothing staged."
            src="/demo-web-scan.svg"
            alt="fya web scan output: SQL injection, reflected XSS, SSRF to cloud metadata, exposed .git, CORS bypass, each mapped to a CWE and an OWASP category"
            w={1238}
            h={1221}
          />
        </div>
        <p className="mono mt-4 text-[11px] text-faint">
          real output from a real scan. every line above is fya talking, not the website.
        </p>
      </section>

      {/* the rap sheet */}
      <section className="mt-24">
        <div className="grid grid-cols-2 gap-x-8 gap-y-12 sm:grid-cols-4">
          {[
            ["91", "checks, each with a test that keeps it silent on a hardened app"],
            ["3", "target kinds from one command"],
            ["6", "report formats, sarif included"],
            ["0", "accounts, agents, or dashboards"],
          ].map(([n, label], i) => (
            <div key={label} className="border-l border-line pl-5">
              <div className={"text-[clamp(2.5rem,5vw,4rem)] font-extrabold leading-none tracking-[-0.04em] tabular-nums " + (i === 0 ? "text-crit" : "text-ink")}>
                {n}
              </div>
              <div className="mono mt-3 max-w-[24ch] text-[11.5px] leading-relaxed text-faint">{label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* wanted in three forms */}
      <section id="targets" className="mt-28 scroll-mt-24">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 className="text-[clamp(1.8rem,4vw,2.9rem)] font-extrabold tracking-[-0.03em]">
            Wanted in three forms.
          </h2>
          <span className="mono text-[11.5px] text-faint">one command, auto-detected</span>
        </div>

        <div className="mt-9 grid grid-cols-1 gap-0 md:grid-cols-3" style={{ borderTop: "1px solid var(--color-line)" }}>
          {targets.map((t) => (
            <div
              key={t.kind}
              className="border-b border-line px-6 py-7 md:border-r md:last:border-r-0"
            >
              <Stamp>#{t.kind}</Stamp>
              <div className="mono mt-5 break-words text-[12.5px] text-ink">
                <span className="text-ok">$ </span>
                {t.cmd}
              </div>
              <p className="mt-3 text-[13.5px] leading-relaxed text-muted">{t.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* the catalog */}
      <section id="coverage" className="mt-28 scroll-mt-24">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 className="text-[clamp(1.8rem,4vw,2.9rem)] font-extrabold tracking-[-0.03em]">
            The catalog. <span className="text-crit">91 felonies.</span>
          </h2>
          <span className="mono text-[11.5px] text-faint">every check maps to OWASP and a CWE</span>
        </div>

        <div className="mt-9 grid grid-cols-1 gap-x-14 gap-y-14 lg:grid-cols-3">
          <div>
            <div className="flex items-baseline gap-3 border-b-2 border-[#ff4b5a] pb-3">
              <span className="text-[15px] font-bold">web</span>
              <span className="mono ml-auto text-[12px] font-bold text-crit">{"45 checks"}</span>
            </div>
            <ul className="mt-5">
              {[
                ["injection", "Command injection, XXE, boolean-blind SQLi, SSTI, LFI wrappers, NoSQL operators."],
                ["exposure", "Actuators and heap dumps, phpinfo, the Werkzeug console, backup copies of live source."],
                ["secrets", "Keys in client JavaScript, source maps, dumpable .git, leaked config."],
              ].map(([term, body]) => (
                <li key={term} className="mb-5 list-none">
                  <span className="mono text-[11.5px] text-info">{term}</span>
                  <p className="mt-1 text-[12.5px] leading-relaxed text-muted">{body}</p>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <div className="flex items-baseline gap-3 border-b-2 border-[#ff4b5a] pb-3">
              <span className="text-[15px] font-bold">mobile and source</span>
              <span className="mono ml-auto text-[12px] font-bold text-crit">{"29 checks"}</span>
            </div>
            <ul className="mt-5">
              {[
                ["apk", "Network security config, exported providers, deep-link hijacking, v1 signing, debug certs."],
                ["whitebox", "Hardcoded secrets, committed key material, SQL by concatenation, verify disabled."],
                ["iac", "Dockerfile and Compose hardening, Kubernetes workloads, Terraform exposure, Actions."],
              ].map(([term, body]) => (
                <li key={term} className="mb-5 list-none">
                  <span className="mono text-[11.5px] text-info">{term}</span>
                  <p className="mt-1 text-[12.5px] leading-relaxed text-muted">{body}</p>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <div className="flex items-baseline gap-3 border-b-2 border-[#ff4b5a] pb-3">
              <span className="text-[15px] font-bold">api and transport</span>
              <span className="mono ml-auto text-[12px] font-bold text-crit">{"17 checks"}</span>
            </div>
            <ul className="mt-5">
              {[
                ["api", "OpenAPI and Swagger exposure, GraphQL introspection, OIDC discovery, SOAP and WSDL."],
                ["tls", "Certificate trust and expiry, weak protocols, key size, mixed content."],
                ["tools", "Nuclei, Nikto, nmap, sqlmap, and testssl folded into one report when installed."],
              ].map(([term, body]) => (
                <li key={term} className="mb-5 list-none">
                  <span className="mono text-[11.5px] text-info">{term}</span>
                  <p className="mt-1 text-[12.5px] leading-relaxed text-muted">{body}</p>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-x-3 gap-y-3">
          {legend.map(([label, hex]) => (
            <span key={label} className="mono inline-flex items-center gap-2 border border-line px-2.5 py-1.5 text-[10.5px] uppercase tracking-[0.12em] text-faint">
              <span aria-hidden className="inline-block h-2.5 w-2.5" style={{ background: hex }} />
              {label}
            </span>
          ))}
        </div>

        <div className="mt-8 flex flex-wrap gap-x-7 gap-y-3">
          <Link href="/docs#checks" className="mono text-[13px] text-crit hover:text-high">
            the full catalog, check by check &rarr;
          </Link>
          <a href="/sample-report.html" className="mono text-[13px] text-info hover:text-ink">
            open a real html report &rarr;
          </a>
        </div>
      </section>

      {/* apk docket */}
      <section className="mt-28">
        <Stamp tilt={-1.5}>apk, also wanted</Stamp>
        <div className="mt-4 grid max-w-4xl grid-cols-1 gap-8 lg:grid-cols-[1.1fr_1fr] lg:items-end lg:gap-12">
          <div className="order-2 lg:order-1">
            <h2 className="text-[clamp(1.8rem,4vw,2.9rem)] font-extrabold tracking-[-0.03em]">
              An APK is a target too.
            </h2>
            <p className="mt-4 max-w-md text-[14.5px] leading-relaxed text-muted">
              Manifest and DEX, no androguard required. Export surface, deep links, signing scheme, debug certs. Found
              on the spot, proven in the report.
            </p>
          </div>
          <div className="order-1 lg:order-2">
            <Plate
              fig="EXHIBIT B"
              cap="apk scan, captured from a real run."
              src="/demo-apk-scan.svg"
              alt="fya APK scan output: manifest and DEX findings mapped to OWASP MASVS"
              w={1238}
              h={367}
            />
          </div>
        </div>
      </section>

      {/* the sequence */}
      <section className="mt-28">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h2 className="text-[clamp(1.8rem,4vw,2.9rem)] font-extrabold tracking-[-0.03em]">The sequence.</h2>
          <span className="mono text-[11.5px] text-faint">six stages, self-throttled</span>
        </div>
        <div className="mt-8 max-w-3xl" style={{ borderTop: "1px solid var(--color-line)" }}>
          {pipeline.map(([v, d], i) => (
            <div
              key={v}
              className="grid grid-cols-[2.25rem_7rem_1fr] items-baseline gap-4 border-b border-line py-4 max-sm:grid-cols-[2rem_minmax(5rem,auto)_1fr]"
            >
              <span className={"mono text-[12px] " + (i === 3 ? "font-bold text-[#ff4b5a]" : "text-faint")}>
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className={"mono text-[13px] font-bold " + (i === 3 ? "text-crit" : "text-ink")}>{v}</span>
              <p className="mono text-[12.5px] leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* claude skill */}
      <section id="skill" className="mt-28 scroll-mt-24">
        <Stamp tilt={1}>no terminal? fine</Stamp>
        <h2 className="mt-6 max-w-2xl text-[clamp(1.8rem,4vw,2.9rem)] font-extrabold tracking-[-0.03em]">
          Tell Claude to <span className="text-crit">break it.</span>
        </h2>
        <p className="mt-4 max-w-2xl text-[14.5px] leading-relaxed text-muted">
          fya ships as a Claude skill. Drop it in, say what to scan, and Claude confirms you own the target, runs the
          same non-destructive checks, and reports back in the chat with no package to install.
        </p>
        <div className="mt-8 grid max-w-3xl grid-cols-1 gap-6 md:grid-cols-2">
          <div className="min-w-0">
            <div className="mono mb-2 text-[10.5px] uppercase tracking-[0.18em] text-faint">install</div>
            <CodeBlock
              label="shell"
              code={"git clone https://github.com/ayam04/fya\ncp -r fya/skills/fya ~/.claude/skills/fya"}
            />
          </div>
          <div className="min-w-0">
            <div className="mono mb-2 text-[10.5px] uppercase tracking-[0.18em] text-faint">ask</div>
            <CodeBlock
              label="claude"
              code={"scan http://localhost:3000 for vulnerabilities\ncheck ./app-release.apk for security issues"}
            />
          </div>
        </div>
        <Link href="/docs#skill" className="mono mt-7 inline-block text-[13px] text-crit hover:text-high">
          full skill setup in the docs &rarr;
        </Link>
      </section>

      {/* the close */}
      <section className="mt-28 pb-28">
        <Stamp ok tilt={0}>it is non-destructive, we checked</Stamp>
        <h2 className="mt-8 max-w-3xl text-[clamp(2.4rem,6.5vw,4.9rem)] font-extrabold leading-[0.95] tracking-[-0.04em]">
          Break your app before
          <br />
          <span className="text-crit">someone else does.</span>
        </h2>
        <p className="mono mt-6 max-w-md text-[12.5px] leading-[1.7] text-muted">
          start with your localhost right now. one command, a couple of seconds, receipts included. no accounts, no
          agents. just you, your terminal, and a stack of receipts.
        </p>
        <div className="mt-8 flex flex-wrap items-center gap-5">
          <Link
            href="/docs"
            className="bg-[#ff4b5a] px-6 py-3 text-[14px] font-bold text-bg transition-colors hover:bg-[#ff6b76]"
          >
            read the docs &rarr;
          </Link>
          <span className="mono text-[13.5px] text-ink">
            <span className="text-ok">$ </span>pip install fya
          </span>
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