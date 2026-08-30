// Structured data for search engines and answer engines (AEO).
//
// This is the single source of truth for the site's JSON-LD. Keeping it in a
// plain .mjs module (instead of inline JSON in page.tsx) lets the test suite
// import it in-process and verify it stays consistent with the docs catalog,
// so it cannot drift stale the way the old "58 checks" count did.
//
// Every fact below is traceable to the repo README.md, CHANGELOG.md, or the
// docs site. No invented numbers, ratings, or entities.

export const softwareApplication = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "fya",
  alternateName: "fya security scanner",
  version: "0.6.0",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Linux, macOS, Windows",
  description:
    "An open-source dynamic security scanner for web apps, Android APKs, and source trees. Runs non-destructive probes, maps findings to the OWASP Top 10 or OWASP Mobile Application Security Verification Standard and to CWEs, and proves each finding with the exact request that triggered it. 91 checks, one command, no accounts or dashboards.",
  url: "https://fya.ayamk.in",
  downloadUrl: "https://pypi.org/project/fya/",
  installCommand: "pip install fya",
  featureList: [
    "91 OWASP-mapped checks across black, gray, and white box testing",
    "Web app, Android APK, and source-tree targets with automatic detection",
    "Non-destructive active probing with passive, safe, and aggressive profiles",
    "JSON, SARIF, Markdown, HTML, and console report formats",
    "Authenticated and scoped scans, baselines for CI gating",
    "Claude skill shipped with no package install required",
  ],
  offers: {
    "@type": "Offer",
    price: "0",
    priceCurrency: "USD",
    description:
      "Free for noncommercial and personal use under the PolyForm Noncommercial License 1.0.0. Commercial use requires a paid license.",
  },
  author: {
    "@type": "Person",
    name: "ayam04",
    url: "https://github.com/ayam04/fya",
  },
  sameAs: [
    "https://github.com/ayam04/fya",
    "https://pypi.org/project/fya/",
    "https://fya.ayamk.in/docs",
  ],
}

export const faq = {
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: [
    {
      "@type": "Question",
      name: "What is fya?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "fya is an open-source security scanner for web apps, Android APKs, and source trees. It runs non-destructive probes, maps every finding to the OWASP Top 10 or OWASP MASVS and to a CWE, and proves each finding with the exact request that triggered it, so nothing is reported without evidence.",
      },
    },
    {
      "@type": "Question",
      name: "What does fya scan?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Three kinds of target from one command: a web server, an Android APK, or a source directory. fya detects the target automatically, then runs only the checks that apply to it, tuned to the selected profile and mode.",
      },
    },
    {
      "@type": "Question",
      name: "Is fya non-destructive?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Yes. Scans never flood a target or send denial-of-service payloads. Request pacing adapts automatically and slows down on errors and timeouts, and active probes are gated behind the safe and aggressive profiles.",
      },
    },
    {
      "@type": "Question",
      name: "Is fya free to use?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Free for noncommercial and personal use under the PolyForm Noncommercial License 1.0.0, which covers hobby projects, research, education, and nonprofit or government use. Using fya in a for-profit company's products or internal operations requires a paid license.",
      },
    },
    {
      "@type": "Question",
      name: "How do I install fya and run a scan?",
      acceptedAnswer: {
        "@type": "Answer",
        text: "Install with pip install fya. Then scan a web server with fya scan http://localhost:8000, an Android APK with fya scan ./app-release.apk, or a source tree with fya scan ./services. Localhost needs no authorization flag; any remote target requires --i-am-authorized.",
      },
    },
  ],
}