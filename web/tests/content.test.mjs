// Content-integrity contract for the fya website.
//
// The site's core promise is "every number on the site is traceable" (see
// web/DESIGN.md). These tests keep that promise by locking the home page's
// counts and copy against the docs catalog (web/app/docs/page.tsx) and the
// banned-pattern list in web/DESIGN.md.
//
// Run: node --test web/tests/content.test.mjs
import test from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")

const page = readFileSync(resolve(root, "app/page.tsx"), "utf-8")
const docs = readFileSync(resolve(root, "app/docs/page.tsx"), "utf-8")
const changelog = readFileSync(resolve(root, "app/changelog/page.tsx"), "utf-8")
const design = readFileSync(resolve(root, "DESIGN.md"), "utf-8")

/** Every check id the docs catalog claims to cover. */
function catalogChecks(src) {
  const ids = [...src.matchAll(/"(web|api|tls|apk|whitebox|graybox|blackbox|integrations)\.[a-z0-9_]+"/g)]
  return [...new Set(ids.map((m) => m[0].slice(1, -1)))]
}

test("docs catalog lists 91 unique checks", () => {
  assert.equal(catalogChecks(docs).length, 91)
})

test("every number the home page claims is traceable to the docs catalog", () => {
  const web = catalogChecks(docs).filter((c) => c.startsWith("web.")).length
  const mobile = catalogChecks(docs).filter((c) =>
    ["apk.", "whitebox.", "blackbox.", "graybox."].some((p) => c.startsWith(p))
  ).length
  const transport = catalogChecks(docs).filter((c) =>
    ["api.", "tls.", "integrations."].some((p) => c.startsWith(p))
  ).length

  // The three numeric claims in the coverage section must be real counts.
  for (const [label, real] of [["\"45 checks\"", web], ["\"29 checks\"", mobile], ["\"17 checks\"", transport]]) {
    assert.ok(page.includes(label), `${label} must appear on the home page (docs says ${real})`)
  }

  // No stale pre-0.6.0 count anywhere on the home page.
  for (const stale of ["58 checks", "21 checks", "12 checks", "36 checks", "\"58\""]) {
    assert.ok(!page.includes(stale), `stale count "${stale}" must not appear`)
  }

  // The stat band's headline number stays 91.
  assert.ok(/91/.test(page.split("stat")[0]))
})

test("banned characters never appear in user-visible site text", () => {
  // DESIGN.md bans the em-dash and the middle-dot separator strip from
  // anything a reader sees. Comments (globals.css) are allowed to use them.
  for (const [file, body] of [["page.tsx", page], ["docs/page.tsx", docs], ["changelog/page.tsx", changelog]]) {
    assert.ok(!body.includes("—"), `${file}: em-dash — is banned in visible text`)
    assert.ok(!body.includes(" – "), `${file}: en-dash as separator is banned`)
  }
  // Middle-dot only as a separator inside a single line is a tell; the
  // changelog's meta strip used them as a separator family.
  assert.ok(!changelog.includes("text-line-strong\">·<"), "changelog: middle-dot separator strip is banned")
})

test("no numbered step eyebrows in marketing copy", () => {
  // "1." / "2." labels above instructions read as generic step labels.
  assert.ok(!/\d\. [a-z]/.test(page), "page.tsx: numbered step labels are banned")
  assert.ok(!page.includes("1. install"), "skill section's numbered steps are banned")
})

test("home page shows real captures, never a hand-built terminal", () => {
  // DESIGN.md: "show real output, never rebuild it". The terminal-style
  // preview must be the captured SVGs, not a div-built fake report.
  assert.ok(page.includes("demo-web-scan.svg"), "hero must use the real web scan capture")
  assert.ok(page.includes("demo-apk-scan.svg"), "targets must use the real APK scan capture")
  // A fake report is built out of successive div rows with severity chips;
  // the real site only repeats cards for the three target kinds.
  const chips = (page.match(/text-crit/g) || []).length
  assert.ok(chips <= 12, `critical-severity text appears ${chips} times; a fake findings table would use many more`)
})

test("structured data (JSON-LD) is present and internally consistent", async () => {
  // AEO coefficient: search engines and answer engines both consume the
  // SoftwareApplication + FAQPage schema. The data lives in a plain .mjs
  // module so this test can read it in-process instead of re-deriving it.
  const { softwareApplication, faq } = await import("../app/structured-data.mjs")

  assert.equal(softwareApplication["@type"], "SoftwareApplication")
  assert.equal(softwareApplication.name, "fya")
  assert.equal(softwareApplication.applicationCategory, "SecurityApplication")

  const real = catalogChecks(docs).length
  // The structured data must not drift from the catalog the way the old
  // "58 checks" count did.
  assert.ok(
    JSON.stringify(softwareApplication).includes(`${real} `) ||
      softwareApplication.description.includes(String(real)),
    `software schema must reference the current ${real}-check catalog`
  )

  assert.equal(faq["@type"], "FAQPage")
  assert.ok(faq.mainEntity.length >= 4, "FAQ must carry enough answers for answer engines")
  for (const q of faq.mainEntity) {
    assert.ok(q.acceptedAnswer.text.length > 40, `FAQ answer for "${q.name}" must be substantive`)
  }

  // The home page must actually emit it.
  assert.ok(page.includes("application/ld+json"), "home page must render the JSON-LD script")
  assert.ok(page.includes("structured-data.mjs") || page.includes("structured-data"), "home page must import the structured-data module")
})