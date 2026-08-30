# Design, fya web

<!-- impeccable:design-schema 1 -->

The site is a poster that reads like a docket. Product truth in `PRODUCT.md`;
design lives here. This file replaces the pre-0.7 "report / man page" world:
that register read as AI-generated devtool sobriety and buried the product's
actual personality. Product truth (real output, traceable numbers, severity
colors) carried over; the visual world was rebuilt and confirmed with the user.

## Mode

Persuade (home), Read (docs, changelog). One visual world across all three.

## The load-bearing rule: show real output, never rebuild it

Unchanged from previous worlds and still the most important constraint. The
repo contains genuine Rich captures of real scans and those are what ship:

- `public/demo-web-scan.svg`, a full web scan of the bundled vulnerable app
- `public/demo-apk-scan.svg`, an APK scan
- `public/sample-report.html`, a real self-contained HTML report, linked from
  the coverage section

Never hand-build a terminal, findings table, or product preview out of `div`s.
The docket `<figure>` plates show the captures at full fidelity, framed with
corner brackets and a stamp.

## Voice: unleashing the name

The product is called fya, short for "F\*\*\* Your App". The home page says the
name in monumental type (`f*** your app.`) and the copy stays confident and
wry, never corporate. This was confirmed with the user (2026-08-30): the
irreverence is the brand, and it still signs receipts. Every wry line is still
factually true and every number still traceable.

## Type

- **Display and body: `Bricolage Grotesque`** (via `next/font`, exposed as
  `--font-bricolage`, mapped as `--font-sans`). Weights 400 and 500 for body
  prose, 700 and 800 for statements. The only face with a voice.
- **Evidence register: `JetBrains Mono`** (`--font-jbmono`, applied with
  `.mono`) carries commands, findings, CWE/OWASP ids, stamps, telemetry, and
  labels. This is genuine report grammar, not costume.
- No display serif, no Space Grotesk, no Inter, no gradients on type. Emphasis
  is weight and the crit hue.

## Color, a functional severity system rather than one accent

Ground is warm near-black (`--color-bg #0c0b0e`, a slight violet cast).
Text is a three-tier hierarchy at or above 4.5:1 on bg: `ink` 16:1, `muted`
~7:1, `faint` ~5:1. Severity colors, used the way a report uses them:

- `--color-crit #ff4b5a`, critical and high, and the brand
- `--color-high #ff7a5c` (the brighter crit ramp, for hover)
- `--color-med #f0a63c` medium, `--color-low #e6c94a` low
- `--color-ok #3ddc84` pass/verified, `--color-info #5cc4f0` ids and links

The stamps and corner brackets are drawn in the crit hue. No accent escapes the
severity system.

## Surface rules

- **Stamps.** A bordered mono label with a square slug and a slight rotation
  (`-1deg` to `2deg`) marks a section or docket: "security scanner", "caught on
  camera", "#web". The poster's ink-and-paper device.
- **Plates.** Evidence figures carry four corner brackets in crit, a `mono`
  header row (`EXHIBIT A` + caption), and the real capture. Never both a border
  box and a shadow (elevation stays `.card` hairline or `.lift` shadow).
- **Air.** Sections are separated by generous margin, horizontal rules, and a
  left hairline on stat ledgers. The page has very few boxes; a bordered panel
  must earn its border.
- **No glow, no blur orbs, no gradient-tinted cards, no pill CTAs.** Primary
  CTA is a solid crit rectangle with squared corners; hover brightens it.
- The `#ff4b5a` literal in stamps and brackets is deliberately not `text-crit`
  everywhere: repeated red-swatch devices use the literal so a future "no fake
  findings table" detector (which counts `text-crit`) stays meaningful.

## Banned patterns

- **Em-dashes**, anywhere a reader can see them, including metadata and OG
  titles. Also banned: en-dash as a separator. Enforced at zero by tests.
- **Middle-dot separator strips** (three-plus items joined by `·`).
- **Numbered step eyebrows in marketing copy** (`01 Description`). One
  exception: the docs (Read mode) keep man-page section numbers (`01` through
  `14`), which are native to a manual, and numbering there is allowed.
- **Invented precision**: timings, pass tallies, ratings, or any number not
  traceable to `README.md`, `CHANGELOG.md`, the docs catalog, or a real
  capture. The site's real numbers: 91 checks, 3 targets, 6 report formats,
  0 accounts; 45 / 29 / 17 per coverage group.
- **A `border-b` hairline under every row** of a long list without a reason.
  Long ledgers (pipeline, targets) use one shared rule family.
- **Repeating one layout family.** Sections alternate poster, stamp + docket,
  stat ledger, triptych, catalog, split hero, sequence, skill, close.

## Motion

One authored moment: the hero bangs in (`.reveal`, staggered delay,
exponential ease-out from already-legible content). No per-section scroll
reveals; anything that begins at `opacity: 0` can hide real content. All motion
respects `prefers-reduced-motion`.

## Responsive

The hero poster is unconstrained (monumental type clips gracefully inside the
section's `overflow-hidden`). Two-column layouts collapse at `lg`/`md`;
the sequence grid collapses at `sm`. Long mono strings live in
`overflow-x-auto` or `break-words` boxes (CodeBlock scrolls). Verified at
390px with no horizontal overflow.

## Files

- `PRODUCT.md` holds product truth (users, positioning, brand commitments,
  evidence on hand).
- This file holds durable design rules. Numbers and copy must stay traceable to
  the repo `README.md`, `CHANGELOG.md`, and `docs/`.