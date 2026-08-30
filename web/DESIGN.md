# Design, fya web

<!-- impeccable:design-schema 1 -->

The site is a technical instrument, not a SaaS landing page. A security scanner
promises "I prove the vuln with the exact request and the receipt," so the
marketing surface proves itself the same way: the hero is fya's own captured
terminal output, not a rendering of it.

## Mode

Persuade (home), Read (docs, changelog). One visual world across all three.

## The load-bearing rule: show real output, never rebuild it

The single most important constraint on this site. The repo already contains
genuine Rich terminal captures of real scans, and those are what ship:

- `public/demo-web-scan.svg`, a full web scan of the bundled vulnerable app
- `public/demo-apk-scan.svg`, an APK scan
- `public/sample-report.html`, a real self-contained HTML report, linked from
  the coverage section

Do **not** hand-build a terminal, a findings table, or a product preview out of
`div` elements. A previous revision did exactly that, and it is the clearest
tell that a page was machine-generated: the fake report carried invented
per-check timings, an invented `v0.6.0` window chrome, and a tally that had to
be kept in sync with prose by hand. The real captures cost less code and are
the more persuasive asset.

When regenerating a capture, scan from a path that does not embed a home
directory, or redact the `target:` line afterwards. Rich writes each line as a
`text` element with an explicit `textLength`, so a redacted string must have
its `textLength` scaled by the same per-character advance or the text stretches.

## Type

- **Mono is the primary register.** `JetBrains Mono` (via `next/font`, exposed
  as `--font-jbmono`) carries structure, labels, data, headings, and commands.
  This is genuine report grammar, not monospace as costume. Applied with `.mono`.
- **System sans** (`--font-sans`) carries reading prose only.
- No display serif, no Space Grotesk, no Inter. Headings use tight tracking,
  never gradient text. Emphasis is weight and the crit hue.

## Color, a functional severity system rather than one accent

Ground is a flat, cool ink (`--color-bg #0a0c10`), surfaces `--color-panel`.
Text is a three-tier hierarchy, all at or above 4.5:1 on bg: `ink` 16:1,
`muted` 6.1:1, `faint` 4.9:1. Color is used the way a report uses it:

- `--color-crit #ff5555`, critical and high, and fya's brand hue
- `--color-high #ff7a5c`, the brighter crit ramp, only for `crit` link hover
- `--color-med #f0a63c`, medium. `--color-low #e6c94a`, low
- `--color-ok #55d38a`, pass and verified. `--color-info #58b4e6`, ids and links

Using a whole severity palette rather than one lone neon accent is what
structurally breaks the AI-default look. The palette is locked across the page.

## Surface rules

- **No glow, no blur orbs, no gradient-tinted cards, no pill CTAs.**
- **Elevation, one system per element:** `.card` is a hairline border with no
  shadow, `.lift` is one neutral shadow with no border. Never both.
- **Buttons:** primary is solid `ink` on dark, squared (`rounded-[3px]`);
  secondary is a hairline-bordered panel. Both mono, no glow.

## Banned patterns, all of which this page previously shipped

These are what made the old page read as generated. Do not reintroduce them:

- **Section-number eyebrows** (`01 Description`, `02 Claude skill`). Section
  headings are plain sentences now. Budget is at most one uppercase
  wide-tracking label per three sections, and the page currently uses zero.
- **Em-dashes**, anywhere a reader can see them, including page metadata and OG
  titles. Use a period, a comma, or a hyphen. The count is enforced at zero.
- **Middle-dot separator strips** (`flask/werkzeug · profile safe · 3.2s`).
- **Invented precision**: per-step timings, pass tallies, or any number not
  traceable to `README.md`, `CHANGELOG.md`, or a real capture. The four numbers
  in the stat band (91 checks, 3 targets, 6 formats, 0 accounts) are real.
- **A `border-t` hairline on every row** of a long list. The 13-row coverage
  table became three labelled clusters.
- **Repeating one layout family.** Eight sections currently use six distinct
  families: split hero, stat band, full-width statement, three-panel plus image
  band, numbered grid, cluster grid, and two card layouts.

## Motion

One authored moment: the hero prints in (`.reveal`, staggered
`animationDelay`, exponential ease-out from already-legible content). There are
no per-section scroll reveals.

A revision tried native scroll-driven reveals (`animation-timeline: view()`)
for section content. It shipped a bug worth recording: elements whose entry
range never completes stay stuck at `opacity: 0`, and in Chrome ten of thirteen
animated blocks became permanently invisible. Any animation that begins at
`opacity: 0` can hide real content, so section content must either not animate
or animate from a visible state. All motion respects `prefers-reduced-motion`.

## Responsive

The hero splits into two columns only at `xl`. Below that it stacks, because
the mono headline needs roughly 430px to stay on two lines and the `lg` left
column is narrower than that.

Every responsive grid declares an explicit `grid-cols-1` base so the mobile
single-column track caps at the viewport. Long mono strings live in
`overflow-x-auto` boxes or wrap with `break-words`, and flex children that
truncate carry `min-w-0`. Verified at 390px with no horizontal overflow.

## Not written

No `PRODUCT.md`. Product truth lives in the repo `README.md`, `CHANGELOG.md`,
and `docs/`, and every number on the site is traceable to one of them.
