# Design — fya web

<!-- impeccable:design-schema 1 -->

The site is rendered as **fya's own output**: a scan report crossed with a Unix
man page. A security scanner's promise is "I prove the vuln with the exact
request and the receipt," so the marketing surface proves itself the same way —
a technical instrument, not a SaaS landing page. This deliberately refuses the
near-black + single-neon-glow + Space-Grotesk hero the category ships by default.

## Mode

Persuade (home), Read (docs, changelog). One visual world across all three.

## Type

- **Mono is the primary register.** `JetBrains Mono` (via `next/font`, exposed as
  `--font-jbmono`) carries all structure, labels, data, headings, commands, and
  finding evidence — this is genuine report/manual grammar (code and measurement),
  not monospace-as-costume. Applied with the `.mono` utility.
- **System sans** (`--font-sans`, `ui-sans-serif` stack) carries long reading
  prose only, for comfort. It is the honest body face for a tool that runs in
  your OS.
- No display serif, no Space Grotesk, no Inter. Tracking floor -0.04em; headings
  use tight tracking, never gradient text — emphasis is weight and the crit hue.

## Color — a functional severity SYSTEM, not one accent

Ground is a flat, cool ink (`--color-bg #0a0c10`), surfaces `--color-panel`.
Text is a three-tier hierarchy, all ≥4.5:1 on bg: `ink` 16:1, `muted` 6.1:1,
`faint` 4.9:1. Color is used the way a report uses it:

- `--color-crit #ff5555` — critical/high, and fya's brand hue
- `--color-high #ff7a5c` — the brighter crit ramp, used only for `crit` link/emphasis hover
- `--color-med #f0a63c` — medium · `--color-low #e6c94a` — low
- `--color-ok #55d38a` — pass/verified · `--color-info #58b4e6` — info/id/link

Using a whole severity palette (not one lone neon accent) is what structurally
breaks the AI-default look. Reserve `crit` red for critical findings, brand, and
primary emphasis; amber for caution (authorization warnings); cyan for check ids
and links; green for pass/fix.

## Surface rules

- **No glow, no blur orbs, no gradient-tinted cards, no pill CTAs.** These were
  the incumbent tells and are banned.
- **Elevation, one system per element:** `.card` = hairline border, no shadow;
  `.lift` = one neutral (uncolored) shadow, no border. Never both. Card radii
  12–16px (`rounded-md`); pills only for nothing.
- **Man-page furniture:** masthead rules (`FYA(1) —— TITLE —— FYA(1)`), numbered
  sections, hairline `.rule` dividers, bracketed/mono terminal actions.
- **Buttons:** primary = solid `ink` on dark, squared (`rounded-[3px]`);
  secondary = hairline-bordered panel. Both mono, no glow.
- **Motion:** one authored moment — the hero report "prints in" (`.reveal`,
  staggered `animationDelay`, exponential ease-out from already-legible content).
  No per-section scroll reveals. All motion respects `prefers-reduced-motion`.

## Responsive

Every responsive grid declares an explicit `grid-cols-1` base (Tailwind's
`minmax(0,1fr)`) so the mobile single-column track caps at the viewport — an
arbitrary `lg:grid-cols-[…]` alone leaves an implicit `auto` column that
overflows. Long mono strings live in `overflow-x-auto` boxes or wrap with
`break-words`; flex children that truncate carry `min-w-0`.

## Not written

No `PRODUCT.md` — product truth lives in the repo `README.md` and `docs/`, and
adding a product record to the Python package root was out of scope for this
web redesign.
