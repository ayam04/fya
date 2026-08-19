import { Mark } from "@/components/Mark"

const cols: [string, [string, string][]][] = [
  [
    "project",
    [
      ["github", "https://github.com/ayam04/fya"],
      ["pypi", "https://pypi.org/project/fya/"],
      ["releases", "https://github.com/ayam04/fya/releases"],
    ],
  ],
  [
    "read",
    [
      ["docs", "/docs"],
      ["changelog", "/changelog"],
      ["check catalog", "/docs#checks"],
    ],
  ],
]

export function Footer() {
  return (
    <footer className="mt-24 border-t border-line">
      <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6">
        {/* man-page footer line: LEFT .... name version · date .... RIGHT */}
        <div className="mono mb-10 hidden items-center gap-4 text-[12px] text-faint sm:flex">
          <span className="text-muted">FYA(1)</span>
          <span className="h-px flex-1 bg-line" />
          <span>fya 0.6.0 · 2026-08-18</span>
          <span className="h-px flex-1 bg-line" />
          <span className="text-muted">FYA(1)</span>
        </div>

        <div className="flex flex-col justify-between gap-10 sm:flex-row">
          <div className="max-w-xs">
            <div className="flex items-center gap-2.5">
              <Mark size={20} className="rounded-[5px]" />
              <span className="mono text-[14px] font-semibold text-ink">
                fya<span className="text-crit">_</span>
              </span>
            </div>
            <p className="mt-3 text-[13px] leading-relaxed text-muted">
              A security scanner that breaks your app before someone else does. Test only what you own or are
              authorized to test.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-x-14 gap-y-6">
            {cols.map(([title, items]) => (
              <div key={title}>
                <div className="mono mb-3 text-[11px] uppercase tracking-[0.16em] text-faint">{title}</div>
                <ul className="mono space-y-2 text-[13px]">
                  {items.map(([label, href]) => (
                    <li key={label}>
                      <a href={href} className="text-muted transition-colors hover:text-ink">
                        {label}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>

        <div className="mono mt-12 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line pt-6 text-[12px] text-faint">
          <span>© {new Date().getFullYear()} ayam04</span>
          <span aria-hidden>·</span>
          <span>PolyForm Noncommercial 1.0.0 — commercial use requires a license</span>
        </div>
      </div>
    </footer>
  )
}
