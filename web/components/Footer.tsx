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
      <div className="mx-auto max-w-6xl px-4 py-14 sm:px-6">
        <div className="flex flex-col justify-between gap-10 sm:flex-row">
          <div className="max-w-xs">
            <div className="flex items-baseline gap-2">
              <span className="text-[18px] font-extrabold tracking-tight text-ink">
                fya<span className="text-crit">.</span>
              </span>
              <span className="mono text-[11px] text-faint">f*** your app</span>
            </div>
            <p className="mt-4 text-[13.5px] leading-relaxed text-muted">
              A security scanner that breaks your app before someone else does. Non-destructive, receipted, and it only
              targets what you own or are authorized to test.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-x-16 gap-y-8">
            {cols.map(([title, items]) => (
              <div key={title}>
                <div className="mono mb-3 text-[10.5px] uppercase tracking-[0.2em] text-faint">{title}</div>
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
          <span>PolyForm Noncommercial 1.0.0. Commercial use requires a license.</span>
        </div>
      </div>
    </footer>
  )
}