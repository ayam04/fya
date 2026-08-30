import Link from "next/link"

// Top bar in the Wanted register: a wordmark with a red period, mono links,
// and a github chip. Fixed so long pages stay navigable.
const links: [string, string, boolean][] = [
  ["/docs", "docs", false],
  ["/changelog", "changelog", false],
  ["/#skill", "claude skill", true],
]

export function Nav() {
  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-line bg-bg/85 backdrop-blur-md">
      <nav className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4 sm:px-6">
        <Link href="/" className="group flex items-baseline gap-2" aria-label="fya home">
          <span className="text-[19px] font-extrabold leading-none tracking-tight text-ink">
            fya<span className="text-crit">.</span>
          </span>
          <span className="mono hidden text-[11px] text-faint sm:inline">wanted, not missing</span>
        </Link>

        <div className="mono flex items-center gap-0.5 text-[13px] sm:gap-1">
          {links.map(([href, label, hide]) => (
            <Link
              key={href}
              href={href}
              className={
                "px-2.5 py-1.5 text-muted transition-colors hover:text-ink sm:px-3 " +
                (hide ? "hidden sm:block" : "")
              }
            >
              {label}
            </Link>
          ))}
          <a
            href="https://github.com/ayam04/fya"
            className="ml-1 flex items-center gap-1.5 border border-line bg-panel px-2.5 py-1.5 text-ink transition-colors hover:border-line-strong sm:px-3"
          >
            <span className="text-faint">$</span> github
          </a>
        </div>
      </nav>
    </header>
  )
}