import Link from "next/link"
import { Mark } from "@/components/Mark"

// hideOnMobile keeps the header from crowding at 390px; docs + changelog stay reachable there.
const links: [string, string, boolean][] = [
  ["/docs", "docs", false],
  ["/changelog", "changelog", false],
  ["/#skill", "claude skill", true],
]

export function Nav() {
  return (
    <header className="fixed inset-x-0 top-0 z-50 border-b border-line bg-bg/80 backdrop-blur-md">
      <nav className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4 sm:px-6">
        <Link href="/" className="group flex items-center gap-2.5" aria-label="fya home">
          <Mark size={22} className="rounded-[5px]" />
          <span className="mono text-[15px] font-semibold tracking-tight text-ink">
            fya<span className="text-crit">_</span>
          </span>
          <span className="mono hidden text-[11px] text-faint sm:inline">(1)</span>
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
