import Link from "next/link"
import { Mark } from "@/components/Mark"

export function Nav() {
  return (
    <header className="sticky top-0 z-30 border-b border-line bg-white/80 backdrop-blur-md">
      <nav className="mx-auto flex h-16 max-w-5xl items-center justify-between px-5">
        <Link href="/" className="flex items-center gap-2.5">
          <Mark size={26} className="rounded-md" />
          <span className="text-[16px] font-semibold tracking-tight">
            fya<span className="text-brand">_</span>
          </span>
        </Link>
        <div className="flex items-center gap-0.5 text-[14px]">
          <Link href="/#overview" className="hidden rounded-md px-3 py-1.5 text-muted transition hover:bg-code hover:text-ink sm:block">
            Overview
          </Link>
          <Link href="/docs" className="rounded-md px-3 py-1.5 text-muted transition hover:bg-code hover:text-ink">
            Docs
          </Link>
          <a href="https://pypi.org/project/fya/" className="hidden rounded-md px-3 py-1.5 text-muted transition hover:bg-code hover:text-ink sm:block">
            PyPI
          </a>
          <a
            href="https://github.com/ayam04/fya"
            className="ml-1.5 rounded-md border border-line px-3.5 py-1.5 font-medium text-ink transition hover:border-ink/20 hover:bg-code"
          >
            GitHub
          </a>
        </div>
      </nav>
    </header>
  )
}
