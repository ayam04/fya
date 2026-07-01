import Link from "next/link"

export function Nav() {
  return (
    <header className="sticky top-0 z-30 border-b border-line bg-white/85 backdrop-blur">
      <nav className="mx-auto flex h-16 max-w-6xl items-center justify-between px-5">
        <Link href="/" className="flex items-center gap-2.5">
          <img src="/icon.svg" alt="" width={28} height={28} className="rounded-md" />
          <span className="text-[17px] font-semibold tracking-tight">
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
            className="ml-1.5 rounded-md bg-ink px-3.5 py-1.5 text-white transition hover:bg-black"
          >
            GitHub
          </a>
        </div>
      </nav>
    </header>
  )
}
