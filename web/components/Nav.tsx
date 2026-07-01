import Link from "next/link"
import { Mark } from "@/components/Mark"

export function Nav() {
  return (
    <header className="fixed inset-x-0 top-0 z-50 px-4">
      <nav className="mx-auto mt-4 flex h-14 max-w-5xl items-center justify-between rounded-full border border-line bg-surface/70 pl-3 pr-2.5 backdrop-blur-xl">
        <Link href="/" className="flex items-center gap-2.5 pl-1">
          <Mark size={24} className="rounded-lg" />
          <span className="font-display text-[16px] font-semibold tracking-tight">
            fya<span className="text-brand">_</span>
          </span>
        </Link>
        <div className="flex items-center gap-1 text-[14px]">
          <Link href="/#skill" className="hidden rounded-full px-3.5 py-1.5 text-muted transition-colors hover:text-ink sm:block">
            Claude skill
          </Link>
          <Link href="/docs" className="rounded-full px-3.5 py-1.5 text-muted transition-colors hover:text-ink">
            Docs
          </Link>
          <a
            href="https://github.com/ayam04/fya"
            className="cursor-pointer rounded-full bg-white/[0.06] px-4 py-1.5 font-medium text-ink ring-1 ring-line transition hover:bg-white/[0.12]"
          >
            GitHub
          </a>
        </div>
      </nav>
    </header>
  )
}
