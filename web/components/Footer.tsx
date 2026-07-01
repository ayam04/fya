import { Mark } from "@/components/Mark"

export function Footer() {
  return (
    <footer className="border-t border-line">
      <div className="mx-auto flex max-w-5xl flex-col gap-3 px-5 py-10 text-sm text-muted sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <Mark size={18} className="rounded" />
          <span>fya. MIT licensed. Test only what you own or are authorized to test.</span>
        </div>
        <div className="flex gap-5">
          <a href="https://github.com/ayam04/fya" className="transition hover:text-ink">
            GitHub
          </a>
          <a href="https://pypi.org/project/fya/" className="transition hover:text-ink">
            PyPI
          </a>
          <a href="/docs" className="transition hover:text-ink">
            Docs
          </a>
        </div>
      </div>
    </footer>
  )
}
