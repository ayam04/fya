"use client"

import { useState } from "react"
import { List, X } from "@phosphor-icons/react"

export function DocsMobileNav({ items }: { items: string[][] }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="sticky top-[76px] z-40 -mx-5 mb-8 border-b border-line bg-bg/85 px-5 py-2.5 backdrop-blur lg:hidden">
      <div className="relative">
        <button
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          aria-controls="docs-mobile-menu"
          className="flex w-full cursor-pointer items-center justify-between rounded-lg border border-line bg-surface/60 px-3.5 py-2.5 text-sm font-medium"
        >
          <span className="text-muted">On this page</span>
          {open ? (
            <X size={18} weight="bold" className="text-brand" />
          ) : (
            <List size={18} weight="bold" className="text-muted" />
          )}
        </button>
        {open && (
          <nav
            id="docs-mobile-menu"
            className="absolute inset-x-0 top-full z-50 mt-2 max-h-[60vh] overflow-y-auto rounded-lg border border-line bg-surface2 p-2 text-sm shadow-2xl shadow-black/60"
          >
            {items.map(([id, label]) => (
              <a
                key={id}
                href={`#${id}`}
                onClick={() => setOpen(false)}
                className="block rounded-md px-3 py-2 text-muted transition-colors hover:bg-white/5 hover:text-ink"
              >
                {label}
              </a>
            ))}
          </nav>
        )}
      </div>
    </div>
  )
}
