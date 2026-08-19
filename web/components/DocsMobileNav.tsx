"use client"

import { useState } from "react"
import { List, X } from "@phosphor-icons/react"

export function DocsMobileNav({ items }: { items: string[][] }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="sticky top-14 z-40 -mx-4 mb-8 border-b border-line bg-bg/90 px-4 py-2.5 backdrop-blur sm:-mx-6 sm:px-6 lg:hidden">
      <div className="relative">
        <button
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          aria-controls="docs-mobile-menu"
          className="mono flex w-full cursor-pointer items-center justify-between border border-line bg-panel px-3.5 py-2.5 text-[13px] font-medium"
        >
          <span className="text-muted">on this page</span>
          {open ? (
            <X size={16} weight="bold" className="text-crit" />
          ) : (
            <List size={16} weight="bold" className="text-muted" />
          )}
        </button>
        {open && (
          <nav
            id="docs-mobile-menu"
            className="absolute inset-x-0 top-full z-50 mt-2 max-h-[60vh] overflow-y-auto border border-line bg-panel2 p-2 text-sm shadow-2xl shadow-black/60"
          >
            {items.map(([id, label]) => (
              <a
                key={id}
                href={`#${id}`}
                onClick={() => setOpen(false)}
                className="mono block px-3 py-2 text-[13px] text-muted transition-colors hover:bg-white/5 hover:text-ink"
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
