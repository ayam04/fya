"use client"

import { useState } from "react"

export function CodeBlock({
  code,
  label,
  className = "",
}: {
  code: string
  label?: string
  className?: string
}) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className={"group relative border border-line bg-panel " + className}>
      <div className="flex items-center justify-between border-b border-line px-3 py-1.5">
        <span className="mono text-[11px] text-faint">{label ?? "shell"}</span>
        <button
          onClick={copy}
          aria-label="Copy to clipboard"
          className="mono cursor-pointer text-[11px] text-faint transition-colors hover:text-ink focus:text-ink"
        >
          {copied ? (
            <span className="text-ok">copied ✓</span>
          ) : (
            "copy"
          )}
        </button>
      </div>
      <pre className="mono overflow-x-auto px-3 py-3 text-[13px] leading-relaxed text-ink/90">
        <code>{code}</code>
      </pre>
    </div>
  )
}
