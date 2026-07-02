"use client"

import { useState } from "react"

export function CodeBlock({ code, className = "" }: { code: string; className?: string }) {
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
    <div className={"group relative overflow-hidden rounded-xl border border-line bg-[#0d0f13] " + className}>
      <button
        onClick={copy}
        aria-label="Copy to clipboard"
        className="absolute right-2 top-2 cursor-pointer rounded-md border border-line bg-surface/90 px-2 py-1 text-xs text-muted backdrop-blur transition hover:text-ink focus:opacity-100 sm:opacity-0 sm:group-hover:opacity-100"
      >
        {copied ? "copied" : "copy"}
      </button>
      <pre className="overflow-x-auto p-4 text-[13px] leading-relaxed text-ink/90">
        <code className="font-mono">{code}</code>
      </pre>
    </div>
  )
}
