export function Callout({
  children,
  tone = "warn",
}: {
  children: React.ReactNode
  tone?: "warn" | "note"
}) {
  const box = tone === "warn" ? "border-brand/25 bg-brand/[0.05]" : "border-line bg-code"
  const badge = tone === "warn" ? "bg-brand text-white" : "bg-ink text-white"
  const glyph = tone === "warn" ? "!" : "i"
  return (
    <div className={"flex gap-3 rounded-lg border p-4 " + box}>
      <span className={"mt-px flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[11px] font-bold " + badge}>
        {glyph}
      </span>
      <div className="text-sm leading-relaxed text-ink/90">{children}</div>
    </div>
  )
}
