export function Callout({
  children,
  tone = "warn",
}: {
  children: React.ReactNode
  tone?: "warn" | "note"
}) {
  const label = tone === "warn" ? "CAUTION" : "NOTE"
  const chip =
    tone === "warn"
      ? "bg-med/15 text-med border-med/30"
      : "bg-info/15 text-info border-info/30"

  return (
    <div className="card flex gap-3.5 p-4">
      <span
        className={
          "mono mt-0.5 h-fit shrink-0 border px-1.5 py-0.5 text-[10px] font-semibold tracking-[0.14em] " + chip
        }
      >
        {label}
      </span>
      <div className="text-[13.5px] leading-relaxed text-ink/85">{children}</div>
    </div>
  )
}
