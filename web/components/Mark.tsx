export function Mark({ size = 28, className = "" }: { size?: number; className?: string }) {
  return (
    <svg
      viewBox="0 0 256 256"
      width={size}
      height={size}
      className={className}
      role="img"
      aria-label="fya"
    >
      <rect x="1.5" y="1.5" width="253" height="253" rx="52" fill="#0f1217" stroke="#20242c" strokeWidth="3" />
      <path
        d="M79 85 L138 128 L79 171"
        fill="none"
        stroke="#e7e9ed"
        strokeWidth="23"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <rect x="154" y="95" width="28" height="72" rx="5" fill="#ff5555" />
    </svg>
  )
}
