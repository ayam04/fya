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
      <rect x="1.5" y="1.5" width="253" height="253" rx="55" fill="#0d1017" stroke="#232a36" strokeWidth="3" />
      <path
        d="M79 85 L138 128 L79 171"
        fill="none"
        stroke="#e8eef5"
        strokeWidth="23"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <rect x="154" y="95" width="28" height="72" rx="5" fill="#ff4d4d" />
    </svg>
  )
}
