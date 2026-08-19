import { ImageResponse } from "next/og"

export const alt = "fya — point it at your app, it tries to break it"
export const size = { width: 1200, height: 630 }
export const contentType = "image/png"

// Rendered in the report identity: masthead rule, the mark, severity chips.
// No external font fetch, so the build cannot fail on a network hiccup.
export default function OG() {
  const chip = (label: string, color: string) => ({
    display: "flex",
    alignItems: "center",
    border: `1px solid ${color}55`,
    background: `${color}1a`,
    color,
    fontSize: 26,
    fontWeight: 600,
    padding: "8px 16px",
    borderRadius: 4,
    letterSpacing: 1,
  })

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          background: "#0a0c10",
          color: "#e7e9ed",
          padding: 72,
          fontFamily: "monospace",
        }}
      >
        {/* masthead */}
        <div style={{ display: "flex", alignItems: "center", width: "100%", color: "#7a7f8a", fontSize: 24 }}>
          <span>FYA(1)</span>
          <div style={{ flex: 1, height: 1, background: "#333944", margin: "0 24px" }} />
          <span style={{ letterSpacing: 4 }}>SECURITY SCANNER MANUAL</span>
          <div style={{ flex: 1, height: 1, background: "#333944", margin: "0 24px" }} />
          <span>FYA(1)</span>
        </div>

        {/* name block */}
        <div style={{ display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", alignItems: "flex-end" }}>
            <span style={{ fontSize: 150, fontWeight: 800, letterSpacing: -4, lineHeight: 1 }}>fya</span>
            <span style={{ fontSize: 150, fontWeight: 800, color: "#ff5555", lineHeight: 1 }}>_</span>
          </div>
          <div style={{ display: "flex", fontSize: 44, marginTop: 24, color: "#e7e9ed" }}>
            point it at your app,{" "}
            <span style={{ color: "#ff5555", marginLeft: 12 }}>it tries to break it.</span>
          </div>
          <div style={{ display: "flex", fontSize: 28, marginTop: 20, color: "#8b909b", maxWidth: 900 }}>
            91 OWASP-mapped checks across black, gray, and white box. It finds the holes, proves them with the exact
            request, and hands you the fix.
          </div>
        </div>

        {/* severity chips + install */}
        <div style={{ display: "flex", alignItems: "center", width: "100%" }}>
          <div style={{ display: "flex", gap: 14 }}>
            <div style={chip("5 HIGH", "#ff5555")}>5 HIGH</div>
            <div style={chip("2 MED", "#f0a63c")}>2 MED</div>
            <div style={chip("91 CHECKS", "#58b4e6")}>91 CHECKS</div>
          </div>
          <div style={{ flex: 1 }} />
          <div
            style={{
              display: "flex",
              alignItems: "center",
              border: "1px solid #20242c",
              background: "#0f1217",
              color: "#e7e9ed",
              fontSize: 28,
              padding: "12px 20px",
              borderRadius: 4,
            }}
          >
            <span style={{ color: "#55d38a", marginRight: 12 }}>$</span> pip install fya
          </div>
        </div>
      </div>
    ),
    size,
  )
}
