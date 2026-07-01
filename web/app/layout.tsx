import type { Metadata } from "next"
import "./globals.css"
import { Nav } from "@/components/Nav"
import { Footer } from "@/components/Footer"

export const metadata: Metadata = {
  title: "fya - point it at your app, it tries to break it",
  description:
    "An open-source dynamic security scanner for localhost servers and Android APKs. 36 OWASP-mapped checks, authenticated scans, scan modes, CI baselines, and SARIF reports.",
  metadataBase: new URL("https://github.com/ayam04/fya"),
  openGraph: {
    title: "fya",
    description: "Point it at your app. It tries to break it.",
    type: "website",
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Nav />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  )
}
