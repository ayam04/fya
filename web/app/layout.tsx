import type { Metadata, Viewport } from "next"
import { Inter, Space_Grotesk } from "next/font/google"
import "./globals.css"
import { Nav } from "@/components/Nav"
import { Footer } from "@/components/Footer"

const inter = Inter({ subsets: ["latin"], variable: "--font-inter", display: "swap" })
const grotesk = Space_Grotesk({ subsets: ["latin"], variable: "--font-grotesk", display: "swap" })

export const viewport: Viewport = {
  themeColor: "#0a0b0d",
}

export const metadata: Metadata = {
  title: "fya - point it at your app, it tries to break it",
  description:
    "An open-source security scanner that hunts your web app or Android APK the way an attacker would. 36 OWASP-mapped checks, non-destructive, runs in your terminal or inside Claude.",
  metadataBase: new URL("https://github.com/ayam04/fya"),
  openGraph: {
    title: "fya",
    description: "Point it at your app. It tries to break it.",
    type: "website",
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${grotesk.variable}`}>
      <body>
        <Nav />
        <main>{children}</main>
        <Footer />
      </body>
    </html>
  )
}
