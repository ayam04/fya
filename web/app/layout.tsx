import type { Metadata, Viewport } from "next"
import { Bricolage_Grotesque, JetBrains_Mono } from "next/font/google"
import "./globals.css"
import { Nav } from "@/components/Nav"
import { Footer } from "@/components/Footer"
import { Analytics } from "@vercel/analytics/next"

// Display + body voice: Bricolage Grotesque (the only voice this page needs).
// Served as the full variable font so font-optical-sizing can pick the
// display cut for huge headlines instead of rendering them from the text cut.
// Evidence register: JetBrains Mono for commands, findings, ids, and labels.
const bricolage = Bricolage_Grotesque({
  subsets: ["latin"],
  variable: "--font-bricolage",
  display: "swap",
  weight: "variable",
})

const jbmono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jbmono",
  display: "swap",
  weight: ["400", "500", "600", "700"],
})

export const viewport: Viewport = {
  themeColor: "#0c0b0e",
  width: "device-width",
  initialScale: 1,
}

export const metadata: Metadata = {
  metadataBase: new URL("https://fya.ayamk.in"),
  title: {
    default: "fya, point it at your app and it tries to break it",
    template: "%s, fya",
  },
  description:
    "An open-source security scanner that attacks your web app, Android APK, or source code the way an adversary would. 91 OWASP-mapped checks across black, gray, and white box. Non-destructive, proven against a baseline, in your terminal or inside Claude.",
  keywords: [
    "security scanner",
    "DAST",
    "vulnerability scanner",
    "OWASP",
    "penetration testing",
    "APK security",
    "SAST",
    "CLI",
  ],
  authors: [{ name: "ayam04" }],
  alternates: { canonical: "/" },
  openGraph: {
    title: "fya, point it at your app and it tries to break it",
    description:
      "91 OWASP-mapped checks across black, gray, and white box. It finds the holes, proves them with the exact request, and hands you the fix.",
    url: "https://fya.ayamk.in",
    siteName: "fya",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "fya, point it at your app and it tries to break it",
    description: "A security scanner that finds the holes, proves them with the exact request, and hands you the fix.",
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${bricolage.variable} ${jbmono.variable}`}>
      <body>
        <Nav />
        <main>{children}</main>
        <Footer />
        <Analytics />
      </body>
    </html>
  )
}
