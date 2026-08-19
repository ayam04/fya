import type { Metadata, Viewport } from "next"
import { JetBrains_Mono } from "next/font/google"
import "./globals.css"
import { Nav } from "@/components/Nav"
import { Footer } from "@/components/Footer"
import { Analytics } from "@vercel/analytics/next"

const jbmono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jbmono",
  display: "swap",
  weight: ["400", "500", "600", "700"],
})

export const viewport: Viewport = {
  themeColor: "#0a0c10",
  width: "device-width",
  initialScale: 1,
}

export const metadata: Metadata = {
  metadataBase: new URL("https://fya.ayamk.in"),
  title: {
    default: "fya — point it at your app, it tries to break it",
    template: "%s — fya",
  },
  description:
    "An open-source security scanner that attacks your web app, Android APK, or source code the way an adversary would. 91 OWASP-mapped checks across black, gray, and white box — non-destructive, proven against a baseline, in your terminal or inside Claude.",
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
    title: "fya — point it at your app, it tries to break it",
    description:
      "91 OWASP-mapped checks across black, gray, and white box. It finds the holes, proves them with the exact request, and hands you the fix.",
    url: "https://fya.ayamk.in",
    siteName: "fya",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "fya — point it at your app, it tries to break it",
    description: "A security scanner that finds the holes, proves them with the exact request, and hands you the fix.",
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={jbmono.variable}>
      <body>
        <Nav />
        <main>{children}</main>
        <Footer />
        <Analytics />
      </body>
    </html>
  )
}
