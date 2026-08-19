import type { MetadataRoute } from "next"

export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/" },
    sitemap: "https://fya.ayamk.in/sitemap.xml",
    host: "https://fya.ayamk.in",
  }
}
