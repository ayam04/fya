import type { MetadataRoute } from "next"

const base = "https://fya.ayamk.in"

export default function sitemap(): MetadataRoute.Sitemap {
  return ["", "/docs", "/changelog"].map((path) => ({
    url: base + path,
    changeFrequency: "weekly",
    priority: path === "" ? 1 : 0.8,
  }))
}
