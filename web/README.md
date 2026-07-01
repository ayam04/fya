# fya website

Overview and documentation site for [fya](https://github.com/ayam04/fya), built
with Next.js (App Router) and Tailwind CSS v4.

## Develop

```bash
npm install
npm run dev        # http://localhost:3000
```

## Build

```bash
npm run build
```

## Deploy on Vercel (from this repo)

Import the `ayam04/fya` repository in Vercel and set:

- Framework preset: Next.js
- Root Directory: `web`

No environment variables are required. Every push to the repo will build and
deploy this folder.
