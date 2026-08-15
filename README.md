# upg.gr

Marketing site for **UPGRADE** (Zakynthos) — built with [Astro](https://astro.build),
deployed as static files to **Cloudflare Pages**.

## Develop

```bash
cd site
npm install
npm run dev      # http://localhost:4321
```

## Build

```bash
cd site
npm run build    # -> site/dist
npm run preview  # serve the built output locally
npm run check    # astro + TypeScript diagnostics
```

## Cloudflare Pages settings

| Setting | Value |
| --- | --- |
| Build command | `cd site && npm ci && npm run build` |
| Build output directory | `site/dist` |
| Node version | 20 or newer (`NODE_VERSION` env var) |

`wrangler.toml` already declares `pages_build_output_dir`, so a Git-connected
Pages project only needs the build command above.

Headers, caching and legacy redirects live in [`site/public/_headers`](site/public/_headers)
and [`site/public/_redirects`](site/public/_redirects); both are copied to the
output verbatim by Astro.

## Structure

```
site/
  src/
    i18n/            el.ts is the source of truth; en.ts is type-checked against it
    data/            site details, projects, products, platforms, security guide
    components/      section components (Hero, Services, Pricing, …)
    layouts/Base.astro
    pages/           Greek at /, English under /en
  public/            fonts, images, icons, _headers, _redirects
legacy/              previous Mobirise site, kept for reference only
```

## Content

- **Languages** — Greek is the default at `/`; English lives under `/en`.
  Every user-facing string lives in `src/i18n/`. Adding a key to `el.ts`
  without adding it to `en.ts` fails the build.
- **Projects** — `src/data/projects.json` is imported from the sister site
  `portfolio.buy-it.gr`. Thumbnails are pre-resized WebP in `public/projects/`.
- **Theme** — light/dark via CSS custom properties; the choice is stored in
  `localStorage` under `upg-theme` and falls back to the system setting.
