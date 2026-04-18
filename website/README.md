# withrelay.dev

Marketing + docs site for [relay](https://github.com/afomera/relay). Built with Astro 5,
Tailwind 4, and IBM Plex Mono. Deployed to Cloudflare Pages as a fully static site.

## Develop

```sh
npm install
npm run dev
```

Open http://localhost:4321.

## Build

```sh
npm run build
```

Static output lands in `dist/`.

## Deploy to Cloudflare Pages

This is a static site — no adapter needed.

- **Framework preset:** Astro
- **Build command:** `npm run build`
- **Build output directory:** `dist`
- **Root directory:** `website`
- **Node version:** 22 (see `.nvmrc`)

Connect the repo, set the root directory to `website/`, and Pages handles the rest.
