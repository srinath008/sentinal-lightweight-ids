# Sentinel download landing page

A plain static site: everything the browser needs is in `dist/`. There is no build step.
It is deployed on Vercel (see `vercel.json`: `outputDirectory` is `dist`, no framework).

## Deploy on Vercel

1. Push this repository to GitHub.
2. In Vercel choose **Add New → Project**, import the repository.
3. Set **Root Directory** to `landing`. Framework Preset: **Other**. Leave Build Command and
   Install Command empty; the Output Directory comes from `vercel.json` (`dist`).
4. Deploy. Every later push to `main` redeploys automatically.

## Update the download

From the repository root, using the project's Python environment:

```bash
python -m release_tools.build_release
```

This rewrites `dist/downloads/` (archive, `SHA256SUMS.txt`, `release.json`). Commit the three files
together, because the page shows the archive size from `release.json` and publishes the checksum.

## Preview locally

```bash
python -m http.server 4173 --bind 127.0.0.1 --directory landing/dist
```

The application release is a source/runtime archive requiring online dependency installation,
not a standalone binary. The site must retain the preview and Linux-verification caveats until
independently verified.

Watermelon UI design references and MIT license are included in `dist/credits/`.
