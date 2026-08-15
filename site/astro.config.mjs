// @ts-check
import { defineConfig } from 'astro/config';

// Static output — deploys to Cloudflare Pages as plain files, no adapter/runtime needed.
export default defineConfig({
  site: 'https://upg.gr',
  output: 'static',
  trailingSlash: 'ignore',
  build: {
    // Cloudflare Pages serves /about/index.html at both /about and /about/
    format: 'directory',
    inlineStylesheets: 'auto',
  },
  i18n: {
    defaultLocale: 'el',
    locales: ['el', 'en'],
    routing: {
      // Greek stays at the root (/), English lives under /en
      prefixDefaultLocale: false,
      redirectToDefaultLocale: false,
    },
  },
  image: {
    responsiveStyles: true,
  },
  devToolbar: { enabled: false },
});
