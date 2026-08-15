import type { APIRoute } from 'astro';
import { site } from '../data/site';

/** Every page exists in both languages; each entry advertises its alternate. */
const paths = ['/', '/cybersecurity', '/products', '/projects'];

export const GET: APIRoute = () => {
  const lastmod = new Date().toISOString().slice(0, 10);

  const urls = paths
    .flatMap((path) => [path, path === '/' ? '/en' : `/en${path}`])
    .map((loc) => {
      const el = new URL(loc.replace(/^\/en/, '') || '/', site.url).href;
      const en = new URL(loc.startsWith('/en') ? loc : `/en${loc === '/' ? '' : loc}`, site.url).href;
      return `  <url>
    <loc>${new URL(loc, site.url).href}</loc>
    <lastmod>${lastmod}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>${loc === '/' ? '1.0' : '0.7'}</priority>
    <xhtml:link rel="alternate" hreflang="el" href="${el}"/>
    <xhtml:link rel="alternate" hreflang="en" href="${en}"/>
    <xhtml:link rel="alternate" hreflang="x-default" href="${el}"/>
  </url>`;
    })
    .join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
${urls}
</urlset>`;

  return new Response(xml, {
    headers: { 'Content-Type': 'application/xml; charset=utf-8' },
  });
};
