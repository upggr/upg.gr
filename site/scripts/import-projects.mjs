/**
 * Rebuild src/data/projects.json (and public/projects/*.webp) from the sister
 * site's portfolio export at portfolio.buy-it.gr.
 *
 * Usage:  node scripts/import-projects.mjs [path-to-portfolio-repo]
 */
import { existsSync, statSync } from 'node:fs';
import { readFile, writeFile, readdir, mkdir, rm } from 'node:fs/promises';
import { dirname, join, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';

const here = dirname(fileURLToPath(import.meta.url));
const siteRoot = resolve(here, '..');
const source = resolve(
  process.argv[2] ?? '../../portfolio.buy-it.gr',
  // relative paths resolve against the site directory, not the cwd
);
const sourceDir = existsSync(source) ? source : resolve(siteRoot, '../../portfolio.buy-it.gr');

const outJson = join(siteRoot, 'src/data/projects.json');
const outThumbs = join(siteRoot, 'public/projects');

/** Non-production hostnames that mirror a project we already list. */
const ENV_SUBDOMAIN = /^(www|preprod|preview|staging|stage|dev|test|beta|demo)\./;

/** The canonical host for a URL, ignoring environment subdomains. */
function rootHost(url) {
  if (!url) return null;
  const host = url.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
  return host.replace(ENV_SUBDOMAIN, '');
}

/** CRM titles carry an SEO tail ("Brand | long description") — keep the brand. */
function cleanTitle(title) {
  const short = title.split(/\s*[|—–]\s*/)[0].trim();
  return short.length >= 3 ? short : title.trim();
}

const raw = JSON.parse(await readFile(join(sourceDir, 'portfolio-data.json'), 'utf8'));

// Manual corrections layered on top of the export, so a re-import never
// resurrects entries we deliberately removed or re-categorised.
const overrides = JSON.parse(
  await readFile(join(siteRoot, 'src/data/project-overrides.json'), 'utf8')
);
const excludeUrls = overrides.excludeUrls?.values ?? [];
const excludeTitles = new Set(overrides.excludeTitles?.values ?? []);
const excludeTabs = new Set(overrides.excludeTabs?.values ?? []);
const retab = Object.fromEntries(
  Object.entries(overrides.retab ?? {}).filter(([key]) => !key.startsWith('_'))
);
const reurl = Object.fromEntries(
  Object.entries(overrides.reurl ?? {}).filter(([key]) => !key.startsWith('_'))
);
const retitle = Object.fromEntries(
  Object.entries(overrides.retitle ?? {}).filter(([key]) => !key.startsWith('_'))
);

const projects = [];
const seen = new Set();

for (const entry of raw) {
  if (!entry.active) continue;

  const title = (entry.title ?? '').trim();
  let tabs = (entry.tabs ?? []).filter(Boolean);
  if (!title || tabs.length === 0) continue;

  let url = (entry.url ?? '').trim();

  if (excludeTitles.has(title)) continue;
  if (url && excludeUrls.some((fragment) => url.includes(fragment))) continue;
  if (retab[title]) tabs = retab[title];
  if (reurl[title]) url = reurl[title];

  // Drop excluded categories, and the entry entirely if nothing else remains.
  tabs = tabs.filter((tab) => !excludeTabs.has(tab));
  if (tabs.length === 0) continue;

  /*
   * Dedupe key. Linked entries collapse on their canonical host *and*
   * category, so preprod./preview./staging. mirrors of a site fold into the
   * one production card rather than appearing as separate projects.
   * Entries with no URL (DNS zones, per-client engagements) are distinct
   * records, so they key on title instead.
   */
  const key = url ? `${rootHost(url)}::${tabs[0]}` : `${title.toLowerCase()}::${tabs[0]}`;
  if (seen.has(key)) continue;
  seen.add(key);

  // `thumbnail` is a path, but the export also uses null and `false`.
  const thumb = typeof entry.thumbnail === 'string' ? entry.thumbnail : '';
  const hasThumb = thumb !== '' && existsSync(join(sourceDir, thumb));

  // The export slugifies some names ("Aquadeluxe Gr"); retitle keys match the
  // cleaned title, so the rename happens after cleanTitle.
  const cleaned = cleanTitle(title);

  projects.push({
    title: retitle[cleaned] ?? cleaned,
    // Prefer the bare production URL over an environment subdomain.
    url: url || null,
    tags: entry.tags ?? [],
    tabs,
    thumb: hasThumb ? thumb : null,
    _srcThumb: hasThumb ? join(sourceDir, thumb) : null,
  });
}

// Work that is not in the portfolio export at all.
for (const extra of overrides.add?.values ?? []) {
  const key = extra.url
    ? `${rootHost(extra.url)}::${extra.tabs[0]}`
    : `${extra.title.toLowerCase()}::${extra.tabs[0]}`;
  if (seen.has(key)) continue;
  seen.add(key);
  projects.push({ ...extra, _srcThumb: null });
}

// Featured first: has a screenshot, then has a link, then alphabetical.
projects.sort(
  (a, b) =>
    Number(a.thumb === null) - Number(b.thumb === null) ||
    Number(a.url === null) - Number(b.url === null) ||
    a.title.localeCompare(b.title)
);

/*
 * Re-encode thumbnails from the export (the source PNGs are ~35MB in total).
 * Screenshots referenced by project-overrides.json have no source to rebuild
 * from, so they are kept rather than cleared.
 */
await mkdir(outThumbs, { recursive: true });
const keep = new Set(
  projects.filter((p) => p.thumb && !p._srcThumb).map((p) => basename(p.thumb))
);
for (const file of await readdir(outThumbs)) {
  if (!keep.has(file)) await rm(join(outThumbs, file), { force: true });
}

let bytes = 0;
for (const project of projects) {
  if (!project._srcThumb) {
    // An override thumbnail is kept only if the file is actually there.
    if (project.thumb && !existsSync(join(siteRoot, 'public', project.thumb))) {
      project.thumb = null;
    }
    continue;
  }
  const name = basename(project._srcThumb).replace(/\.(png|jpe?g|webp)$/i, '') + '.webp';
  // A blank source filename would produce a nameless ".webp".
  if (name === '.webp') {
    project.thumb = null;
    continue;
  }
  const dest = join(outThumbs, name);
  await sharp(project._srcThumb)
    .resize(760, 510, { fit: 'cover', position: 'top' })
    .webp({ quality: 74, effort: 5 })
    .toFile(dest);
  bytes += statSync(dest).size;
  project.thumb = `/projects/${name}`;
  delete project._srcThumb;
}
for (const project of projects) delete project._srcThumb;

await writeFile(outJson, JSON.stringify(projects, null, 1) + '\n', 'utf8');

const withThumb = projects.filter((p) => p.thumb).length;
const withUrl = projects.filter((p) => p.url).length;
console.log(
  `${projects.length} projects (${withUrl} linked, ${withThumb} with thumbnails, ` +
    `${(bytes / 1048576).toFixed(1)}MB of images)`
);
