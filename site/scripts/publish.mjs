/**
 * Copy the built site from site/dist into the repository root, which is what
 * Cloudflare Pages serves for this project.
 *
 * Only paths the build actually produces are touched. Everything else in the
 * repo (legacy/, tools/, data/, site/, README, ISO.pdf, …) is left alone, and
 * the root is never emptied wholesale.
 */
import { existsSync } from 'node:fs';
import { cp, readdir, rm, mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, '../dist');
const root = resolve(here, '../../');

/** Never remove or overwrite these, whatever the build emits. */
const PROTECTED = new Set([
  '.git', '.gitignore', 'site', 'legacy', 'tools', 'data',
  'README.md', 'wrangler.toml', 'ISO.pdf', 'koukounaria.rsc:',
]);

if (!existsSync(dist)) {
  console.error('No build output at site/dist — run `npm run build` first.');
  process.exit(1);
}

const entries = await readdir(dist, { withFileTypes: true });
if (entries.length === 0) {
  console.error('site/dist is empty; refusing to publish.');
  process.exit(1);
}

let copied = 0;
for (const entry of entries) {
  if (PROTECTED.has(entry.name)) {
    console.warn(`skipping protected path: ${entry.name}`);
    continue;
  }
  const from = join(dist, entry.name);
  const to = join(root, entry.name);

  // Replace just this generated path, so stale build files never linger.
  await rm(to, { recursive: true, force: true });
  await cp(from, to, { recursive: true });
  copied++;
}

// Astro does not emit dotfiles it does not know about; make sure the Pages
// config files land at the root even though they start with an underscore.
for (const name of ['_headers', '_redirects']) {
  const from = join(dist, name);
  if (existsSync(from)) await cp(from, join(root, name), { force: true });
}

console.log(`published ${copied} entr${copied === 1 ? 'y' : 'ies'} from site/dist to the repo root`);
