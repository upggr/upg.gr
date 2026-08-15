import el from './el';
import en from './en';

export const languages = { el: 'Ελληνικά', en: 'English' } as const;
export const defaultLang = 'el' as const;

export type Lang = keyof typeof languages;

export type Dict = typeof el;

/**
 * Same shape as the Greek dictionary, but with string literals widened to
 * `string` — every translation must supply the same keys, while being free to
 * carry different text.
 */
type Translation<T> = T extends string
  ? string
  : T extends readonly (infer U)[]
    ? readonly Translation<U>[]
    : { readonly [K in keyof T]: Translation<T[K]> };

/** A missing or misspelled key in en.ts fails the build here. */
const dictionaries = { el, en } satisfies Record<Lang, Translation<Dict>>;

export function getDict(lang: Lang): Dict {
  return dictionaries[lang] as Dict;
}

/** Resolve the language from a URL like /en/products -> 'en'. */
export function langFromUrl(url: URL): Lang {
  const [, first] = url.pathname.split('/');
  return first in languages ? (first as Lang) : defaultLang;
}

/**
 * Build a locale-aware href.
 * Greek lives at the root (/services), English under /en (/en/services).
 */
export function localizedPath(path: string, lang: Lang): string {
  const clean = `/${path.replace(/^\/+/, '')}`.replace(/\/+$/, '') || '/';
  if (lang === defaultLang) return clean;
  return clean === '/' ? '/en' : `/en${clean}`;
}

/** Same page in the other language, for the language switcher. */
export function alternatePath(url: URL, target: Lang): string {
  const segments = url.pathname.split('/').filter(Boolean);
  if (segments[0] in languages) segments.shift();
  return localizedPath(segments.join('/'), target);
}
