import { type CollectionEntry, getCollection } from 'astro:content'

export type Post = CollectionEntry<'posts'>

/** Published posts, newest first (drafts are visible in `astro dev` only). */
export async function getPosts(): Promise<Post[]> {
  const posts = await getCollection('posts', ({ data }) => (import.meta.env.PROD ? data.draft !== true : true))
  return posts.sort((a, b) => b.data.published.valueOf() - a.data.published.valueOf())
}

export function groupByYear(posts: Post[]): [string, Post[]][] {
  const map = new Map<string, Post[]>()
  for (const p of posts) {
    const y = String(p.data.published.getUTCFullYear())
    if (!map.has(y)) map.set(y, [])
    map.get(y)!.push(p)
  }
  return [...map.entries()]
}

export function countBy(posts: Post[], pick: (p: Post) => string[]): { name: string; count: number }[] {
  const m = new Map<string, number>()
  for (const p of posts) for (const k of pick(p)) m.set(k, (m.get(k) ?? 0) + 1)
  return [...m.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => a.name.localeCompare(b.name))
}

export const postUrl = (p: Post) => `/posts/${p.slug}/`
export const categoryUrl = (c: string) => `/archive/category/${c}/`
export const tagUrl = (t: string) => `/archive/tag/${t}/`

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
export const fmtShort = (d: Date) => `${MONTHS[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, '0')}`
export const fmtLong = (d: Date) => `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()}`
export const fmtISO = (d: Date) => d.toISOString().substring(0, 10)

/** First paragraph of plain text, for list excerpts when a post has no description. */
export function excerpt(p: Post, max = 140): string {
  if (p.data.description) return p.data.description
  const text = p.body
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/^:::[^\r\n]*\r?\n[\s\S]*?^:::[ \t]*\r?$/gm, ' ') // admonition blocks
    .split(/\r?\n/)
    .filter((l) => l.trim() && !/^\s*(#|-|\*|!\[|\[|>|\||<|:::)/.test(l))
    .join(' ')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[*_`]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
  return text.length > max ? `${text.slice(0, max).trimEnd()}…` : text
}
