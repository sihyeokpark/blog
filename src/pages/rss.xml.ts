import rss from '@astrojs/rss'
import type { APIContext } from 'astro'
import MarkdownIt from 'markdown-it'
import sanitizeHtml from 'sanitize-html'
import { site } from '../config'
import { excerpt, getPosts, postUrl } from '../utils/posts'

const parser = new MarkdownIt()

export async function GET(context: APIContext) {
  const posts = await getPosts() // drafts excluded in production builds
  return rss({
    title: site.title,
    description: site.description,
    site: context.site ?? 'https://blog.exon.kr/',
    items: posts.map((post) => ({
      title: post.data.title,
      pubDate: post.data.published,
      description: excerpt(post, 200),
      link: postUrl(post),
      categories: [post.data.category, ...(post.data.tags ?? [])].filter(Boolean) as string[],
      content: sanitizeHtml(parser.render(post.body), {
        allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']),
      }),
    })),
    customData: '<language>ko</language>',
  })
}
