import sitemap from "@astrojs/sitemap"
import Compress from "astro-compress"
import { defineConfig } from "astro/config"
import rehypeAutolinkHeadings from "rehype-autolink-headings"
import rehypeComponents from "rehype-components" /* Render the custom directive content */
import rehypeKatex from "rehype-katex"
import rehypeSlug from "rehype-slug"
import remarkDirective from "remark-directive" /* Handle directives */
import remarkGithubAdmonitionsToDirectives from "remark-github-admonitions-to-directives"
import remarkMath from "remark-math"
import { AdmonitionComponent } from "./src/plugins/rehype-component-admonition.mjs"
import { GithubCardComponent } from "./src/plugins/rehype-component-github-card.mjs"
import { parseDirectiveNode } from "./src/plugins/remark-directive-rehype.js"
import { remarkReadingTime } from "./src/plugins/remark-reading-time.mjs"

// https://astro.build/config
export default defineConfig({
  site: "https://blog.exon.kr/",
  trailingSlash: "always",
  integrations: [Compress({ Image: false, CSS: false }), sitemap()],
  markdown: {
    shikiConfig: {
      themes: { light: "github-light", dark: "github-dark" },
      wrap: false,
    },
    remarkPlugins: [remarkMath, remarkReadingTime, remarkGithubAdmonitionsToDirectives, remarkDirective, parseDirectiveNode],
    rehypePlugins: [
      rehypeKatex,
      rehypeSlug,
      [
        rehypeComponents,
        {
          components: {
            github: GithubCardComponent,
            note: (x, y) => AdmonitionComponent(x, y, "note"),
            tip: (x, y) => AdmonitionComponent(x, y, "tip"),
            important: (x, y) => AdmonitionComponent(x, y, "important"),
            caution: (x, y) => AdmonitionComponent(x, y, "caution"),
            warning: (x, y) => AdmonitionComponent(x, y, "warning"),
          },
        },
      ],
      [
        rehypeAutolinkHeadings,
        {
          behavior: "append",
          properties: { className: ["anchor"], ariaHidden: "true", tabIndex: -1 },
          content: { type: "text", value: "#" },
        },
      ],
    ],
  },
})
