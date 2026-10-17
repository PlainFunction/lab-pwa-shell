// Builds the shell into dist/ for Workers Static Assets.
//
//   npm run build            build, and print what each file weighs
//   node scripts/build.mjs --check   also fail if the shell outgrows its budget (npm test runs this)
//
// The app's name comes from APP_NAME in wrangler.toml, so the passkey prompt,
// the sign-in screen and the installed app all say the same thing. Colours
// (themeColor for buttons and the icon, accentColor for links and labels,
// backgroundColor for the page) and the short name under the icon are in shell.config.json.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { buildShell } from '../capabilities/core/pwa/shell/build.mjs'

const at = p => fileURLToPath(new URL(`../${p}`, import.meta.url))
// Everything that loads before the first screen, gzipped: HTML, JS, CSS, service worker, manifest.
const BUDGET_GZIP = 12 * 1024

const toml = readFileSync(at('wrangler.toml'), 'utf8')
const name = toml.match(/^APP_NAME\s*=\s*"([^"]+)"/m)?.[1]
if (!name) throw new Error('APP_NAME is not set in wrangler.toml')
const config = { name, ...JSON.parse(readFileSync(at('shell.config.json'), 'utf8')) }

const { version, sizes, font } = await buildShell({ outDir: at('dist'), config })
let total = 0
for (const [file, { bytes, gzip }] of Object.entries(sizes)) {
  total += gzip
  console.log(`  ${file.padEnd(22)} ${String(bytes).padStart(6)} B   ${String(gzip).padStart(5)} B gzipped`)
}
console.log(`  ${'fraunces.woff2'.padEnd(22)} ${String(font).padStart(6)} B   (headings; loads alongside, kept by the service worker)`)
console.log(`✓ shell ${version}: ${(total / 1024).toFixed(1)} KB gzipped, in dist/`)

if (process.argv.includes('--check') && total > BUDGET_GZIP) {
  console.error(`✗ the shell is ${total} B gzipped, over its ${BUDGET_GZIP} B budget`)
  process.exit(1)
}
