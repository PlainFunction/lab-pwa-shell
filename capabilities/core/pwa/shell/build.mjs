// Builds the shell into a folder for Workers Static Assets: the page, one
// script, one stylesheet, the service worker, the manifest, icons and the
// security headers. Everything a client changes is in `config`.
//
//   import { buildShell } from './capabilities/core/pwa/shell/build.mjs'
//   await buildShell({ outDir: 'dist', config: { name: 'Harbour Plumbing', shortName: 'Harbour', themeColor: '#1E3A72', backgroundColor: '#F7F7FF' } })
//
// themeColor is the buttons and the icon, accentColor (optional, our #279AF1 by
// default) the links and labels, backgroundColor the page. Needs esbuild, and
// @fontsource-variable/fraunces for the heading font.

import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import { icons } from './icons.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))

// Static assets never run the Worker, so their headers come from here. The API sets its own.
const HEADERS = `/*
  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data: https:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
  Cross-Origin-Opener-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
  Referrer-Policy: no-referrer
  Strict-Transport-Security: max-age=31536000
  X-Content-Type-Options: nosniff
  X-Robots-Tag: noindex
/sw.js
  Cache-Control: no-cache
`

const HEX = /^#[0-9a-fA-F]{6}$/
const escapeHtml = s => s.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`)

function check(config) {
  const { name, shortName, themeColor, backgroundColor, accentColor = '#279AF1' } = config ?? {}
  if (typeof name !== 'string' || !name.trim() || name.length > 60) throw new Error('config.name: 1 to 60 characters')
  if (typeof shortName !== 'string' || !shortName.trim() || shortName.length > 12) throw new Error('config.shortName: 1 to 12 characters (it goes under the icon)')
  if (!HEX.test(themeColor ?? '')) throw new Error('config.themeColor: a colour like #1E3A72')
  if (!HEX.test(backgroundColor ?? '')) throw new Error('config.backgroundColor: a colour like #F7F7FF')
  if (!HEX.test(accentColor)) throw new Error('config.accentColor: a colour like #279AF1')
  return { name: name.trim(), shortName: shortName.trim(), themeColor, backgroundColor, accentColor }
}

export async function buildShell({ outDir, config, minify = true }) {
  const { build } = await import('esbuild')
  const c = check(config)
  const files = {}

  files['index.html'] = readFileSync(join(HERE, 'index.html'), 'utf8').replace('%NAME%', escapeHtml(c.name)).replace('%THEME%', c.themeColor)
  files['app.css'] = readFileSync(join(HERE, 'app.css'), 'utf8').replace('%BRAND%', c.themeColor).replace('%ACCENT%', c.accentColor).replace('%PAPER%', c.backgroundColor)
  // Latin, weight axis only: about 36 KB, fetched once and kept by the service worker.
  files['fraunces.woff2'] = readFileSync(createRequire(import.meta.url).resolve('@fontsource-variable/fraunces/files/fraunces-latin-wght-normal.woff2'))
  files['manifest.webmanifest'] = JSON.stringify({
    id: '/', name: c.name, short_name: c.shortName, start_url: '/', scope: '/', display: 'standalone',
    background_color: c.backgroundColor, theme_color: c.themeColor,
    icons: [
      { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
    ],
  }, null, 2)
  Object.assign(files, icons(c.themeColor))

  // Safari 16 is where web push on iPhone starts (16.4).
  const bundle = async (entry, define = {}) => (await build({
    entryPoints: [join(HERE, entry)], bundle: true, format: 'esm', target: ['es2022', 'safari16'],
    minify, write: false, legalComments: 'none', define,
  })).outputFiles[0].text
  files['app.js'] = await bundle('app.ts')

  // The service worker keeps exactly these, and a change to any of them is a new version.
  const shell = Object.keys(files).filter(f => f !== 'index.html').sort()
  const hash = createHash('sha256')
  for (const f of ['index.html', ...shell]) hash.update(f).update(files[f])
  const version = hash.digest('hex').slice(0, 12)
  files['sw.js'] = await bundle('sw.ts', { __VERSION__: JSON.stringify(version), __SHELL__: JSON.stringify(['/', ...shell.map(f => `/${f}`)]), __APP_NAME__: JSON.stringify(c.name) })
  files['_headers'] = HEADERS

  // Files are replaced in place and only stale ones removed: on Windows, wrangler dev
  // holds the folder open, so deleting the folder itself fails while it runs.
  mkdirSync(outDir, { recursive: true })
  for (const name of readdirSync(outDir)) if (!(name in files)) rmSync(join(outDir, name), { recursive: true, force: true })
  for (const [name, body] of Object.entries(files)) writeFileSync(join(outDir, name), body)

  const size = name => ({ bytes: Buffer.byteLength(files[name]), gzip: gzipSync(files[name]).length })
  return { version, sizes: Object.fromEntries(['index.html', 'app.js', 'app.css', 'sw.js', 'manifest.webmanifest'].map(n => [n, size(n)])), font: files['fraunces.woff2'].length }
}
