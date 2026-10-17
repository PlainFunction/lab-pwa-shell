// Runs the app on a phone without deploying it: a Cloudflare quick tunnel gives
// wrangler dev a public https address, and the app is started with that address
// as its PUBLIC_URL, because passkeys only work at the address they were made for.
//
//   npm run dev:tunnel                   tunnel + wrangler dev
//   npm run dev:tunnel -- "Your name"    and print an invite link for that address
//
// Needs cloudflared on your PATH (winget install Cloudflare.cloudflared, or
// brew install cloudflared). The address changes every run, and passkeys made
// at an old one don't work at the new one: make a fresh invite each time.
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { createConnection } from 'node:net'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const port = '8799'
const name = process.argv.slice(2).find(a => !a.startsWith('--'))
const children = []
const stop = code => { for (const c of children) c.kill(); process.exit(code) }
process.on('SIGINT', () => stop(0))

// Another dev server on the port would answer the tunnel with its own PUBLIC_URL,
// and every passkey would be refused with a confusing "only works at" error.
const busy = await new Promise(resolve => {
  const s = createConnection({ host: '127.0.0.1', port: Number(port) }, () => { s.destroy(); resolve(true) })
  s.on('error', () => resolve(false))
})
if (busy) {
  console.error(`✗ something is already running on port ${port}. Stop it first (another wrangler dev?)`)
  process.exit(1)
}

const tunnel = spawn('cloudflared', ['tunnel', '--no-autoupdate', '--url', `http://localhost:${port}`], { stdio: ['ignore', 'pipe', 'pipe'] })
children.push(tunnel)
tunnel.on('error', () => {
  console.error('✗ cloudflared isn\'t installed (or isn\'t on your PATH). winget install Cloudflare.cloudflared, or brew install cloudflared')
  stop(1)
})
tunnel.on('exit', code => { console.error(`✗ cloudflared stopped (${code})`); stop(1) })

const url = await new Promise(resolve => {
  let seen = ''
  const read = chunk => {
    seen += chunk
    const m = seen.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/)
    if (m) resolve(m[0])
  }
  tunnel.stdout.on('data', read)
  tunnel.stderr.on('data', read)
})
console.log(`✓ tunnel: ${url}`)

// wrangler's own entry point, run with this Node: npx is a .cmd on Windows and spawn() can't start it without a shell.
const node = (script, args, opts = {}) => spawn(process.execPath, [script, ...args], { cwd: root, ...opts })
const wranglerBin = join(dirname(createRequire(import.meta.url).resolve('wrangler/package.json')), 'bin', 'wrangler.js')

await new Promise((resolve, reject) => node(join(root, 'scripts', 'build.mjs'), [], { stdio: 'inherit' }).on('exit', c => c === 0 ? resolve() : reject(new Error('build failed'))))
const dev = node(wranglerBin, ['dev', '--config', 'wrangler.toml', '--port', port, '--var', `PUBLIC_URL:${url}`], { stdio: ['inherit', 'pipe', 'inherit'] })
children.push(dev)
dev.on('exit', code => stop(code ?? 0))
let ready = false
dev.stdout.on('data', chunk => {
  process.stdout.write(chunk)
  if (ready || !String(chunk).includes('Ready on')) return
  ready = true
  if (name) node(join(root, 'scripts', 'invite.mjs'), [name, '--url', url], { stdio: 'inherit' })
  else console.log(`\nOpen ${url} on your phone. To make an invite for this address:\n  npm run invite -- "Your name" --url ${url}\n`)
})
