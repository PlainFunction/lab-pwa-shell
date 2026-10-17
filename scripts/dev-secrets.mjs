// Writes the secrets `wrangler dev` needs into .dev.vars.
//
//   npm run dev:secrets
//
// Generates KEYRING and a VAPID key pair for notifications. Never replaces a
// value that's already there: a new KEYRING would lose everything sealed with
// the old one, and new VAPID keys would cut off every device that subscribed.
// Prints names, never values.
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const file = fileURLToPath(new URL('../.dev.vars', import.meta.url))
const text = existsSync(file) ? readFileSync(file, 'utf8') : ''
const have = new Set(text.split(/\r?\n/).map(line => line.match(/^\s*([A-Z0-9_]+)\s*=\s*\S/)?.[1]).filter(Boolean))

const lines = []
// Same shape as core's AesGcmCipher expects. To rotate, add k2 and point current at it.
if (!have.has('KEYRING')) lines.push(`KEYRING=${JSON.stringify({ current: 'k1', keys: { k1: randomBytes(32).toString('base64') } })}`)
if (!have.has('VAPID_PUBLIC_KEY') && !have.has('VAPID_PRIVATE_KEY')) {
  // The browser wants the public key uncompressed (0x04, x, y); the Worker signs with d.
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const pub = publicKey.export({ format: 'jwk' })
  const raw = Buffer.concat([Buffer.from([4]), Buffer.from(pub.x, 'base64url'), Buffer.from(pub.y, 'base64url')])
  lines.push(`VAPID_PUBLIC_KEY=${raw.toString('base64url')}`, `VAPID_PRIVATE_KEY=${privateKey.export({ format: 'jwk' }).d}`)
}

// Drop empty placeholders for anything we're about to write, so .dev.vars doesn't end up with both.
const writing = new Set(lines.map(l => l.split('=')[0]))
const kept = text.split(/\r?\n/).filter(line => !writing.has(line.match(/^\s*([A-Z0-9_]+)\s*=\s*$/)?.[1])).join('\n')

if (!lines.length) {
  console.log('✓ .dev.vars already has everything. Nothing changed.')
} else {
  const sep = kept && !kept.endsWith('\n') ? '\n' : ''
  writeFileSync(file, kept + sep + lines.join('\n') + '\n')
  console.log(`✓ Added to .dev.vars: ${[...writing].join(', ')}`)
  console.log('  Keep a copy of KEYRING somewhere safe. Without it, sealed data can\'t be read.')
}
