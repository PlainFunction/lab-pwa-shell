// Makes an invite link, the way into the app for someone new, and gets people
// back in when nobody in the app can. It writes straight into the Worker's D1,
// so only someone with access to the Cloudflare account can use it. Day to
// day, people invite and recover each other from the app's settings, as their
// roles allow.
//
//   npm run invite -- "Dan Harbour"                 role admin (Owner, in src/roles.ts), on wrangler dev's local D1
//   npm run invite -- "Sam" --role tradie           any role in src/roles.ts
//   npm run invite -- "Dan Harbour" --remote        on the deployed Worker's D1
//   npm run invite -- "Dan Harbour" --url https://app.example.com.au
//
//   npm run invite -- --people [--remote]           who's in, with their ids and roles
//   npm run invite -- --recover <id> [--remote]     someone lost every device (or the last owner did)
//
// --recover removes all of that person's passkeys, signs them out everywhere,
// stops their notifications and cancels their unused links, then prints a link that sets up a new
// passkey on the same account, with the same role. In the app this is "Recover access", which also
// goes in the audit log; from here it doesn't, so note who you recovered and why.
//
// A link works once, for 24 hours. Only its SHA-256 is stored, so the printed
// link is the only copy: send it to the person, not to a group.
import { spawnSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const args = process.argv.slice(2)
const flag = name => args.includes(name)
const option = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined }
const VALUED = new Set(['--url', '--recover', '--role'])
const name = args.find((a, i) => !a.startsWith('--') && !VALUED.has(args[i - 1]))?.trim()

const root = fileURLToPath(new URL('..', import.meta.url))
const toml = readFileSync(join(root, 'wrangler.toml'), 'utf8')
const database = toml.match(/^database_name\s*=\s*"([^"]+)"/m)?.[1]
const url = (option('--url') ?? toml.match(/^PUBLIC_URL\s*=\s*"([^"]+)"/m)?.[1] ?? '').replace(/\/+$/, '')
if (!database || !url) throw new Error('wrangler.toml needs database_name and PUBLIC_URL (or pass --url)')

const sqlText = s => `'${String(s).replace(/'/g, "''")}'`

// The app's roles, read from src/roles.ts, so a typo can't make someone who can do nothing.
const roles = [...readFileSync(join(root, 'src', 'roles.ts'), 'utf8').matchAll(/^ {2}([a-z][a-z0-9_-]*): \{ label: '([^']+)'/gm)].map(m => ({ id: m[1], label: m[2] }))
const labelOf = id => roles.find(r => r.id === id)?.label ?? `${id}, no longer a role`

/** wrangler's own entry point, run with this Node: npx is a .cmd on Windows and spawn() can't start it without a shell. */
function wrangler(...cmd) {
  const bin = join(dirname(createRequire(import.meta.url).resolve('wrangler/package.json')), 'bin', 'wrangler.js')
  return spawnSync(process.execPath, [bin, ...cmd, flag('--remote') ? '--remote' : '--local', '--config', join(root, 'wrangler.toml')], { cwd: root, encoding: 'utf8' })
}

/** Runs SQL on the Worker's D1, and returns the rows of the last statement. */
function d1(sql) {
  const run = wrangler('d1', 'execute', database, '--json', '--command', sql)
  if (run.status !== 0) {
    console.error(run.stdout, run.stderr)
    console.error('✗ Nothing changed. Has the schema been applied? npm run db:local (or db:remote)')
    process.exit(1)
  }
  return JSON.parse(run.stdout).at(-1)?.results ?? []
}

const newLink = () => {
  const token = randomBytes(24).toString('base64url')
  return { token, id: createHash('sha256').update(token).digest('hex'), expires: new Date(Date.now() + 24 * 3600_000).toISOString() }
}

if (flag('--people')) {
  const people = d1('SELECT u.id, u.name, u.role, COUNT(p.id) AS devices, MAX(COALESCE(p.last_used_at, p.created_at)) AS used FROM pwa_users u LEFT JOIN pwa_passkeys p ON p.user_id = u.id GROUP BY u.id ORDER BY u.created_at')
  if (!people.length) console.log('Nobody yet. Make the first invite: npm run invite -- "Their name"')
  for (const p of people) console.log(`  ${p.id}  ${p.name} (${labelOf(p.role)}), ${p.devices} device(s), last used ${p.used ?? 'never'}`)
  process.exit(0)
}

const recover = option('--recover')
if (recover) {
  const [person] = d1(`SELECT id, name, role FROM pwa_users WHERE id = ${sqlText(recover)}`)
  if (!person) {
    console.error(`✗ Nobody with id ${recover}. See them all with: npm run invite -- --people`)
    process.exit(1)
  }
  const { token, id, expires } = newLink()
  // Their devices' notifications: the subscriptions are sealed in KV under the endpoint's hash.
  for (const { endpoint } of d1(`SELECT endpoint FROM pwa_push WHERE user_id = ${sqlText(person.id)}`)) {
    const key = `push:${createHash('sha256').update(endpoint).digest('hex')}`
    if (wrangler('kv', 'key', 'delete', key, '--binding', 'KV').status !== 0) console.error(`  couldn't remove a push subscription (${key}); remove it by hand`)
  }
  // One batch: the lost devices stop working before the new link exists.
  d1([
    `DELETE FROM pwa_passkeys WHERE user_id = ${sqlText(person.id)}`,
    `DELETE FROM pwa_sessions WHERE user_id = ${sqlText(person.id)}`,
    `DELETE FROM pwa_invites WHERE user_id = ${sqlText(person.id)}`,
    `DELETE FROM pwa_push WHERE user_id = ${sqlText(person.id)}`,
    `INSERT INTO pwa_invites (id, name, role, user_id, created_by, expires_at) VALUES ('${id}', ${sqlText(person.name)}, ${sqlText(person.role)}, ${sqlText(person.id)}, 'operator', '${expires}')`,
  ].join('; '))
  console.log(`✓ ${person.name}'s devices are signed out and removed. Their set-up link works once, until ${expires}:\n\n  ${url}/#invite=${token}\n`)
  process.exit(0)
}

const role = option('--role') ?? 'admin'
if (!roles.some(r => r.id === role)) {
  console.error(`✗ No role called ${role}. The app's roles: ${roles.map(r => `${r.id} (${r.label})`).join(', ')}`)
  process.exit(1)
}
if (!name || name.length > 60) {
  console.error('Usage: npm run invite -- "Their name" [--role <role>] [--remote] [--url https://...]\n       npm run invite -- --people | --recover <id> [--remote]')
  process.exit(1)
}
const { token, id, expires } = newLink()
d1(`INSERT INTO pwa_invites (id, name, role, user_id, created_by, expires_at) VALUES ('${id}', ${sqlText(name)}, ${sqlText(role)}, NULL, 'operator', '${expires}')`)
console.log(`✓ Invite for ${name} (${labelOf(role)}), works once until ${expires}:\n\n  ${url}/#invite=${token}\n`)
