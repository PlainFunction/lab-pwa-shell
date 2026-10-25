import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'
import schema from '../capabilities/core/schema.sql?raw'
import { SoftwarePasskey, b64url, randomBytes, sha256Hex } from '#capabilities'
import type { LabEnv } from '../src/scanning'
import worker from '../src/worker'

// The app itself is tested in capabilities/core/pwa. These check this
// Worker's own part: that it starts with this config, has these automations,
// and that a passkey gets someone from an invite to an approved follow-up.

const ORIGIN = 'https://harbour.example'
const ctx = { waitUntil() {}, passThroughOnException() {}, props: {} } as unknown as ExecutionContext
const labEnv = (over: Partial<LabEnv> = {}): LabEnv => ({
  APP_NAME: 'Harbour Plumbing', PUBLIC_URL: ORIGIN, DB: env.DB, KV: env.KV, SCANS: env.SCANS,
  KEYRING: JSON.stringify({ current: 'k1', keys: { k1: b64url(randomBytes(32)) } }), ...over,
})

beforeEach(async () => {
  const statements = schema.split('\n').filter(l => !l.trim().startsWith('--')).join('\n').split(';').map(s => s.trim()).filter(Boolean)
  await env.DB.batch(statements.map(s => env.DB.prepare(s)))
  await env.DB.batch(['pwa_users', 'pwa_passkeys', 'pwa_invites', 'pwa_sessions', 'pwa_challenges', 'pwa_calls', 'audit_log'].map(t => env.DB.prepare(`DELETE FROM ${t}`)))
})

/** A phone with a passkey, signed in through an invite like the one scripts/invite.mjs makes. */
async function phone(e: LabEnv, role = 'admin', name = 'Dan') {
  let cookie = ''
  const call = async (method: string, path: string, body?: unknown) => {
    const headers: Record<string, string> = { origin: ORIGIN }
    if (cookie) headers.cookie = cookie
    if (body !== undefined) headers['content-type'] = 'application/json'
    const res = await worker.fetch!(new Request(`${ORIGIN}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }) as never, e, ctx)
    cookie = res.headers.get('set-cookie')?.split(';')[0] ?? cookie
    return { status: res.status, body: await res.json() as Record<string, any> }
  }
  const token = b64url(randomBytes(24))
  await env.DB.prepare("INSERT INTO pwa_invites (id, name, role, user_id, created_by, expires_at) VALUES (?, ?, ?, NULL, 'operator', '2999-01-01T00:00:00Z')").bind(await sha256Hex(token), name, role).run()
  const key = await SoftwarePasskey.create(ORIGIN)
  const options = await call('POST', '/api/register/options', { invite: token })
  await call('POST', '/api/register', { invite: token, credential: await key.register(options.body as never) })
  /** A photo from the camera, as the shell uploads it for the form. */
  const upload = async (bytes: Uint8Array) => {
    const headers: Record<string, string> = { origin: ORIGIN, cookie, 'content-type': 'image/jpeg', 'x-file-name': 'IMG_0412.jpg' }
    const res = await worker.fetch!(new Request(`${ORIGIN}/api/uploads`, { method: 'POST', headers, body: bytes }) as never, e, ctx)
    return { status: res.status, body: await res.json() as Record<string, any> }
  }
  return { call, upload, key }
}

describe('this Worker', () => {
  it('starts with this config and has these automations', async () => {
    const { call } = await phone(labEnv())
    expect((await call('GET', '/api/session')).body).toEqual({
      app: { name: 'Harbour Plumbing', origin: 'https://harbour.example' },
      user: {
        name: 'Dan', atRisk: false, role: { id: 'admin', label: 'Owner' }, people: true, flags: ['see:prices'],
        invites: [{ id: 'admin', label: 'Owner' }, { id: 'office', label: 'Office' }, { id: 'tradie', label: 'Tradie' }],
      },
    })
    const tools = (await call('GET', '/api/tools')).body.tools as { name: string; confirm: boolean }[]
    expect(tools.map(t => [t.name, t.confirm])).toEqual([['jobs__today', false], ['quotes__follow_up', true], ['notify__test', true], ['scans__scan', true], ['scans__recent', false]])
  })

  it("shows today's jobs straight away, with what they're worth only for roles that see prices", async () => {
    const owner = await phone(labEnv())
    const res = await owner.call('POST', '/api/calls', { tool: 'jobs__today', args: {} })
    expect(res.body.status).toBe('done')
    expect(res.body.content.jobs).toHaveLength(3)
    expect(res.body.content.jobs[0]).toEqual({ title: 'Blocked drain', detail: 'Marrickville, $280.00', meta: '7:30am' })
    expect(res.body.content.booked).toBe('$430.00')

    const tradie = await phone(labEnv(), 'tradie', 'Kim')
    const theirs = (await tradie.call('POST', '/api/calls', { tool: 'jobs__today', args: {} })).body.content
    expect(theirs.jobs[0]).toEqual({ title: 'Blocked drain', detail: 'Marrickville', meta: '7:30am' })
    expect(theirs.booked).toBeUndefined()
  })

  it('gives each role only its own automations', async () => {
    const names = async (role: string) => ((await (await phone(labEnv(), role, role)).call('GET', '/api/tools')).body.tools as { name: string }[]).map(t => t.name)
    expect(await names('office')).toEqual(['jobs__today', 'quotes__follow_up', 'scans__scan', 'scans__recent'])
    expect(await names('tradie')).toEqual(['jobs__today', 'scans__scan'])
  })

  it('follows up a quote only after a passkey approves it', async () => {
    const { call, key } = await phone(labEnv())
    const held = await call('POST', '/api/calls', { tool: 'quotes__follow_up', args: { customer: 'Ana Silva', email: 'ana@example.com', quote: 'Q-1042', amount: 1850 } })
    expect(held.body.status).toBe('confirm')
    const done = await call('POST', `/api/calls/${held.body.id}/confirm`, { credential: await key.sign(held.body.options as never) })
    expect(done.body.content).toMatchObject({ to: 'ana@example.com', quote: 'Q-1042, $1,850.00' })
  })

  it("says notifications aren't set up rather than pretending", async () => {
    const { call, key } = await phone(labEnv())
    const held = await call('POST', '/api/calls', { tool: 'notify__test', args: { message: 'Hello', to: 'Everyone' } })
    const res = await call('POST', `/api/calls/${held.body.id}/confirm`, { credential: await key.sign(held.body.options as never) })
    expect(res.body).toEqual({ status: 'done', ok: false, error: 'Notifications are not set up: VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY and VAPID_SUBJECT' })
  })

  it('scans a photo from the camera after a passkey approves it, files it in R2, and lists it', async () => {
    const { call, upload, key } = await phone(labEnv())
    const photo = crypto.getRandomValues(new Uint8Array(2048))
    const up = await upload(photo)
    expect(up.status).toBe(200)
    const held = await call('POST', '/api/calls', { tool: 'scans__scan', args: { photo: up.body.id } })
    expect(held.body.status).toBe('confirm')
    const done = await call('POST', `/api/calls/${held.body.id}/confirm`, { credential: await key.sign(held.body.options as never) })
    expect(done.body).toEqual({ status: 'done', ok: true, content: {
      title: 'Reece receipt (sample)', filed: 'Bill, dated 2026-10-17', next: "It's filed.",
      note: "Workers AI isn't connected, so every photo reads as the same sample receipt.",
    } })
    const stored = await env.SCANS.get(`scans/${[...new Uint8Array(await crypto.subtle.digest('SHA-256', photo))].map(b => b.toString(16).padStart(2, '0')).join('')}`)
    // Filed sealed with the KEYRING, so the bucket on its own holds nothing readable.
    expect(stored!.customMetadata).toMatchObject({ sealed: '1' })
    expect(await stored!.text()).toMatch(/^v1\.k1\./)
    const recent = await call('POST', '/api/calls', { tool: 'scans__recent', args: {} })
    expect(recent.body.content.scans[0]).toMatchObject({ title: 'Reece receipt (sample)', detail: 'Bill, dated 2026-10-17' })
  })
})
