import { z } from 'zod'
import { WebPushNotifier, type PushSubscription } from '../channels/web-push'
import { CapabilityError, ConflictError, NotAllowedError, ValidationError } from '../kernel/errors'
import { fromB64url } from '../kernel/encoding'
import { Logger } from '../kernel/logger'
import type { Module, Registry } from '../kernel/registry'
import { HttpClient } from '../security/egress'
import { Telemetry, type SpanOptions } from '../telemetry/telemetry'
import { Passkeys, Sessions, StepUpNeeded, deviceLabel, type SignedIn, type Tap } from './auth'
import { Calls } from './calls'
import { PwaModule, RELYING_PARTY, type PwaEnv, type PwaOptions } from './module'
import { Access } from './roles'
import type { User } from './stores'

// The driving side. The shell (HTML, JS, CSS, icons, the service worker) is
// static assets and never runs this code; only /api/* does. The shell holds
// nothing private, so it can sit in every cache. Everything behind /api/ needs
// a session, apart from the four routes that start one.
//
// Requests that change anything must come from our own origin (Origin header)
// as JSON; with SameSite=Strict cookies that's two separate locks on CSRF.

const MAX_BODY = 64 * 1024

const API_HEADERS = {
  'cache-control': 'no-store',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
}

export const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...API_HEADERS, ...headers } })

class Unauthorised extends CapabilityError {
  constructor() { super('unauthorised', 'Sign in first') }
}

interface Route {
  method: string
  /** Template for telemetry, e.g. /api/calls/:id/confirm. Never the real path: ids stay out of traces. */
  path: string
  pattern: RegExp
  /** Needs a session. */
  auth: boolean
  run(x: { c: Registry; env: PwaEnv; request: Request; body: Record<string, unknown>; params: string[]; me?: SignedIn }): Promise<Response>
}

const route = (method: string, path: string, auth: boolean, run: Route['run']): Route => ({
  method, path, auth, run,
  pattern: new RegExp(`^${path.replace(/:\w+/g, '([A-Za-z0-9_-]{1,1400})')}$`),
})

const str = (v: unknown, name: string, max = 200) => {
  if (typeof v !== 'string' || !v || v.length > max) throw new ValidationError(`${name} is missing`)
  return v
}

const pushSchema = z.object({
  endpoint: z.url().max(1024),
  keys: z.object({ p256dh: z.string().max(200), auth: z.string().max(100) }),
})
const PUSH_HOSTS = new HttpClient({ service: 'Web Push', allow: WebPushNotifier.PUSH_SERVICES })

function checkSubscription(input: unknown): PushSubscription {
  const parsed = pushSchema.safeParse(input)
  if (!parsed.success) throw new ValidationError('Not a push subscription')
  const sub = parsed.data
  // Only the browsers' own push services: we're never made to post anywhere else.
  if (!PUSH_HOSTS.allows(new URL(sub.endpoint))) throw new NotAllowedError('Not a push service we send to')
  let p256dh: Uint8Array, auth: Uint8Array
  try { p256dh = fromB64url(sub.keys.p256dh); auth = fromB64url(sub.keys.auth) } catch { throw new ValidationError('Bad push keys') }
  if (p256dh.length !== 65 || p256dh[0] !== 4 || auth.length !== 16) throw new ValidationError('Bad push keys')
  return { endpoint: sub.endpoint, keys: sub.keys }
}

const me = (x: { me?: SignedIn }) => x.me!.user

/**
 * The passkey tap for this request: the signature comes in the body as
 * `credential`, alongside the same fields that asked for the action. Without
 * one, the response is 428 with options to sign, and the shell sends the same
 * request again with the signature.
 */
const tapFor = (x: { c: Registry; body: Record<string, unknown>; me?: SignedIn }): Tap =>
  (action, details) => x.c.get(Passkeys).tap(me(x), x.body.credential, action, details)

/** Who's signed in, and what their role lets the shell show. The Worker checks every action again regardless. */
const userView = async (c: Registry, user: User) =>
  ({ name: user.name, atRisk: await c.get(Passkeys).atRisk(user), ...c.get(Access).abilities(user) })

const ROUTES: Route[] = [
  // Always answers, so the shell knows whether to show sign-in.
  route('GET', '/api/session', false, async ({ c, request }) => {
    const signedIn = await c.get(Sessions).read(request)
    const rp = c.get(RELYING_PARTY)
    const user = signedIn ? await userView(c, signedIn.user) : null
    // The address the app is set up for, so the shell can say so when it's opened anywhere else.
    return json({ app: { name: rp.name, origin: rp.origin }, user })
  }),
  route('DELETE', '/api/session', true, async ({ c, me: signedIn }) => {
    await c.get(Sessions).end(signedIn!.session)
    return json({ ok: true }, 200, { 'set-cookie': Sessions.clearCookie() })
  }),

  route('POST', '/api/register/options', false, async ({ c, body }) =>
    json(await c.get(Passkeys).registrationOptions(str(body.invite, 'invite')))),
  route('POST', '/api/register', false, async ({ c, body, request }) => {
    const { user, cookie } = await c.get(Passkeys).register(str(body.invite, 'invite'), body.credential, deviceLabel(request.headers.get('user-agent')))
    return json({ user: await userView(c, user) }, 200, { 'set-cookie': cookie })
  }),
  route('POST', '/api/login/options', false, async ({ c }) => json(await c.get(Passkeys).loginOptions())),
  route('POST', '/api/login', false, async ({ c, body }) => {
    const { user, cookie } = await c.get(Passkeys).login(body.credential)
    return json({ user: await userView(c, user) }, 200, { 'set-cookie': cookie })
  }),

  route('GET', '/api/tools', true, async x => json({ tools: await x.c.get(Calls).list(me(x)) })),
  route('POST', '/api/calls', true, async x =>
    json(await x.c.get(Calls).start(me(x), str(x.body.tool, 'tool'), x.body.args, x.body.answers))),
  route('POST', '/api/calls/:id/confirm', true, async x =>
    json(await x.c.get(Calls).confirm(me(x), x.params[0], x.body.credential))),
  route('POST', '/api/calls/:id/deny', true, async x => {
    await x.c.get(Calls).deny(me(x), x.params[0])
    return json({ ok: true })
  }),

  route('GET', '/api/devices', true, async x => {
    const current = x.me!.session.passkeyId
    const devices = (await x.c.get(Passkeys).devices(me(x))).map(p => ({ id: p.id, label: p.label, synced: p.synced, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt ?? null, current: p.id === current }))
    return json({ devices })
  }),
  route('DELETE', '/api/devices/:id', true, async x => {
    await x.c.get(Passkeys).remove(me(x), x.params[0], tapFor(x))
    return json({ ok: true })
  }),
  route('POST', '/api/invites', true, async x => {
    const { token, expiresAt } = await x.c.get(Passkeys).invite(me(x), {
      name: typeof x.body.name === 'string' ? x.body.name : undefined, role: typeof x.body.role === 'string' ? x.body.role : undefined, ownDevice: x.body.ownDevice === true,
    }, tapFor(x))
    return json({ link: `${x.c.get(RELYING_PARTY).origin}/#invite=${token}`, expiresAt })
  }),

  // People with the people permission only (checked in Passkeys): everyone, changing a role,
  // recovering someone who lost every device, removing someone.
  route('GET', '/api/people', true, async x => json({ people: await x.c.get(Passkeys).people(me(x)) })),
  route('POST', '/api/people/:id/recover', true, async x => {
    const { token, expiresAt } = await x.c.get(Passkeys).recover(me(x), x.params[0], tapFor(x))
    return json({ link: `${x.c.get(RELYING_PARTY).origin}/#invite=${token}`, expiresAt })
  }),
  route('PATCH', '/api/people/:id', true, async x => {
    await x.c.get(Passkeys).setRole(me(x), x.params[0], str(x.body.role, 'role', 32), tapFor(x))
    return json({ ok: true })
  }),
  route('DELETE', '/api/people/:id', true, async x => {
    await x.c.get(Passkeys).removePerson(me(x), x.params[0], tapFor(x))
    return json({ ok: true })
  }),

  route('GET', '/api/push', true, async ({ env }) => json({ publicKey: env.VAPID_PRIVATE_KEY ? env.VAPID_PUBLIC_KEY ?? null : null })),
  route('POST', '/api/push', true, async x => {
    await x.c.get(Passkeys).subscribe(x.me!, checkSubscription(x.body.subscription))
    return json({ ok: true })
  }),
  route('DELETE', '/api/push', true, async x => {
    await x.c.get(Passkeys).unsubscribe(me(x), str(x.body.endpoint, 'endpoint', 1024))
    return json({ ok: true })
  }),
]

function errorResponse(err: unknown, c: Registry, path: string): Response {
  if (err instanceof Unauthorised) return json({ error: err.message }, 401)
  if (err instanceof StepUpNeeded) return json({ error: err.message, stepUp: err.options }, 428)
  if (err instanceof NotAllowedError) {
    // Why a passkey was refused helps us; the person gets the same message either way.
    c.get(Logger).warn('pwa.refused', { route: path, error: err })
    return json({ error: err.message }, 403)
  }
  if (err instanceof ValidationError) return json({ error: err.message }, 400)
  if (err instanceof ConflictError) return json({ error: err.message }, 409)
  c.get(Logger).error('pwa.request.failed', { route: path, error: err })
  return json({ error: 'Something went wrong. It has been logged.' }, 500)
}

type Matched = { r: Route; params: string[] } | { path: string; response: Response }

function match(request: Request, url: URL): Matched {
  const hits = ROUTES.map(r => ({ r, m: r.pattern.exec(url.pathname) })).filter(x => x.m)
  if (!hits.length) return { path: 'unmatched', response: json({ error: 'Not found' }, 404) }
  const hit = hits.find(x => x.r.method === request.method)
  if (!hit) return { path: hits[0].r.path, response: json({ error: 'Method not allowed' }, 405, { allow: hits.map(x => x.r.method).join(', ') }) }
  return { r: hit.r, params: hit.m!.slice(1) }
}

async function handle(r: Route, params: string[], request: Request, c: Registry, env: PwaEnv): Promise<Response> {
  try {
    let body: Record<string, unknown> = {}
    if (request.method !== 'GET') {
      // Only our own pages can change anything.
      const { origin } = c.get(RELYING_PARTY)
      if (request.headers.get('origin') !== origin) throw new NotAllowedError(`This app only works at ${origin}`)
      if (Number(request.headers.get('content-length') ?? 0) > MAX_BODY) return json({ error: 'Too big' }, 413)
      const raw = await request.text()
      if (raw.length > MAX_BODY) return json({ error: 'Too big' }, 413)
      if (raw) {
        if (!(request.headers.get('content-type') ?? '').startsWith('application/json')) throw new ValidationError('Send JSON')
        try { body = JSON.parse(raw) } catch { throw new ValidationError('Send JSON') }
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw new ValidationError('Send a JSON object')
      }
    }
    const signedIn = r.auth ? await c.get(Sessions).read(request) : undefined
    if (r.auth && !signedIn) throw new Unauthorised()
    return await r.run({ c, env, request, body, params, me: signedIn })
  } catch (err) {
    return errorResponse(err, c, r.path)
  }
}

/** One invocation in a root span, flushed after the response has gone. */
function traced<T>(c: Registry, ctx: ExecutionContext, name: string, opts: SpanOptions, fn: () => Promise<T>): Promise<T> {
  const t = c.get(Telemetry)
  const p = t.run(() => t.inSpan(name, opts, fn))
  ctx.waitUntil(p.then(() => undefined, () => undefined).then(() => t.flush()))
  return p
}

export function createPwaWorker<E extends PwaEnv>(opts: { module: (env: E) => Module }): ExportedHandler<E> {
  // env is the same object for the life of an isolate, so so is the registry.
  const registries = new WeakMap<object, Registry>()
  const registryFor = (env: E) => {
    let c = registries.get(env)
    if (!c) { c = opts.module(env).build(); registries.set(env, c) }
    return c
  }

  return {
    async fetch(request, env, ctx) {
      const url = new URL(request.url)
      // With run_worker_first = ["/api/*"] nothing else gets here. If it does, it's the shell.
      if (!url.pathname.startsWith('/api/')) return env.ASSETS ? env.ASSETS.fetch(request) : new Response('Not found', { status: 404 })
      const c = registryFor(env)
      const m = match(request, url)
      const path = 'r' in m ? m.r.path : m.path
      return traced(c, ctx, `${request.method} ${path}`, { kind: 'server', attrs: { 'faas.trigger': 'http', 'http.request.method': request.method, 'http.route': path } }, async () => {
        const res = 'r' in m ? await handle(m.r, m.params, request, c, env) : m.response
        c.get(Logger).info('pwa.request', { route: path, method: request.method, status: res.status })
        return res
      })
    },

    async scheduled(controller, env, ctx) {
      const c = registryFor(env)
      await traced(c, ctx, `cron ${controller.cron}`, { kind: 'server', attrs: { 'faas.trigger': 'timer', 'faas.cron': controller.cron } }, async () => {
        const pruned = await c.get(Passkeys).prune()
        const calls = await c.get(Calls).prune()
        c.get(Logger).info('cron.done', { ...pruned, calls })
      })
    },
  }
}

/**
 * A client's app: passkey sign-in, their automations as forms, approvals with
 * a passkey tap, and notifications. Give it the tool servers that run inside it:
 *
 *   export default createPwaShell({ tools: ({ env, notify }) => [jobTools(env), quoteTools(notify)] })
 *
 * Pass `module` instead to change more than the tools, with a subclass of PwaModule.
 */
export function createPwaShell<E extends PwaEnv = PwaEnv>(opts: PwaOptions<E> & { module?: (env: E) => Module } = {}): ExportedHandler<E> {
  return createPwaWorker<E>({ module: opts.module ?? (env => new PwaModule<E>(env, opts)) })
}
