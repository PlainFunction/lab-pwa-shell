// The app shell: sign in with a passkey, run automations from forms, approve
// with a passkey, turn on notifications. No framework: a dozen screens don't
// need one, and every byte here is downloaded on a phone.
//
// Text from the server only ever goes in with textContent, never innerHTML,
// so a tool's output can't become markup. The CSP (script-src 'self') backs that up.

import { fieldsOf, missing, readForm, shownOf, summaryOf, type Field, type Schema, type Shown } from '../forms'

type Json = Record<string, any>
interface Tool { name: string; title: string; description: string; confirm: boolean; inputSchema: Schema; outputSchema?: Schema }
interface Answer { action: 'accept'; content: Json }

const root = document.getElementById('app')!
let appName = document.title
interface Named { id: string; label: string }
/**
 * Who's signed in and what their role lets the screens show. The Worker checks
 * every action again, so this only decides what's drawn. atRisk: one passkey
 * that doesn't sync, so losing this device locks them out.
 */
let me: { name: string; atRisk?: boolean; role: Named; people: boolean; invites: Named[]; flags: string[] } | null = null

// ── DOM ─────────────────────────────────────────────────────────────────────

type Kid = Node | string | false | null | undefined | Kid[]
const flat = (kids: Kid[]): (Node | string)[] => kids.flatMap(k => Array.isArray(k) ? flat(k) : k === false || k === null || k === undefined ? [] : [k])
function h(tag: string, props: Json | null = null, ...kids: Kid[]): HTMLElement {
  const el = document.createElement(tag)
  for (const [k, v] of Object.entries(props ?? {})) {
    if (v === undefined || v === false || v === null) continue
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v as EventListener)
    else if (k === 'class') el.className = String(v)
    else if (v === true) el.setAttribute(k, '')
    else el.setAttribute(k, String(v))
  }
  for (const kid of flat(kids)) el.append(kid)
  return el
}

const show = (...nodes: Kid[]) => {
  root.replaceChildren(...flat(nodes))
  window.scrollTo(0, 0)
  root.querySelector<HTMLElement>('h1, h2')?.focus()
}

const heading = (text: string, cls?: string) => h('h1', { tabindex: '-1', class: cls }, text)
const eyebrow = (text: string) => h('p', { class: 'eyebrow' }, text)
const note = (text: string, cls = 'muted') => h('p', { class: cls }, text)
const button = (text: string, onclick: (e: Event) => unknown, cls = 'btn') =>
  h('button', { type: 'button', class: cls, onclick: (e: Event) => busy(e.currentTarget as HTMLButtonElement, () => onclick(e)) }, text)

/** Disables a button while its work runs, and shows any error under it. */
async function busy(btn: HTMLButtonElement, fn: () => unknown) {
  btn.disabled = true
  btn.parentElement?.querySelector('.error')?.remove()
  try { await fn() } catch (err) {
    if (err instanceof SignedOut) return
    btn.after(note(message(err), 'error'))
  } finally { btn.disabled = false }
}

const message = (err: unknown) =>
  err instanceof DOMException && err.name === 'NotAllowedError' ? 'The passkey prompt was closed or timed out. Try again when you\'re ready.'
    : err instanceof Error ? err.message : 'Something went wrong'

// ── API ─────────────────────────────────────────────────────────────────────

class SignedOut extends Error {}

async function api<T = Json>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store',
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = await res.json().catch(() => ({}))
  if (res.status === 401) { me = null; signIn(); throw new SignedOut() }
  if (!res.ok) throw new Error(data.error ?? `Something went wrong (${res.status})`)
  return data as T
}

// ── Passkeys ────────────────────────────────────────────────────────────────

const toBytes = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0))
const toB64 = (buf: ArrayBuffer | null) => buf ? btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : null
const ids = (list: { id: string; type: 'public-key' }[] = []) => list.map(c => ({ ...c, id: toBytes(c.id) }))

async function createPasskey(o: Json) {
  const cred = await navigator.credentials.create({ publicKey: { ...o, challenge: toBytes(o.challenge), user: { ...o.user, id: toBytes(o.user.id) }, excludeCredentials: ids(o.excludeCredentials) } as unknown as PublicKeyCredentialCreationOptions }) as PublicKeyCredential
  const r = cred.response as AuthenticatorAttestationResponse
  return { id: cred.id, rawId: toB64(cred.rawId), type: cred.type, response: { clientDataJSON: toB64(r.clientDataJSON), attestationObject: toB64(r.attestationObject), transports: r.getTransports?.() ?? [] } }
}

async function usePasskey(o: Json) {
  const cred = await navigator.credentials.get({ publicKey: { ...o, challenge: toBytes(o.challenge), allowCredentials: ids(o.allowCredentials) } as unknown as PublicKeyCredentialRequestOptions }) as PublicKeyCredential
  const r = cred.response as AuthenticatorAssertionResponse
  return { id: cred.id, rawId: toB64(cred.rawId), type: cred.type, response: { clientDataJSON: toB64(r.clientDataJSON), authenticatorData: toB64(r.authenticatorData), signature: toB64(r.signature), userHandle: toB64(r.userHandle) } }
}

const hasPasskeys = () => typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials

// ── Install ─────────────────────────────────────────────────────────────────

let installPrompt: (Event & { prompt(): Promise<void> }) | null = null
window.addEventListener('beforeinstallprompt', e => { e.preventDefault(); installPrompt = e as typeof installPrompt })
const standalone = () => matchMedia('(display-mode: standalone)').matches || (navigator as { standalone?: boolean }).standalone === true
const ios = () => /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)

function installHint(): Kid {
  if (standalone()) return null
  if (installPrompt) return h('div', { class: 'card' }, note('Put this app on your home screen or desktop, so it opens in its own window.'), button('Install the app', async () => { await installPrompt!.prompt(); installPrompt = null }, 'btn ghost'))
  if (ios()) return h('div', { class: 'card' }, note('To put this on your home screen: tap Share, then Add to Home Screen. Notifications on iPhone only work from there.'))
  return null
}

// ── Notifications ───────────────────────────────────────────────────────────
// On by default. Right after set-up the app asks (browsers only show the prompt
// after a tap), and once a device allows them it's subscribed again every time
// the app opens, so a new phone or a recovered account picks them back up.
// Turning them off in Settings is remembered on this device.

const PUSH_OFF = 'pf-push-off'
const pushOff = () => { try { return localStorage.getItem(PUSH_OFF) === '1' } catch { return false } }
const setPushOff = (off: boolean) => { try { if (off) localStorage.setItem(PUSH_OFF, '1'); else localStorage.removeItem(PUSH_OFF) } catch { /* private mode */ } }
const canPush = () => 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window

let pushKey: Promise<string | null> | undefined
const pushKeyOf = () => pushKey ??= api<{ publicKey: string | null }>('GET', '/api/push').then(r => r.publicKey).catch(() => { pushKey = undefined; return null })

/** Subscribes this device and tells the Worker. Only asks for permission when `ask` (after a tap), and asks first, while the tap still counts. */
async function enablePush(ask: boolean): Promise<void> {
  if (Notification.permission !== 'granted') {
    if (!ask) return
    if ((await Notification.requestPermission()) !== 'granted') throw new Error('Notifications are blocked for this site. Allow them in the browser settings, then try again.')
  }
  const key = await pushKeyOf()
  if (!key) return
  const reg = await navigator.serviceWorker.ready
  const sub = await reg.pushManager.getSubscription() ?? await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: toBytes(key) })
  await api('POST', '/api/push', { subscription: sub.toJSON() })
  setPushOff(false)
}

/** "Not now" on the set-up prompt: don't ask again until the app is next opened. */
let pushLater = false

/** Worth offering: this browser can, the app has them set up, and nobody has said yes or no on this device. */
const offerPush = async () => canPush() && Notification.permission === 'default' && !pushOff() && !pushLater && !!(await pushKeyOf())

let pushSynced = false
/** Once a page load: a device that already allowed them is subscribed, silently. */
function syncPush() {
  if (pushSynced || !canPush() || pushOff() || Notification.permission !== 'granted') return
  pushSynced = true
  enablePush(false).catch(() => { pushSynced = false })
}

function notifyPrompt() {
  show(entry(
    eyebrow('One more thing'),
    heading('Turn on notifications'),
    note("So this device tells you when something needs you, like a quote waiting for your OK."),
    button('Turn on', async () => { await enablePush(true); await home() }),
    button('Not now', () => { pushLater = true; return home() }, 'link'),
  ))
}

// ── Screens ─────────────────────────────────────────────────────────────────

/** Sign in, set up and the error screens: the mark, a heading and one thing to do, in the middle. */
const entry = (...kids: Kid[]) => h('div', { class: 'entry' }, h('span', { class: 'mark', 'aria-hidden': 'true' }), kids)

function signIn() {
  show(entry(
    eyebrow('Sign in'),
    heading(appName),
    note('Use the passkey on this device: Face ID, a fingerprint or your PIN.'),
    hasPasskeys() ? button('Sign in', async () => {
      const options = await api('POST', '/api/login/options')
      const res = await api<{ user: typeof me }>('POST', '/api/login', { credential: await usePasskey(options) })
      me = res.user
      await home()
    }) : note('This browser can\'t use passkeys. Try Safari, Chrome, Edge or Firefox, up to date.', 'error'),
    note("New here? You'll need an invite link from whoever runs this app.", 'muted fine'),
    installHint(),
  ))
}

function setUp(invite: string) {
  show(entry(
    eyebrow('Your invite'),
    heading(`Welcome to ${appName}`),
    note('Set up a passkey and you\'ll sign in with Face ID, a fingerprint or your PIN. No password to remember.'),
    button('Set up this device', async () => {
      const options = await api('POST', '/api/register/options', { invite })
      const res = await api<{ user: typeof me }>('POST', '/api/register', { invite, credential: await createPasskey(options) })
      me = res.user
      if (await offerPush()) notifyPrompt()
      else await home()
    }),
    note('The link works once. If it has run out, ask for a new one.', 'muted fine'),
  ))
}

const bar = (back?: () => unknown) => h('header', { class: 'bar' },
  back ? button('← Back', back, 'link') : h('strong', null, h('span', { class: 'mark', 'aria-hidden': 'true' }), appName),
  back ? null : button('Settings', settings, 'link'),
)

/** An automation with nothing to fill in runs as soon as it's tapped (or goes straight to approval). */
const open = (t: Tool) => fieldsOf(t.inputSchema).length ? form(t) : run(t, {}, [])

async function home() {
  const [{ tools }, offer] = await Promise.all([api<{ tools: Tool[] }>('GET', '/api/tools'), offerPush()])
  syncPush()
  const pushCard = offer ? h('div', { class: 'card' },
    note('Get a notification on this device when something needs you.'),
    h('div', { class: 'actions' },
      button('Turn on', async () => { await enablePush(true); pushCard?.remove() }, 'btn small'),
      button('Not now', async () => { setPushOff(true); pushCard?.remove() }, 'link'),
    ),
  ) : null
  show(
    bar(),
    eyebrow(new Date().toLocaleDateString('en-AU', { weekday: 'long', day: 'numeric', month: 'long' })),
    heading(`Hi ${me?.name ?? ''}`.trim()),
    pushCard,
    tools.length ? h('ul', { class: 'tools' }, tools.map(t => h('li', null,
      h('button', { type: 'button', class: 'card tool', onclick: (e: Event) => busy(e.currentTarget as HTMLButtonElement, () => open(t)) },
        h('strong', null, t.title),
        h('span', { class: 'muted' }, t.description),
        t.confirm ? h('span', { class: 'tag' }, 'Asks for your passkey') : null,
      ),
    ))) : note('Nothing is set up here yet.'),
    me?.atRisk ? h('div', { class: 'card warn' },
      note('Only this device can sign you in. If you lose it, someone else here has to let you back in. Adding a second device (a laptop is fine) avoids that.'),
      button('Add another device', settings, 'btn ghost'),
    ) : null,
    installHint(),
  )
}

function input(f: Field, value: unknown): HTMLElement {
  const id = `f-${f.name}`
  const common = { id, name: f.name, required: f.required, 'aria-describedby': f.description ? `${id}-d` : undefined }
  let el: HTMLElement
  if (f.kind === 'textarea') el = h('textarea', { ...common, rows: 4, maxlength: f.maxLength }, value === undefined ? '' : String(value))
  else if (f.kind === 'select') el = h('select', common, h('option', { value: '' }, 'Choose…'), (f.options ?? []).map(o => h('option', { value: o, selected: value === o }, o)))
  else if (f.kind === 'checkbox') el = h('input', { ...common, type: 'checkbox', checked: value === true })
  else el = h('input', { ...common, type: f.kind, step: f.kind === 'number' ? 'any' : undefined, maxlength: f.maxLength, value: value === undefined ? undefined : String(value), autocomplete: 'off' })
  return h('div', { class: f.kind === 'checkbox' ? 'field check' : 'field' },
    h('label', { for: id }, f.label, f.required ? '' : h('span', { class: 'muted' }, ' (optional)')),
    el,
    f.description ? h('small', { id: `${id}-d`, class: 'muted' }, f.description) : null,
  )
}

function values(formEl: HTMLFormElement, fields: Field[]) {
  const raw: Record<string, string | boolean> = {}
  for (const f of fields) {
    const el = formEl.elements.namedItem(f.name) as HTMLInputElement | null
    raw[f.name] = f.kind === 'checkbox' ? !!el?.checked : el?.value ?? ''
  }
  return readForm(fields, raw)
}

/** A tool's form, or a follow-up question's. Submitting runs it (or asks for the passkey). */
function form(t: Tool, o: { args?: Json; answers?: Answer[]; question?: { message: string; schema: Schema } } = {}) {
  const fields = fieldsOf(o.question?.schema ?? t.inputSchema)
  const submit = async (formEl: HTMLFormElement) => {
    const filled = values(formEl, fields)
    const empty = missing(fields, filled)
    if (empty.length) throw new Error(`Still needed: ${empty.join(', ')}`)
    const args = o.question ? o.args ?? {} : filled
    const answers = o.question ? [...(o.answers ?? []), { action: 'accept' as const, content: filled }] : o.answers ?? []
    await run(t, args, answers)
  }
  const btn = h('button', { type: 'submit', class: 'btn' }, t.confirm ? 'Review' : 'Go') as HTMLButtonElement
  const formEl = h('form', { novalidate: true, onsubmit: (e: Event) => { e.preventDefault(); busy(btn, () => submit(formEl)) } },
    fields.map(f => input(f, o.question ? undefined : o.args?.[f.name])), btn) as HTMLFormElement
  show(bar(home), heading(t.title), note(o.question?.message ?? t.description), formEl)
}

async function run(t: Tool, args: Json, answers: Answer[]) {
  const outcome = await api('POST', '/api/calls', { tool: t.name, args, answers })
  await after(t, outcome, args, answers)
}

async function after(t: Tool, outcome: Json, args: Json, answers: Answer[]) {
  if (outcome.status === 'confirm') return confirm(t, outcome, args, answers)
  if (outcome.status === 'ask') return form(t, { args, answers, question: { message: outcome.message, schema: outcome.schema } })
  result(t, outcome)
}

/** What's about to happen, and the one tap that approves it. The passkey signs a hash of exactly this. */
function confirm(t: Tool, outcome: Json, args: Json, answers: Answer[]) {
  const rows = summaryOf(fieldsOf(t.inputSchema), args)
  show(
    bar(() => fieldsOf(t.inputSchema).length ? form(t, { args, answers }) : home()),
    eyebrow('Needs your passkey'),
    heading('Check and approve'),
    note(`This will run "${t.title}" with:`),
    rows.length ? h('dl', { class: 'card summary' }, rows.map(r => [h('dt', null, r.label), h('dd', null, r.value)])) : note('No details.'),
    button('Approve with passkey', async () => {
      const credential = await usePasskey(outcome.options)
      await after(t, await api('POST', `/api/calls/${outcome.id}/confirm`, { credential }), args, answers)
    }),
    button('Cancel', async () => { await api('POST', `/api/calls/${outcome.id}/deny`, {}); await home() }, 'btn ghost'),
    note('Nothing happens until you approve. This expires in 10 minutes.', 'muted fine'),
  )
}

/** An out.list: rows with the meta (a time, an amount) in a column on the left, like a run sheet. */
const rows = (s: Shown) => [
  h('p', { class: 'label' }, s.label),
  s.items?.length
    ? h('ul', { class: 'list rows' }, s.items.map(i => h('li', null,
      i.meta ? h('span', { class: 'meta' }, i.meta) : null,
      h('div', null, h('strong', null, i.title), i.detail ? note(i.detail, 'muted fine') : null),
    )))
    : note('Nothing here.'),
]

/** A result in the order the tool lists its outputs, with fields next to each other sharing one card. */
function body(shown: Shown[]): Kid[] {
  const out: Kid[] = []
  let fields: Shown[] = []
  const flush = () => {
    if (fields.length) out.push(h('dl', { class: 'card summary' }, fields.map(s => [h('dt', null, s.label), h('dd', null, s.value)])))
    fields = []
  }
  for (const s of shown) {
    if (s.kind === 'field') { fields.push(s); continue }
    flush()
    out.push(s.kind === 'header' ? h('h2', null, s.value)
      : s.kind === 'list' ? rows(s)
        : s.kind === 'text' ? h('p', null, s.value)
          : s.kind === 'context' ? note(s.value, 'muted fine')
            : s.kind === 'link' ? h('p', null, h('a', { href: s.value, rel: 'noopener noreferrer', target: '_blank' }, s.label))
              : h('img', { src: s.value, alt: s.label, class: 'shot' }))
  }
  flush()
  return out
}

function result(t: Tool, outcome: Json) {
  const shown = outcome.ok ? shownOf(t.outputSchema, outcome.content ?? {}) : []
  const headers = shown.filter(s => s.kind === 'header')
  // Something read-only with nothing to fill in, like today's jobs: it's a page to look at, not a task that finished.
  const view = outcome.ok && !t.confirm && fieldsOf(t.inputSchema).length === 0
  show(
    bar(home),
    view ? [eyebrow(t.title), heading(headers[0]?.value ?? t.title)]
      : heading(outcome.ok ? 'Done' : "That didn't work", outcome.ok ? 'ok' : undefined),
    outcome.ok ? null : note(outcome.error ?? 'The automation failed.', 'error'),
    // On a view, the first header is already the page's heading.
    body(view && headers[0] ? shown.filter(s => s !== headers[0]) : shown),
    view ? button('Refresh', () => run(t, {}, []), 'btn ghost') : null,
    button('Back to the list', home, 'btn ghost'),
  )
}

// ── Settings ────────────────────────────────────────────────────────────────

async function pushSection(): Promise<Kid> {
  if (!canPush()) {
    return h('section', null, h('h2', null, 'Notifications'), note(ios() && !standalone() ? 'On iPhone, add this app to your home screen first, then turn notifications on from there.' : "This browser can't show notifications."))
  }
  if (!(await pushKeyOf())) return null
  const reg = await navigator.serviceWorker.ready
  const current = await reg.pushManager.getSubscription()
  return h('section', null, h('h2', null, 'Notifications'),
    note(current ? 'This device gets notifications.'
      : Notification.permission === 'denied' ? 'Notifications are blocked for this app. Allow them in the browser or phone settings, then come back here.'
        : 'Off on this device.'),
    current
      ? button('Turn off on this device', async () => {
        setPushOff(true)
        await api('DELETE', '/api/push', { endpoint: current.endpoint })
        await current.unsubscribe()
        await settings()
      }, 'btn ghost')
      : Notification.permission === 'denied' ? null : button('Turn on', async () => { await enablePush(true); await settings() }),
  )
}

function inviteLink(link: string, expiresAt: string) {
  const text = h('input', { type: 'text', readonly: true, value: link, 'aria-label': 'Invite link' }) as HTMLInputElement
  return h('div', { class: 'card' }, text,
    button('share' in navigator ? 'Share' : 'Copy', async () => {
      if (navigator.share) await navigator.share({ title: appName, url: link }).catch(() => {})
      else { await navigator.clipboard.writeText(link); text.select() }
    }, 'btn ghost'),
    note(`Works once, until ${new Date(expiresAt).toLocaleString('en-AU', { dateStyle: 'medium', timeStyle: 'short' })}. Send it only to the person it's for.`),
  )
}

/** A small action that asks once more before doing something that can't be undone. */
function twoStep(label: string, warning: string, yes: string, act: () => Promise<unknown>, cls = 'link danger') {
  const slot = h('div', { class: 'step' })
  const first = button(label, async () => {
    slot.replaceChildren(h('div', { class: 'confirm' }, note(warning), h('div', { class: 'actions' },
      button(yes, async () => { await act(); slot.replaceChildren(first) }, 'btn small danger'),
      button('Cancel', async () => slot.replaceChildren(first), 'link'),
    )))
  }, cls)
  slot.append(first)
  return slot
}

/** A role picker. Changing it saves straight away and says so; a refusal puts it back. */
function rolePicker(p: Json) {
  const status = h('span', { class: 'muted fine', role: 'status' })
  const pick = h('select', {
    class: 'small', 'aria-label': `Role for ${p.name}`,
    onchange: async () => {
      status.textContent = 'Saving…'
      try {
        await api('PATCH', `/api/people/${p.id}`, { role: pick.value })
        p.role = pick.value
        status.textContent = 'Saved'
      } catch (err) {
        pick.value = p.role
        status.textContent = err instanceof SignedOut ? '' : message(err)
      }
    },
  }, (me?.invites ?? []).map(r => h('option', { value: r.id, selected: r.id === p.role }, r.label))) as HTMLSelectElement
  return h('div', { class: 'role' }, pick, status)
}

async function peopleSection(): Promise<Kid> {
  if (!me?.people) return null
  const { people } = await api<{ people: Json[] }>('GET', '/api/people')
  const others = people.filter(p => !p.you)
  if (!others.length) return null
  return h('section', null, h('h2', null, 'People'),
    note('Someone lost every device? Recover their access: it signs them out everywhere straight away and gives you a new set-up link for them.'),
    h('ul', { class: 'list' }, others.map(p => {
      const link = h('div')
      const used = p.lastUsedAt ? `Last used ${new Date(p.lastUsedAt).toLocaleDateString('en-AU')}` : 'Not used yet'
      return h('li', null,
        h('div', { class: 'who' }, h('strong', null, p.name), rolePicker(p)),
        note(`${p.devices} ${p.devices === 1 ? 'device' : 'devices'}${p.synced ? ', synced' : ''}. ${used}.`, 'muted fine'),
        h('div', { class: 'actions' },
          twoStep('Recover access', `This removes all of ${p.name}'s devices and signs them out now. They'll need the new link to get back in.`, 'Yes, recover access', async () => {
            const { link: url, expiresAt } = await api('POST', `/api/people/${p.id}/recover`, {})
            link.replaceChildren(inviteLink(url, expiresAt))
          }, 'link'),
          twoStep('Remove', `${p.name} won't be able to open the app at all. You can invite them again later.`, `Yes, remove ${p.name}`, async () => {
            await api('DELETE', `/api/people/${p.id}`)
            await settings()
          }),
        ),
        link,
      )
    })),
  )
}

async function settings() {
  const [{ devices }, push, people] = await Promise.all([api<{ devices: Json[] }>('GET', '/api/devices'), pushSection(), peopleSection()])
  if (me) me.atRisk = devices.length === 1 && !devices[0].synced
  const added = h('div')
  const invited = h('div')
  const who = h('input', { type: 'text', id: 'who', maxlength: 60, autocomplete: 'off' }) as HTMLInputElement
  const roles = me?.invites ?? []
  // The least a new person can be is usually the right start, so the last role listed is picked.
  const role = h('select', { id: 'as' }, roles.map((r, i) => h('option', { value: r.id, selected: i === roles.length - 1 }, r.label))) as HTMLSelectElement
  show(
    bar(home),
    heading('Settings'),
    me ? note(`Signed in as ${me.name}, ${me.role.label}.`, 'muted') : null,
    push,
    h('section', null, h('h2', null, 'Your devices'),
      h('ul', { class: 'list' }, devices.map(d => h('li', null,
        h('strong', null, d.label, d.current ? ' (this one)' : ''),
        note(`${d.synced ? 'Synced passkey' : 'This device only'}. Added ${new Date(d.createdAt).toLocaleDateString('en-AU')}.`, 'muted fine'),
        devices.length > 1 ? button('Remove', async () => { await api('DELETE', `/api/devices/${d.id}`); d.current ? signIn() : await settings() }, 'link danger') : null,
      ))),
      button('Add another device', async () => {
        const { link, expiresAt } = await api('POST', '/api/invites', { ownDevice: true })
        added.replaceChildren(inviteLink(link, expiresAt))
      }, 'btn ghost'),
      added,
      note('Lost a phone? Remove it here and it is signed out straight away.'),
    ),
    roles.length ? h('section', null, h('h2', null, 'Invite someone'),
      h('div', { class: 'field' }, h('label', { for: 'who' }, 'Their name'), who),
      roles.length > 1
        ? h('div', { class: 'field' }, h('label', { for: 'as' }, 'Their role'), role)
        : note(`They'll join as ${roles[0].label}.`, 'muted fine'),
      button('Make an invite link', async () => {
        const { link, expiresAt } = await api('POST', '/api/invites', { name: who.value, role: roles.length > 1 ? role.value : roles[0].id })
        invited.replaceChildren(inviteLink(link, expiresAt))
      }, 'btn ghost'),
      invited,
    ) : null,
    people,
    h('section', null, button('Sign out', async () => { await api('DELETE', '/api/session'); me = null; signIn() }, 'btn ghost')),
  )
}

// ── Start ───────────────────────────────────────────────────────────────────

async function start() {
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {})
  // The invite is in the fragment, so it never reached a server. Take it out of the address bar and history too.
  const invite = new URLSearchParams(location.hash.slice(1)).get('invite')
  if (invite) history.replaceState(null, '', location.pathname)
  try {
    const session = await api<{ app: { name: string; origin: string }; user: typeof me }>('GET', '/api/session')
    appName = session.app.name
    me = session.user
    // Passkeys belong to one address. Opened at any other (a new tunnel, a workers.dev
    // name), nothing would work, so say where it does instead of failing on the first tap.
    if (session.app.origin !== location.origin) {
      show(entry(heading(appName), note(`This app is set up for ${session.app.origin}, so it can't sign anyone in here.`, 'error'),
        h('p', null, h('a', { href: `${session.app.origin}/${invite ? `#invite=${invite}` : ''}` }, 'Open it there'))))
      return
    }
  } catch (err) {
    show(entry(heading(appName), note(navigator.onLine ? message(err) : "You're offline. This app needs a connection to do anything.", 'error'), button('Try again', start)))
    return
  }
  if (invite && /^[A-Za-z0-9_-]{32}$/.test(invite)) return setUp(invite)
  if (!me) return signIn()
  await home().catch(err => { if (!(err instanceof SignedOut)) show(entry(heading(appName), note(message(err), 'error'), button('Try again', start))) })
}

// Pasting an invite link into a tab that already has the app open only changes
// the fragment, which doesn't reload the page. Start again so it's seen.
window.addEventListener('hashchange', () => { if (location.hash.includes('invite=')) start() })

start()
