import type { AuditLog } from '../audit/audit-log'
import type { PushSubscription, PushSubscriptionStore } from '../channels/web-push'
import type { Clock } from '../kernel/clock'
import { ConflictError, NotAllowedError, ValidationError } from '../kernel/errors'
import { b64url, randomBytes, sha256Hex } from '../kernel/encoding'
import type { Access } from './roles'
import type { AccountStore, ChallengeStore, Passkey, Session, SessionStore, User } from './stores'
import { ALGORITHMS, assertionSchema, claimedChallenge, verifyAssertion, verifyRegistration, type RelyingParty } from './webauthn/webauthn'

// Signing in to the app. There are no passwords and no sign-in links: a
// person gets a one-time invite, makes a passkey with it (Face ID, a
// fingerprint or the device PIN), and from then on signs in with that passkey.
// The passkey's private half never leaves their device; we keep the public key.
//
// A session is a random token in an HttpOnly, SameSite=Strict, __Host- cookie.
// We store its SHA-256, so a copy of the sessions table signs nobody in.

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR
const CHALLENGE_TTL = 5 * MINUTE

export const SESSION_COOKIE = '__Host-pf_session'
const TOKEN = /^[A-Za-z0-9_-]{43}$/

export interface SignedIn { user: User; session: Session }

function cookieValue(header: string | null, name: string): string | undefined {
  for (const part of (header ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return v.join('=')
  }
  return undefined
}

export class Sessions {
  readonly #store: SessionStore
  readonly #accounts: AccountStore
  readonly #clock: Clock
  readonly #idle: number
  readonly #max: number

  /** Signed out after `idleDays` without opening the app, and after `maxDays` whatever happens. */
  constructor(o: { store: SessionStore; accounts: AccountStore; clock: Clock; idleDays?: number; maxDays?: number }) {
    this.#store = o.store
    this.#accounts = o.accounts
    this.#clock = o.clock
    this.#idle = (o.idleDays ?? 14) * DAY
    this.#max = (o.maxDays ?? 90) * DAY
  }

  /** Starts a session and returns its Set-Cookie header. */
  async start(userId: string, passkeyId: string): Promise<string> {
    const token = b64url(randomBytes(32))
    const now = this.#clock.now()
    await this.#store.create({
      id: await sha256Hex(token), userId, passkeyId,
      createdAt: now.toISOString(), seenAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + Math.min(this.#idle, this.#max)).toISOString(),
    })
    // The cookie lives as long as a session can; the server decides when it's really over.
    return `${SESSION_COOKIE}=${token}; Path=/; Max-Age=${Math.floor(this.#max / 1000)}; HttpOnly; Secure; SameSite=Strict`
  }

  /** Who this request is from, or undefined. Pushes the idle limit back at most once an hour. */
  async read(request: Request): Promise<SignedIn | undefined> {
    const token = cookieValue(request.headers.get('cookie'), SESSION_COOKIE)
    if (!token || !TOKEN.test(token)) return undefined
    const session = await this.#store.get(await sha256Hex(token))
    if (!session) return undefined
    const now = this.#clock.now()
    if (session.expiresAt <= now.toISOString()) {
      await this.#store.remove(session.id)
      return undefined
    }
    const user = await this.#accounts.user(session.userId)
    if (!user) {
      await this.#store.remove(session.id)
      return undefined
    }
    if (now.getTime() - new Date(session.seenAt).getTime() > HOUR) {
      const until = Math.min(now.getTime() + this.#idle, new Date(session.createdAt).getTime() + this.#max)
      session.seenAt = now.toISOString()
      session.expiresAt = new Date(until).toISOString()
      await this.#store.touch(session.id, session.seenAt, session.expiresAt)
    }
    return { user, session }
  }

  async end(session: Session) { await this.#store.remove(session.id) }

  /** Signs out every device this passkey signed in. */
  endForPasskey(passkeyId: string) { return this.#store.removeForPasskey(passkeyId) }

  /** Signs a person out everywhere. */
  endForUser(userId: string) { return this.#store.removeForUser(userId) }

  prune() { return this.#store.prune(this.#clock.now().toISOString()) }

  static clearCookie() { return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict` }
}

/** A short name for a device, from its user agent, so people can tell their passkeys apart. */
export function deviceLabel(ua: string | null): string {
  const s = ua ?? ''
  const device = /iPhone/.test(s) ? 'iPhone' : /iPad/.test(s) ? 'iPad' : /Android/.test(s) ? 'Android'
    : /Macintosh|Mac OS X/.test(s) ? 'Mac' : /Windows/.test(s) ? 'Windows' : /CrOS/.test(s) ? 'Chromebook' : /Linux/.test(s) ? 'Linux' : 'Device'
  const browser = /Edg\//.test(s) ? 'Edge' : /SamsungBrowser/.test(s) ? 'Samsung Internet' : /Firefox\//.test(s) ? 'Firefox'
    : /Chrome\/|CriOS/.test(s) ? 'Chrome' : /Safari\//.test(s) ? 'Safari' : ''
  return browser ? `${device}, ${browser}` : device
}

export interface CreationOptionsJSON {
  challenge: string
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  pubKeyCredParams: { type: 'public-key'; alg: number }[]
  timeout: number
  attestation: 'none'
  authenticatorSelection: { residentKey: 'required'; requireResidentKey: true; userVerification: 'required' }
  excludeCredentials: { type: 'public-key'; id: string }[]
}

export interface RequestOptionsJSON {
  challenge: string
  rpId: string
  timeout: number
  userVerification: 'required'
  allowCredentials: { type: 'public-key'; id: string }[]
}

/** A person as someone who manages people sees them, to change their role, recover or remove. */
export interface Person {
  id: string
  name: string
  role: string
  roleLabel: string
  devices: number
  /** At least one of their passkeys comes back on a new phone by itself. */
  synced: boolean
  lastUsedAt: string | null
  you: boolean
}

export interface PasskeysDeps {
  rp: RelyingParty
  accounts: AccountStore
  access: Access
  challenges: ChallengeStore
  sessions: Sessions
  audit: AuditLog
  clock: Clock
  /** So a removed device stops getting notifications too. */
  push?: PushSubscriptionStore
}

const newChallenge = () => b64url(randomBytes(32))
const credentialIdOf = (input: unknown) => {
  const parsed = assertionSchema.safeParse(input)
  if (!parsed.success) throw new ValidationError('Not a passkey assertion')
  return parsed.data.id
}

export class Passkeys {
  readonly #d: PasskeysDeps
  constructor(deps: PasskeysDeps) { this.#d = deps }

  get rp() { return this.#d.rp }
  #now() { return this.#d.clock.now() }

  /**
   * A one-time link for a new person, as a role the caller may give (see
   * Access.invitable), or for another of the caller's own devices, which anyone
   * may make. Returns the token; the link is `<origin>/#invite=<token>`, in the
   * fragment so it never reaches a server log.
   */
  async invite(by: User, o: { name?: string; role?: string; ownDevice?: boolean }, ttlHours = 24): Promise<{ token: string; expiresAt: string }> {
    const role = o.ownDevice ? by.role : o.role ?? ''
    if (!o.ownDevice && !this.#d.access.invitable(by).includes(role)) {
      throw new NotAllowedError(this.#d.access.exists(role) ? `You can't invite someone as ${this.#d.access.label(role)}` : 'Pick a role for them')
    }
    const name = o.ownDevice ? by.name : (o.name ?? '').trim()
    if (!name || name.length > 60) throw new ValidationError('A name of up to 60 characters, please')
    const token = b64url(randomBytes(24))
    const expiresAt = new Date(this.#now().getTime() + ttlHours * HOUR).toISOString()
    await this.#d.accounts.addInvite(await sha256Hex(token), {
      name, role, userId: o.ownDevice ? by.id : undefined, createdBy: by.id, expiresAt,
    })
    await this.#d.audit.record({ actor: `app:${by.id}`, action: o.ownDevice ? 'invite.device' : 'invite.person', subject: 'app:invites', detail: { role, hours: ttlHours } })
    return { token, expiresAt }
  }

  /** What `navigator.credentials.create` needs, for someone holding an invite. */
  async registrationOptions(inviteToken: string): Promise<CreationOptionsJSON> {
    const inviteHash = await sha256Hex(inviteToken)
    const invite = await this.#d.accounts.peekInvite(inviteHash, this.#now().toISOString())
    if (!invite) throw new NotAllowedError('That invite has been used or has run out. Ask for a new one.')
    const userId = invite.userId ?? b64url(randomBytes(16))
    const existing = invite.userId ? await this.#d.accounts.passkeysOf(invite.userId) : []
    const challenge = newChallenge()
    await this.#d.challenges.put(await sha256Hex(challenge), 'register', { invite: inviteHash, user: userId }, new Date(this.#now().getTime() + CHALLENGE_TTL).toISOString())
    return {
      challenge,
      rp: { id: this.#d.rp.id, name: this.#d.rp.name },
      user: { id: userId, name: invite.name, displayName: invite.name },
      pubKeyCredParams: ALGORITHMS.map(alg => ({ type: 'public-key' as const, alg })),
      timeout: CHALLENGE_TTL,
      attestation: 'none',
      // A passkey the device can find by itself, so signing in needs no username.
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      excludeCredentials: existing.map(p => ({ type: 'public-key' as const, id: p.id })),
    }
  }

  /** Checks the new passkey, uses up the invite and signs this device in. */
  async register(inviteToken: string, credential: unknown, label: string): Promise<{ user: User; cookie: string }> {
    const inviteHash = await sha256Hex(inviteToken)
    const challenge = claimedChallenge((credential as { response?: { clientDataJSON?: string } })?.response?.clientDataJSON ?? '')
    const payload = challenge ? await this.#d.challenges.take(await sha256Hex(challenge), 'register', this.#now().toISOString()) : undefined
    if (!payload || payload.invite !== inviteHash) throw new NotAllowedError('That set-up took too long or was for another invite. Try again.')

    // Checked before the invite is used up, so a failed attempt doesn't waste it.
    const verified = await verifyRegistration(credential, { rp: this.#d.rp, challenge })
    if (await this.#d.accounts.passkey(verified.credentialId)) throw new ConflictError('That passkey is already set up')
    const now = this.#now().toISOString()
    const invite = await this.#d.accounts.takeInvite(inviteHash, now)
    if (!invite) throw new NotAllowedError('That invite has been used or has run out. Ask for a new one.')

    let user: User | undefined
    if (invite.userId) {
      user = await this.#d.accounts.user(invite.userId)
      if (!user) throw new NotAllowedError('That person has been removed')
    }
    const newUser = user ? undefined : { id: payload.user, name: invite.name, role: invite.role, createdAt: now }
    const passkey: Passkey = {
      id: verified.credentialId, userId: payload.user, publicKey: verified.publicKey, alg: verified.alg,
      signCount: verified.signCount, label: label.slice(0, 60) || 'Device', synced: verified.synced, createdAt: now,
    }
    await this.#d.accounts.addPasskey(passkey, newUser)
    user ??= newUser!
    await this.#d.audit.record({ actor: `app:${user.id}`, action: newUser ? 'person.joined' : 'passkey.added', subject: `passkey:${passkey.id.slice(0, 16)}`, detail: { synced: passkey.synced, invitedBy: invite.createdBy } })
    return { user, cookie: await this.#d.sessions.start(user.id, passkey.id) }
  }

  /** What `navigator.credentials.get` needs to sign in. No username: the device offers its passkeys for this site. */
  async loginOptions(): Promise<RequestOptionsJSON> {
    const challenge = newChallenge()
    await this.#d.challenges.put(await sha256Hex(challenge), 'login', {}, new Date(this.#now().getTime() + CHALLENGE_TTL).toISOString())
    return { challenge, rpId: this.#d.rp.id, timeout: CHALLENGE_TTL, userVerification: 'required', allowCredentials: [] }
  }

  async login(credential: unknown): Promise<{ user: User; cookie: string }> {
    const id = credentialIdOf(credential)
    const challenge = claimedChallenge((credential as { response: { clientDataJSON: string } }).response.clientDataJSON)
    const payload = challenge ? await this.#d.challenges.take(await sha256Hex(challenge), 'login', this.#now().toISOString()) : undefined
    if (!payload) throw new NotAllowedError('That sign-in took too long. Try again.')
    const passkey = await this.#d.accounts.passkey(id)
    if (!passkey) throw new NotAllowedError("That passkey isn't set up here. It may have been removed.")
    const user = await this.#verify(passkey, credential, challenge)
    await this.#d.audit.record({ actor: `app:${user.id}`, action: 'session.started', subject: `passkey:${passkey.id.slice(0, 16)}` })
    return { user, cookie: await this.#d.sessions.start(user.id, passkey.id) }
  }

  /** Approves something with one of `user`'s passkeys, signed over `challenge`. Returns the passkey used. */
  async check(user: User, credential: unknown, challenge: string): Promise<Passkey> {
    const passkey = await this.#d.accounts.passkey(credentialIdOf(credential))
    if (!passkey || passkey.userId !== user.id) throw new NotAllowedError('That passkey is not yours')
    await this.#verify(passkey, credential, challenge)
    return passkey
  }

  async #verify(passkey: Passkey, credential: unknown, challenge: string): Promise<User> {
    const result = await verifyAssertion(credential, { rp: this.#d.rp, challenge, publicKey: passkey.publicKey, signCount: passkey.signCount })
    if (result.userHandle && result.userHandle !== passkey.userId) throw new NotAllowedError('Passkey is for someone else')
    if (!(await this.#d.accounts.usedPasskey(passkey.id, result.signCount, this.#now().toISOString()))) throw new NotAllowedError('Passkey counter went backwards')
    const user = await this.#d.accounts.user(passkey.userId)
    if (!user) throw new NotAllowedError('That person has been removed')
    return user
  }

  devices(user: User) { return this.#d.accounts.passkeysOf(user.id) }

  /**
   * True when losing this one device would lock the person out: a single
   * passkey that doesn't sync. The app suggests adding another device.
   */
  async atRisk(user: User): Promise<boolean> {
    const keys = await this.#d.accounts.passkeysOf(user.id)
    return keys.length === 1 && !keys[0].synced
  }

  #manage(by: User) {
    this.#d.access.check(by, 'people', "Your role can't manage people")
  }

  /** Someone else, for a person who manages people. Never yourself, so there's always someone left who can. */
  async #other(by: User, userId: string, yourself: string): Promise<User> {
    this.#manage(by)
    if (userId === by.id) throw new ConflictError(yourself)
    const person = await this.#d.accounts.user(userId)
    if (!person) throw new NotAllowedError('Nobody here by that id')
    return person
  }

  /** Turns a device on for notifications, recorded against the person and passkey on it. */
  async subscribe(signedIn: SignedIn, sub: PushSubscription) {
    if (!this.#d.push) throw new ConflictError('Notifications are not set up')
    await this.#d.push.add(sub)
    await this.#d.accounts.ownPush(sub.endpoint, signedIn.user.id, signedIn.session.passkeyId)
  }

  /** Turns notifications off for one of the person's own devices. */
  async unsubscribe(user: User, endpoint: string) {
    if (!(await this.#d.accounts.pushOf({ userId: user.id })).includes(endpoint)) throw new NotAllowedError('That device is not yours')
    await this.#stopPush([endpoint])
  }

  async #stopPush(endpoints: string[]) {
    for (const endpoint of endpoints) {
      await this.#d.push?.remove(endpoint)
      await this.#d.accounts.forgetPush(endpoint)
    }
  }

  /** Everyone who can open the app, for someone who manages people. */
  async people(by: User): Promise<Person[]> {
    this.#manage(by)
    return Promise.all((await this.#d.accounts.people()).map(async p => {
      const keys = await this.#d.accounts.passkeysOf(p.id)
      const used = keys.map(k => k.lastUsedAt ?? k.createdAt).sort().at(-1) ?? null
      return { id: p.id, name: p.name, role: p.role, roleLabel: this.#d.access.label(p.role), devices: keys.length, synced: keys.some(k => k.synced), lastUsedAt: used, you: p.id === by.id }
    }))
  }

  /**
   * For someone who has lost every device. Removes all their passkeys and signs
   * them out everywhere straight away, so a lost or stolen phone stops working,
   * then makes a one-time link that sets up a new passkey on the same account.
   */
  async recover(by: User, userId: string, ttlHours = 24): Promise<{ token: string; expiresAt: string }> {
    const person = await this.#other(by, userId, "You can't recover yourself. Add another device in Settings instead.")
    const removed = await this.#d.accounts.removePasskeysOf(person.id)
    const signedOut = await this.#d.sessions.endForUser(person.id)
    // An "add another device" link made on the lost phone would otherwise still work,
    // and its notifications would still arrive.
    await this.#d.accounts.removeInvitesFor(person.id)
    await this.#stopPush(await this.#d.accounts.pushOf({ userId: person.id }))
    const token = b64url(randomBytes(24))
    const expiresAt = new Date(this.#now().getTime() + ttlHours * HOUR).toISOString()
    await this.#d.accounts.addInvite(await sha256Hex(token), { name: person.name, role: person.role, userId: person.id, createdBy: by.id, expiresAt })
    await this.#d.audit.record({ actor: `app:${by.id}`, action: 'person.recovered', subject: `person:${person.id}`, detail: { passkeysRemoved: removed, signedOut, hours: ttlHours } })
    return { token, expiresAt }
  }

  /** Takes someone out of the app: their passkeys, sessions and account. */
  async removePerson(by: User, userId: string): Promise<void> {
    const person = await this.#other(by, userId, "You can't remove yourself.")
    const signedOut = await this.#d.sessions.endForUser(person.id)
    await this.#d.accounts.removeInvitesFor(person.id)
    await this.#stopPush(await this.#d.accounts.pushOf({ userId: person.id }))
    await this.#d.accounts.removeUser(person.id)
    await this.#d.audit.record({ actor: `app:${by.id}`, action: 'person.removed', subject: `person:${person.id}`, detail: { signedOut } })
  }

  /** Gives someone else another role. It applies from their next request: nothing is cached. */
  async setRole(by: User, userId: string, role: string): Promise<void> {
    const person = await this.#other(by, userId, "You can't change your own role. Ask someone else who manages people.")
    if (!this.#d.access.exists(role)) throw new ValidationError('No role by that name')
    if (person.role === role) return
    await this.#d.accounts.setRole(person.id, role)
    await this.#d.audit.record({ actor: `app:${by.id}`, action: 'person.role', subject: `person:${person.id}`, detail: { from: person.role, to: role } })
  }

  /** Removes a passkey and signs out every device it signed in. Not the last one: that would lock the person out. */
  async remove(user: User, passkeyId: string): Promise<void> {
    const mine = await this.#d.accounts.passkeysOf(user.id)
    if (!mine.some(p => p.id === passkeyId)) throw new NotAllowedError('That passkey is not yours')
    if (mine.length === 1) throw new ConflictError("That's your only passkey. Add another device first.")
    await this.#d.accounts.removePasskey(passkeyId, user.id)
    const ended = await this.#d.sessions.endForPasskey(passkeyId)
    await this.#stopPush(await this.#d.accounts.pushOf({ passkeyId }))
    await this.#d.audit.record({ actor: `app:${user.id}`, action: 'passkey.removed', subject: `passkey:${passkeyId.slice(0, 16)}`, detail: { signedOut: ended } })
  }

  async prune() {
    const now = this.#now().toISOString()
    return { challenges: await this.#d.challenges.prune(now), invites: await this.#d.accounts.pruneInvites(now), sessions: await this.#d.sessions.prune() }
  }
}
