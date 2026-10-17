import { Port } from '../kernel/port'
import type { Cipher } from '../security/cipher'

// Where the app keeps who can open it. Four small ports, each with a D1
// adapter, all in the client's own D1 database (see core/schema.sql). Anything
// that works like a password (invite tokens, session tokens, challenges) is
// stored as its SHA-256, so a copy of the table can't be used to get in.

export interface User {
  /** Random, base64url. Also the WebAuthn user handle the passkey carries. */
  id: string
  name: string
  /** One of the app's roles (see roles.ts). */
  role: string
  createdAt: string
}

export interface Passkey {
  /** The credential id, base64url. */
  id: string
  userId: string
  /** COSE public key, base64url. Public keys only: the private half never leaves the device. */
  publicKey: string
  alg: number
  signCount: number
  /** e.g. "iPhone, Safari". Shown so people can tell their devices apart. */
  label: string
  synced: boolean
  createdAt: string
  lastUsedAt?: string
}

export interface Invite {
  name: string
  role: string
  /** Set when it adds a device for someone who's already in. */
  userId?: string
  createdBy: string
  expiresAt: string
}

export interface Session {
  /** SHA-256 of the cookie's token. */
  id: string
  userId: string
  /** The passkey that started it, so removing a passkey signs that device out. */
  passkeyId: string
  createdAt: string
  seenAt: string
  expiresAt: string
}

export type CallStatus = 'pending' | 'approved' | 'denied'

/** An automation waiting for someone to approve it with their passkey. */
export interface PendingCall {
  id: string
  userId: string
  /** `server__tool` */
  tool: string
  args: Record<string, unknown>
  answers: unknown[]
  /** What the passkey signs: a hash of exactly this call. */
  challenge: string
  status: CallStatus
  createdAt: string
  expiresAt: string
}

const PLACE = 'Cloudflare D1, in the client\'s own database'

export abstract class AccountStore extends Port {
  abstract user(id: string): Promise<User | undefined>
  /** Everyone, oldest first. */
  abstract people(): Promise<User[]>
  /** Removes a person and every passkey they have. */
  abstract removeUser(id: string): Promise<boolean>
  abstract setRole(id: string, role: string): Promise<boolean>
  abstract passkey(id: string): Promise<Passkey | undefined>
  abstract passkeysOf(userId: string): Promise<Passkey[]>
  /** Adds a passkey, and its person too when `newUser`. Both or neither. */
  abstract addPasskey(passkey: Passkey, newUser?: User): Promise<void>
  /** Records a use. False if the counter moved underneath us (two sign-ins racing with a counting key). */
  abstract usedPasskey(id: string, signCount: number, at: string): Promise<boolean>
  abstract removePasskey(id: string, userId: string): Promise<boolean>
  /** Removes every passkey a person has, for recovering their access. Returns how many. */
  abstract removePasskeysOf(userId: string): Promise<number>
  abstract addInvite(tokenHash: string, invite: Invite): Promise<void>
  /** Looks without using it up. Undefined once used or expired. */
  abstract peekInvite(tokenHash: string, now: string): Promise<Invite | undefined>
  /** Uses it up. Only one caller ever gets it. */
  abstract takeInvite(tokenHash: string, now: string): Promise<Invite | undefined>
  abstract pruneInvites(now: string): Promise<number>
  /** Cancels every unused invite that adds a device to this person. */
  abstract removeInvitesFor(userId: string): Promise<number>
  /** Records whose device a push subscription is, and which passkey turned it on. */
  abstract ownPush(endpoint: string, userId: string, passkeyId: string): Promise<void>
  /** Push endpoints of a person, or of the devices one passkey signed in. */
  abstract pushOf(by: { userId: string } | { passkeyId: string }): Promise<string[]>
  abstract forgetPush(endpoint: string): Promise<void>
}

interface UserRow { id: string; name: string; role: string; created_at: string }
interface PasskeyRow { id: string; user_id: string; public_key: string; alg: number; sign_count: number; label: string; synced: number; created_at: string; last_used_at: string | null }
interface InviteRow { name: string; role: string; user_id: string | null; created_by: string; expires_at: string }

const toUser = (r: UserRow): User => ({ id: r.id, name: r.name, role: r.role, createdAt: r.created_at })
const toPasskey = (r: PasskeyRow): Passkey => ({
  id: r.id, userId: r.user_id, publicKey: r.public_key, alg: r.alg, signCount: r.sign_count, label: r.label,
  synced: !!r.synced, createdAt: r.created_at, lastUsedAt: r.last_used_at ?? undefined,
})
const toInvite = (r: InviteRow): Invite => ({ name: r.name, role: r.role, userId: r.user_id ?? undefined, createdBy: r.created_by, expiresAt: r.expires_at })

export class D1AccountStore extends AccountStore {
  readonly #db: D1Database
  constructor(db: D1Database) {
    super()
    this.#db = db
  }

  async user(id: string) {
    const r = await this.#db.prepare('SELECT id, name, role, created_at FROM pwa_users WHERE id = ?').bind(id).first<UserRow>()
    return r ? toUser(r) : undefined
  }

  async people() {
    const { results } = await this.#db.prepare('SELECT id, name, role, created_at FROM pwa_users ORDER BY created_at, id').all<UserRow>()
    return results.map(toUser)
  }

  async removeUser(id: string) {
    const [, user] = await this.#db.batch([
      this.#db.prepare('DELETE FROM pwa_passkeys WHERE user_id = ?').bind(id),
      this.#db.prepare('DELETE FROM pwa_users WHERE id = ?').bind(id),
    ])
    return user.meta.changes === 1
  }

  async setRole(id: string, role: string) {
    return (await this.#db.prepare('UPDATE pwa_users SET role = ? WHERE id = ?').bind(role, id).run()).meta.changes === 1
  }

  async passkey(id: string) {
    const r = await this.#db.prepare('SELECT * FROM pwa_passkeys WHERE id = ?').bind(id).first<PasskeyRow>()
    return r ? toPasskey(r) : undefined
  }

  async passkeysOf(userId: string) {
    const { results } = await this.#db.prepare('SELECT * FROM pwa_passkeys WHERE user_id = ? ORDER BY created_at').bind(userId).all<PasskeyRow>()
    return results.map(toPasskey)
  }

  async addPasskey(p: Passkey, newUser?: User) {
    const add = this.#db.prepare('INSERT INTO pwa_passkeys (id, user_id, public_key, alg, sign_count, label, synced, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(p.id, p.userId, p.publicKey, p.alg, p.signCount, p.label, p.synced ? 1 : 0, p.createdAt)
    if (!newUser) { await add.run(); return }
    await this.#db.batch([
      this.#db.prepare('INSERT INTO pwa_users (id, name, role, created_at) VALUES (?, ?, ?, ?)').bind(newUser.id, newUser.name, newUser.role, newUser.createdAt),
      add,
    ])
  }

  async usedPasskey(id: string, signCount: number, at: string) {
    // A counter of 0 stays 0 (synced passkeys); one that counts must only go up.
    const r = await this.#db.prepare('UPDATE pwa_passkeys SET sign_count = ?1, last_used_at = ?2 WHERE id = ?3 AND (?1 = 0 OR sign_count < ?1)')
      .bind(signCount, at, id).run()
    return r.meta.changes === 1
  }

  async removePasskey(id: string, userId: string) {
    const r = await this.#db.prepare('DELETE FROM pwa_passkeys WHERE id = ? AND user_id = ?').bind(id, userId).run()
    return r.meta.changes === 1
  }

  async removePasskeysOf(userId: string) {
    return (await this.#db.prepare('DELETE FROM pwa_passkeys WHERE user_id = ?').bind(userId).run()).meta.changes
  }

  async addInvite(tokenHash: string, i: Invite) {
    await this.#db.prepare('INSERT INTO pwa_invites (id, name, role, user_id, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(tokenHash, i.name, i.role, i.userId ?? null, i.createdBy, i.expiresAt).run()
  }

  async peekInvite(tokenHash: string, now: string) {
    const r = await this.#db.prepare('SELECT name, role, user_id, created_by, expires_at FROM pwa_invites WHERE id = ? AND expires_at > ?').bind(tokenHash, now).first<InviteRow>()
    return r ? toInvite(r) : undefined
  }

  async takeInvite(tokenHash: string, now: string) {
    // DELETE ... RETURNING: of two people racing with one link, one gets the row and the other gets nothing.
    const r = await this.#db.prepare('DELETE FROM pwa_invites WHERE id = ? RETURNING name, role, user_id, created_by, expires_at').bind(tokenHash).first<InviteRow>()
    return r && r.expires_at > now ? toInvite(r) : undefined
  }

  async removeInvitesFor(userId: string) {
    return (await this.#db.prepare('DELETE FROM pwa_invites WHERE user_id = ?').bind(userId).run()).meta.changes
  }

  async ownPush(endpoint: string, userId: string, passkeyId: string) {
    await this.#db.prepare('INSERT INTO pwa_push (endpoint, user_id, passkey_id) VALUES (?, ?, ?) ON CONFLICT (endpoint) DO UPDATE SET user_id = excluded.user_id, passkey_id = excluded.passkey_id')
      .bind(endpoint, userId, passkeyId).run()
  }

  async pushOf(by: { userId: string } | { passkeyId: string }) {
    const q = 'userId' in by
      ? this.#db.prepare('SELECT endpoint FROM pwa_push WHERE user_id = ?').bind(by.userId)
      : this.#db.prepare('SELECT endpoint FROM pwa_push WHERE passkey_id = ?').bind(by.passkeyId)
    return (await q.all<{ endpoint: string }>()).results.map(r => r.endpoint)
  }

  async forgetPush(endpoint: string) {
    await this.#db.prepare('DELETE FROM pwa_push WHERE endpoint = ?').bind(endpoint).run()
  }

  async pruneInvites(now: string) {
    return (await this.#db.prepare('DELETE FROM pwa_invites WHERE expires_at <= ?').bind(now).run()).meta.changes
  }

  describe() {
    return { name: 'D1 app accounts', use: 'Who can open the app: names, passkey public keys, invite links, and whose device each push subscription is', personalInfo: ['name'], storesIn: PLACE }
  }
}

export abstract class SessionStore extends Port {
  abstract create(s: Session): Promise<void>
  abstract get(id: string): Promise<Session | undefined>
  abstract touch(id: string, seenAt: string, expiresAt: string): Promise<void>
  abstract remove(id: string): Promise<void>
  /** Signs out every device a passkey signed in. */
  abstract removeForPasskey(passkeyId: string): Promise<number>
  /** Signs a person out everywhere. */
  abstract removeForUser(userId: string): Promise<number>
  abstract prune(now: string): Promise<number>
}

interface SessionRow { id: string; user_id: string; passkey_id: string; created_at: string; seen_at: string; expires_at: string }

export class D1SessionStore extends SessionStore {
  readonly #db: D1Database
  constructor(db: D1Database) {
    super()
    this.#db = db
  }
  async create(s: Session) {
    await this.#db.prepare('INSERT INTO pwa_sessions (id, user_id, passkey_id, created_at, seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(s.id, s.userId, s.passkeyId, s.createdAt, s.seenAt, s.expiresAt).run()
  }
  async get(id: string) {
    const r = await this.#db.prepare('SELECT * FROM pwa_sessions WHERE id = ?').bind(id).first<SessionRow>()
    return r ? { id: r.id, userId: r.user_id, passkeyId: r.passkey_id, createdAt: r.created_at, seenAt: r.seen_at, expiresAt: r.expires_at } : undefined
  }
  async touch(id: string, seenAt: string, expiresAt: string) {
    await this.#db.prepare('UPDATE pwa_sessions SET seen_at = ?, expires_at = ? WHERE id = ?').bind(seenAt, expiresAt, id).run()
  }
  async remove(id: string) {
    await this.#db.prepare('DELETE FROM pwa_sessions WHERE id = ?').bind(id).run()
  }
  async removeForPasskey(passkeyId: string) {
    return (await this.#db.prepare('DELETE FROM pwa_sessions WHERE passkey_id = ?').bind(passkeyId).run()).meta.changes
  }
  async removeForUser(userId: string) {
    return (await this.#db.prepare('DELETE FROM pwa_sessions WHERE user_id = ?').bind(userId).run()).meta.changes
  }
  async prune(now: string) {
    return (await this.#db.prepare('DELETE FROM pwa_sessions WHERE expires_at <= ?').bind(now).run()).meta.changes
  }
  describe() {
    return { name: 'D1 app sessions', use: 'Which devices are signed in to the app', personalInfo: [], storesIn: PLACE }
  }
}

export type ChallengePurpose = 'register' | 'login'

export abstract class ChallengeStore extends Port {
  abstract put(challengeHash: string, purpose: ChallengePurpose, payload: Record<string, string>, expiresAt: string): Promise<void>
  /** Uses it up: a challenge only ever works once. Undefined if unknown, expired or for something else. */
  abstract take(challengeHash: string, purpose: ChallengePurpose, now: string): Promise<Record<string, string> | undefined>
  abstract prune(now: string): Promise<number>
}

export class D1ChallengeStore extends ChallengeStore {
  readonly #db: D1Database
  constructor(db: D1Database) {
    super()
    this.#db = db
  }
  async put(challengeHash: string, purpose: ChallengePurpose, payload: Record<string, string>, expiresAt: string) {
    await this.#db.prepare('INSERT INTO pwa_challenges (id, purpose, payload, expires_at) VALUES (?, ?, ?, ?)')
      .bind(challengeHash, purpose, JSON.stringify(payload), expiresAt).run()
  }
  async take(challengeHash: string, purpose: ChallengePurpose, now: string) {
    const r = await this.#db.prepare('DELETE FROM pwa_challenges WHERE id = ? RETURNING purpose, payload, expires_at')
      .bind(challengeHash).first<{ purpose: string; payload: string; expires_at: string }>()
    if (!r || r.purpose !== purpose || r.expires_at <= now) return undefined
    return JSON.parse(r.payload) as Record<string, string>
  }
  async prune(now: string) {
    return (await this.#db.prepare('DELETE FROM pwa_challenges WHERE expires_at <= ?').bind(now).run()).meta.changes
  }
  describe() {
    return { name: 'D1 passkey challenges', use: 'One-time challenges for passkey sign-in and set-up, five minutes each', personalInfo: [], storesIn: PLACE }
  }
}

export abstract class PendingCallStore extends Port {
  abstract create(call: PendingCall): Promise<void>
  abstract get(id: string): Promise<PendingCall | undefined>
  /** Moves a pending, unexpired call on. False if someone got there first or it ran out of time. */
  abstract settle(id: string, to: Exclude<CallStatus, 'pending'>, now: string): Promise<boolean>
  abstract prune(now: string): Promise<number>
}

interface CallRow { id: string; user_id: string; tool: string; sealed: string; challenge: string; status: CallStatus; created_at: string; expires_at: string }

/** Arguments can hold customer details, so they're sealed, bound to the call's id. */
export class D1PendingCallStore extends PendingCallStore {
  readonly #db: D1Database
  readonly #cipher: Cipher
  constructor(db: D1Database, cipher: Cipher) {
    super()
    this.#db = db
    this.#cipher = cipher
  }
  async create(c: PendingCall) {
    const sealed = await this.#cipher.encryptJson({ args: c.args, answers: c.answers }, `pwa-call:${c.id}`)
    await this.#db.prepare('INSERT INTO pwa_calls (id, user_id, tool, sealed, challenge, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(c.id, c.userId, c.tool, sealed, c.challenge, c.status, c.createdAt, c.expiresAt).run()
  }
  async get(id: string) {
    const r = await this.#db.prepare('SELECT * FROM pwa_calls WHERE id = ?').bind(id).first<CallRow>()
    if (!r) return undefined
    const { args, answers } = await this.#cipher.decryptJson<{ args: Record<string, unknown>; answers: unknown[] }>(r.sealed, `pwa-call:${r.id}`)
    return { id: r.id, userId: r.user_id, tool: r.tool, args, answers, challenge: r.challenge, status: r.status, createdAt: r.created_at, expiresAt: r.expires_at }
  }
  async settle(id: string, to: Exclude<CallStatus, 'pending'>, now: string) {
    const r = await this.#db.prepare("UPDATE pwa_calls SET status = ? WHERE id = ? AND status = 'pending' AND expires_at > ?").bind(to, id, now).run()
    return r.meta.changes === 1
  }
  async prune(now: string) {
    return (await this.#db.prepare('DELETE FROM pwa_calls WHERE expires_at <= ?').bind(now).run()).meta.changes
  }
  describe() {
    return { name: 'D1 calls waiting for approval', use: 'Automations waiting for a passkey tap, ten minutes each', personalInfo: ['whatever the automation is given'], storesIn: `${PLACE}, encrypted` }
  }
}
