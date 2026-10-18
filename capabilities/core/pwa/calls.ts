import { z } from 'zod'
import type { AuditLog } from '../audit/audit-log'
import type { Clock } from '../kernel/clock'
import { ConflictError, NotAllowedError, ValidationError } from '../kernel/errors'
import { b64url, randomBytes, randomId, stableJson, utf8 } from '../kernel/encoding'
import type { Logger } from '../kernel/logger'
import type { CredentialBroker } from '../slack-agent/agent/credentials'
import type { NamedTool, ToolBox } from '../slack-agent/agent/toolbox'
import { needsAnswer, type ElicitAnswer, type JsonSchema } from '../slack-agent/tools/contract'
import type { Passkeys, RequestOptionsJSON } from './auth'
import { UnsupportedField, fieldsOf } from './forms'
import type { Access } from './roles'
import type { PendingCallStore, User } from './stores'
import type { UploadStore } from './uploads'

// Running a client's automations from the app. They're the same tools the
// Slack agent runs (LocalToolServer, or MCP Workers), drawn as web forms.
//
// Anything that only reads runs straight away. Anything else waits for the
// person to approve it with their passkey, and the challenge the passkey signs
// is a hash of exactly that call: who, which tool, every argument. So the
// signature in the audit trail is over what was approved, and an approval for
// one call can't be replayed onto another. The arguments that run are the ones
// stored when the call was made, never ones sent again with the approval.

const CALL_TTL = 10 * 60_000

/** A tool as the app sees it. */
export interface AppTool {
  /** `server__tool` */
  name: string
  title: string
  description: string
  /** True unless it only reads: running it needs a passkey. */
  confirm: boolean
  inputSchema: JsonSchema
  outputSchema?: JsonSchema
}

export type CallOutcome =
  | { status: 'done'; ok: true; content: Record<string, unknown> }
  | { status: 'done'; ok: false; error: string }
  /** The tool stopped to ask something. Call it again with the answer added to `answers`. */
  | { status: 'ask'; message: string; schema: JsonSchema }
  /** Waiting for a passkey: sign `options` and send it to confirm with `id`. */
  | { status: 'confirm'; id: string; expiresAt: string; options: RequestOptionsJSON }

const answersSchema = z.array(z.union([
  z.object({ action: z.literal('accept'), content: z.record(z.string(), z.unknown()) }),
  z.object({ action: z.literal('decline') }),
])).max(10)

/** The arguments that are photos (`ui.image`), by value. */
const photosIn = (schema: JsonSchema, args: Record<string, unknown>) =>
  Object.entries(schema.properties ?? {})
    .filter(([k, p]) => p['x-slack']?.element === 'image_select' && typeof args[k] === 'string')
    .map(([k]) => args[k] as string)

const titleOf = (t: NamedTool) => t.title ?? t.name.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())

export interface CallsDeps {
  tools: ToolBox
  pending: PendingCallStore
  uploads: UploadStore
  passkeys: Passkeys
  access: Access
  credentials: CredentialBroker
  audit: AuditLog
  clock: Clock
  logger: Logger
}

export class Calls {
  readonly #d: CallsDeps
  constructor(deps: CallsDeps) { this.#d = deps }

  /**
   * The tools this person's role may use (`tool:<name>`) that the app can draw.
   * One it can't draw (a Slack-only field) is left out and logged, not fatal to the rest.
   */
  async list(user: User): Promise<AppTool[]> {
    const out: AppTool[] = []
    for (const t of await this.#d.tools.all()) {
      if (!this.#d.access.can(user, `tool:${t.fullName}`)) continue
      try {
        fieldsOf(t.inputSchema)
      } catch (err) {
        if (!(err instanceof UnsupportedField)) throw err
        this.#d.logger.warn('pwa.tool.skipped', { tool: t.fullName, reason: err.message })
        continue
      }
      out.push({ name: t.fullName, title: titleOf(t), description: t.description, confirm: !t.annotations?.readOnlyHint, inputSchema: t.inputSchema, outputSchema: t.outputSchema })
    }
    return out
  }

  /** Someone without the role for it gets the same answer as for a tool that doesn't exist. */
  async #find(user: User, name: string) {
    const tool = (await this.list(user)).some(t => t.name === name) ? await this.#d.tools.find(name) : undefined
    if (!tool) throw new ValidationError(`No automation called ${name}`)
    return tool
  }

  /** Runs a read-only tool now, or holds anything else for a passkey. */
  async start(user: User, name: string, args: unknown, answers: unknown = []): Promise<CallOutcome> {
    const tool = await this.#find(user, name)
    const a = z.record(z.string(), z.unknown()).safeParse(args ?? {})
    const ans = answersSchema.safeParse(answers ?? [])
    if (!a.success || !ans.success) throw new ValidationError('Arguments must be an object, and answers a list')
    // Before asking for a passkey: every photo must be one this person uploaded, and still here.
    for (const id of photosIn(tool.inputSchema, a.data)) {
      if (!(await this.#d.uploads.get(user.id, id))) throw new ValidationError('That photo has expired. Add it again.')
    }
    if (tool.annotations?.readOnlyHint) return this.#run(user, tool, a.data, ans.data)

    const now = this.#d.clock.now()
    const id = randomId()
    const expiresAt = new Date(now.getTime() + CALL_TTL).toISOString()
    // The passkey signs this, so the signature commits to exactly this call.
    const digest = await crypto.subtle.digest('SHA-256', utf8(stableJson({
      purpose: 'pwa-call', id, user: user.id, tool: tool.fullName, args: a.data, answers: ans.data, nonce: b64url(randomBytes(16)),
    })))
    const challenge = b64url(digest)
    await this.#d.pending.create({ id, userId: user.id, tool: tool.fullName, args: a.data, answers: ans.data, challenge, status: 'pending', createdAt: now.toISOString(), expiresAt })
    await this.#d.audit.record({ actor: `app:${user.id}`, action: 'call.requested', subject: `call:${id}`, detail: { tool: tool.fullName, call: challenge } })
    const allow = (await this.#d.passkeys.devices(user)).map(p => ({ type: 'public-key' as const, id: p.id }))
    return { status: 'confirm', id, expiresAt, options: { challenge, rpId: this.#d.passkeys.rp.id, timeout: CALL_TTL, userVerification: 'required', allowCredentials: allow } }
  }

  /** Checks the passkey's signature over the stored call, then runs exactly what was stored. */
  async confirm(user: User, id: string, credential: unknown): Promise<CallOutcome> {
    const call = await this.#d.pending.get(id)
    if (!call || call.userId !== user.id) throw new NotAllowedError('Nothing is waiting for you with that id')
    const now = this.#d.clock.now().toISOString()
    if (call.status !== 'pending' || call.expiresAt <= now) throw new ConflictError('That was already approved, cancelled or ran out of time')

    const passkey = await this.#d.passkeys.check(user, credential, call.challenge)
    // Two taps at once: both signatures check out, only one gets to run it.
    if (!(await this.#d.pending.settle(id, 'approved', now))) throw new ConflictError('That was already approved, cancelled or ran out of time')
    await this.#d.audit.record({ actor: `app:${user.id}`, action: 'call.approved', subject: `call:${id}`, detail: { tool: call.tool, call: call.challenge, passkey: passkey.id.slice(0, 16) } })

    const tool = await this.#d.tools.find(call.tool)
    if (!tool) return { status: 'done', ok: false, error: 'That automation is no longer here' }
    // Their role may have changed since they asked.
    if (!this.#d.access.can(user, `tool:${call.tool}`)) return { status: 'done', ok: false, error: "Your role can't run that any more" }
    const outcome = await this.#run(user, tool, call.args, call.answers as ElicitAnswer[])
    const action = outcome.status === 'ask' ? 'call.asked' : outcome.status === 'done' && outcome.ok ? 'call.ran' : 'call.failed'
    await this.#d.audit.record({ actor: `system:${call.tool}`, action, subject: `call:${id}` })
    return outcome
  }

  async deny(user: User, id: string): Promise<void> {
    const call = await this.#d.pending.get(id)
    if (!call || call.userId !== user.id) throw new NotAllowedError('Nothing is waiting for you with that id')
    if (await this.#d.pending.settle(id, 'denied', this.#d.clock.now().toISOString())) {
      await this.#d.audit.record({ actor: `app:${user.id}`, action: 'call.denied', subject: `call:${id}`, detail: { tool: call.tool } })
    }
  }

  async #run(user: User, tool: NamedTool, args: Record<string, unknown>, answers: ElicitAnswer[]): Promise<CallOutcome> {
    // A tool reads only the photos in its own arguments, and only this person's.
    const photos = new Set(photosIn(tool.inputSchema, args))
    const file = async (id: string) => {
      const f = photos.has(id) ? await this.#d.uploads.get(user.id, id) : undefined
      if (!f) throw new NotAllowedError(photos.has(id) ? 'That photo has expired. Add it again.' : "That photo isn't part of this call")
      return f
    }
    const result = await this.#d.tools.call(tool, args, {
      file,
      user: user.id,
      now: this.#d.clock.now(),
      answers,
      can: permission => this.#d.access.can(user, permission),
      fetch: (url, init) => this.#d.credentials.fetch(url, init, { tool: tool.fullName }),
    })
    if (needsAnswer(result)) {
      try { fieldsOf(result.elicit.schema) } catch { return { status: 'done', ok: false, error: 'The automation asked something the app can\'t show' } }
      return { status: 'ask', message: result.elicit.message, schema: result.elicit.schema }
    }
    return result.ok ? { status: 'done', ok: true, content: result.content } : { status: 'done', ok: false, error: result.error }
  }

  prune() { return this.#d.pending.prune(this.#d.clock.now().toISOString()) }
}
