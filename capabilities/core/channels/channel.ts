import { Port, type Manifest } from '../kernel/port'

// Two ports, because talking to the owner and talking to their customers are
// different jobs with different rules:
//
//   Notifier  tells the owner (or us) something: "3 emails waiting for you".
//             Slack, web push to their phone, email. Short, may hold a link.
//   Mailer    sends a customer an email the owner has approved. Only ever
//             called by an approved action, never directly by an automation.
//
// No SMS. Approvals and follow-ups go by email and push: it's cheaper, there's
// no sender registration, and push is end-to-end encrypted to the device.

export interface Notice {
  title: string
  body: string
  /** A link to act on it. Signed, and behind Access, never a bearer secret on its own. */
  url?: string
  urgency?: 'low' | 'normal' | 'high'
  /** Notices with the same tag replace each other on a phone instead of stacking. */
  tag?: string
}

export abstract class Notifier extends Port {
  abstract notify(notice: Notice): Promise<void>
}

export interface EmailAddress { email: string; name?: string }

export interface OutboundEmail {
  to: EmailAddress
  subject: string
  text: string
  html?: string
  /** Replies go to the owner, not to us and not to a no-reply address. */
  replyTo?: EmailAddress
  /** Ties sends to an approval, for the audit log and for de-duplication. */
  reference?: string
}

export abstract class Mailer extends Port {
  abstract send(email: OutboundEmail): Promise<{ id?: string }>
}

/**
 * Sends to several notifiers.
 *   'all'    every channel (default): the owner sees it wherever they look first
 *   'first'  in order until one works: push, then Slack, then email as the fallback
 * Throws only if every channel fails.
 */
export class FanoutNotifier extends Notifier {
  readonly #notifiers: Notifier[]
  readonly #mode: 'all' | 'first'
  constructor(notifiers: Notifier[], mode: 'all' | 'first' = 'all') {
    super()
    this.#notifiers = notifiers
    this.#mode = mode
  }

  async notify(notice: Notice) {
    const errors: unknown[] = []
    if (this.#mode === 'first') {
      for (const n of this.#notifiers) {
        try { await n.notify(notice); return } catch (err) { errors.push(err) }
      }
    } else {
      const results = await Promise.allSettled(this.#notifiers.map(n => n.notify(notice)))
      for (const r of results) if (r.status === 'rejected') errors.push(r.reason)
      if (errors.length < this.#notifiers.length) return
    }
    throw new AggregateError(errors, 'Every notification channel failed')
  }

  describe(): Manifest {
    const parts = this.#notifiers.map(n => n.describe())
    return {
      name: parts.map(p => p.name).join(' + '),
      use: 'Telling the owner something needs them',
      personalInfo: [...new Set(parts.flatMap(p => p.personalInfo))],
      storesIn: parts.map(p => p.storesIn).join('; '),
      egress: [...new Set(parts.flatMap(p => p.egress ?? []))],
    }
  }
}

/** Collects notices and emails. For tests, and for a dry run with a new client. */
export class MemoryNotifier extends Notifier {
  readonly sent: Notice[] = []
  async notify(n: Notice) { this.sent.push(n) }
  describe() { return { name: 'Memory notifier', use: 'Tests', personalInfo: [], storesIn: 'Memory' } }
}

export class MemoryMailer extends Mailer {
  readonly sent: OutboundEmail[] = []
  async send(e: OutboundEmail) { this.sent.push(e); return { id: `mem-${this.sent.length}` } }
  describe() { return { name: 'Memory mailer', use: 'Tests', personalInfo: ['name', 'email'], storesIn: 'Memory' } }
}
