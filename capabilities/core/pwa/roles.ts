import { ConfigError, NotAllowedError } from '../kernel/errors'

// Who can do what in the app. Each app says which roles it has and what each
// may do; a person has one role. Everything is checked in the Worker, and the
// shell is told the result only so it can hide what someone can't use.
//
// A permission is a string, matched against a role's `can` list, where `*`
// matches anything (so `*` alone is everything):
//
//   tool:<server>__<tool>   see and run an automation, e.g. tool:jobs__*
//   people                  see everyone, change roles, recover and remove people, invite as any role
//   invite                  invite people as one of the role's `invites`
//   anything else           the app's own, for tools to check with ctx.can(), e.g. see:prices
//
// Anyone may add another of their own devices, whatever their role.

export interface Role {
  /** What people see, e.g. "Office". */
  label: string
  can: string[]
  /** Roles someone with this one may invite as, with the `invite` permission. */
  invites?: string[]
}

export type Roles = Record<string, Role>

/** For an app that doesn't set its own: admins do everything, staff run the automations. */
export const DEFAULT_ROLES: Roles = {
  admin: { label: 'Admin', can: ['*'] },
  staff: { label: 'Staff', can: ['tool:*'] },
}

const ID = /^[a-z][a-z0-9_-]{0,31}$/

const glob = (pattern: string) => new RegExp(`^${pattern.split('*').map(p => p.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`)

/** What the shell gets: enough to show or hide things, never what decides. */
export interface Abilities {
  role: { id: string; label: string }
  /** Can manage people: the People section. */
  people: boolean
  /** Roles they may invite someone as. Empty: no Invite section. */
  invites: { id: string; label: string }[]
  /** The app's own permissions they hold, e.g. ["see:prices"], so the shell can show extra things. */
  flags: string[]
}

export class Access {
  readonly #roles: Roles
  readonly #match = new Map<string, RegExp[]>()

  constructor(roles: Roles = DEFAULT_ROLES) {
    const ids = Object.keys(roles)
    if (!ids.length) throw new ConfigError('roles: at least one')
    for (const [id, r] of Object.entries(roles)) {
      if (!ID.test(id)) throw new ConfigError(`roles: "${id}" should be lower case letters, digits, - or _`)
      if (!r.label?.trim()) throw new ConfigError(`roles.${id}: needs a label`)
      for (const other of r.invites ?? []) if (!roles[other]) throw new ConfigError(`roles.${id}.invites: no role called ${other}`)
      this.#match.set(id, r.can.map(glob))
    }
    if (!ids.some(id => this.#allows(id, 'people'))) throw new ConfigError('roles: one of them needs the people permission, or nobody could manage the app')
    this.#roles = roles
  }

  /** The roles, in the order the app listed them. */
  get roles() { return Object.entries(this.#roles).map(([id, r]) => ({ id, label: r.label })) }

  exists(role: string) { return Object.hasOwn(this.#roles, role) }
  label(role: string) { return this.#roles[role]?.label ?? role }

  #allows(role: string, permission: string) {
    return (this.#match.get(role) ?? []).some(re => re.test(permission))
  }

  /** A role that's no longer in the config can do nothing until someone gives them another. */
  can(user: { role: string }, permission: string) { return this.exists(user.role) && this.#allows(user.role, permission) }

  check(user: { role: string }, permission: string, message = "Your role can't do that") {
    if (!this.can(user, permission)) throw new NotAllowedError(message)
  }

  /** Roles this person may give someone they invite. */
  invitable(user: { role: string }): string[] {
    if (this.can(user, 'people')) return Object.keys(this.#roles)
    if (!this.can(user, 'invite')) return []
    return this.#roles[user.role]?.invites ?? []
  }

  abilities(user: { role: string }): Abilities {
    return {
      role: { id: user.role, label: this.label(user.role) },
      people: this.can(user, 'people'),
      invites: this.invitable(user).map(id => ({ id, label: this.label(id) })),
      flags: this.flags.filter(f => this.can(user, f)),
    }
  }

  /** The app's own permissions: every exact one any role names, other than tools, people and invite. */
  get flags(): string[] {
    const all = new Set<string>()
    for (const r of Object.values(this.#roles)) {
      for (const p of r.can) if (!p.includes('*') && !p.startsWith('tool:') && p !== 'people' && p !== 'invite') all.add(p)
    }
    return [...all].sort()
  }
}
