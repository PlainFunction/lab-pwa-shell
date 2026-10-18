import type { Roles } from '#capabilities'

// Who can do what in Harbour Plumbing's app. The Worker enforces all of it;
// the app only hides what someone can't use.
//
//   tool:<server>__<tool>   see and run an automation (* matches anything)
//   people                  manage everyone: roles, recovering, removing ('*' includes it)
//   invite                  invite people as one of `invites`
//   see:prices              this app's own: the automations show job and quote values
//
// The operator's script makes the first person an `admin`.
export const roles: Roles = {
  admin: { label: 'Owner', can: ['*'] },
  office: { label: 'Office', can: ['tool:jobs__*', 'tool:quotes__*', 'tool:scans__*', 'invite', 'see:prices'], invites: ['tradie'] },
  // Tradies scan the dockets and job sheets they collect, but don't see the list of everyone's scans.
  tradie: { label: 'Tradie', can: ['tool:jobs__today', 'tool:scans__scan'] },
}
