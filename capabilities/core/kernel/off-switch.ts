// One switch that stops a client's Worker, without a deploy. It's a KV key, so
// whoever looks after it can flip it from a terminal or the Cloudflare dashboard:
//
//   wrangler kv key put off-switch on --binding KV --remote    # off
//   wrangler kv key delete off-switch --binding KV --remote    # back on
//
// While it's off, requests get a page saying nothing was done, inbound email
// is refused (so the sender knows), and cron work stops. Housekeeping that only
// forgets things (expiring approvals and old sessions) carries on. KV can take
// up to a minute to reach every location.

export const OFF_SWITCH_KEY = 'off-switch'

export const SWITCHED_OFF = 'Switched off: nothing was done. Whoever looks after this has turned it off for now, and the work is being done by hand.'

/** Whether the off switch is on. No KV bound, no switch. */
export async function switchedOff(kv: KVNamespace | undefined): Promise<boolean> {
  return !!kv && (await kv.get(OFF_SWITCH_KEY)) !== null
}

/** The KV namespace a Worker's env carries as `KV`, if any. */
export const kvOf = (env: object): KVNamespace | undefined => (env as { KV?: KVNamespace }).KV
