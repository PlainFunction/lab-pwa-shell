import { AuditLog, D1AuditLog } from '../audit/audit-log'
import type { Notice, Notifier } from '../channels/channel'
import { KvPushSubscriptionStore, PushSubscriptionStore, WebPushNotifier } from '../channels/web-push'
import { Clock, SystemClock } from '../kernel/clock'
import { ConfigError } from '../kernel/errors'
import { JsonLogger, Logger } from '../kernel/logger'
import { Module, Token, type Registry } from '../kernel/registry'
import { CloudflareSecretStore, SecretStore } from '../secrets/secrets'
import { AesGcmCipher, Cipher } from '../security/cipher'
import { CredentialBroker } from '../slack-agent/agent/credentials'
import { ToolBox } from '../slack-agent/agent/toolbox'
import type { ToolServer } from '../slack-agent/tools/contract'
import { McpToolServer } from '../slack-agent/tools/mcp'
import { TelemetryLogger, instrument } from '../telemetry/instrument'
import { CloudflareTelemetry, OtlpTelemetry, Telemetry } from '../telemetry/telemetry'
import { Passkeys, Sessions } from './auth'
import { Calls } from './calls'
import { Access, DEFAULT_ROLES, type Roles } from './roles'
import { AccountStore, ChallengeStore, D1AccountStore, D1ChallengeStore, D1PendingCallStore, D1SessionStore, PendingCallStore, SessionStore } from './stores'
import type { RelyingParty } from './webauthn/webauthn'

/**
 * One Worker per client, like everything in capabilities: its own D1, KV and
 * secrets, and its own address. The app's shell is static assets on the same
 * Worker; only /api/* runs code.
 */
export interface PwaEnv {
  /** What the app is called on the sign-in screen and in the passkey prompt. */
  APP_NAME: string
  /** Where the app is served, exactly: https://app.example.com.au. Passkeys are bound to its host name. */
  PUBLIC_URL: string
  DB: D1Database
  KV: KVNamespace
  /** The shell: Workers Static Assets. */
  ASSETS?: Fetcher
  ENVIRONMENT?: string
  /** Days without opening the app before it asks for the passkey again. Default 14. */
  SESSION_IDLE_DAYS?: string
  /** Days before it asks whatever happens. Default 90. */
  SESSION_MAX_DAYS?: string
  /** JSON. Credential name → hosts it may be sent to, e.g. {"xero":["api.xero.com"]}. */
  CREDENTIAL_HOSTS?: string
  /** Comma-separated service bindings, each another of our Workers serving MCP tools (see serveMcp). */
  MCP_BINDINGS?: string
  /** For notifications. Uncompressed P-256 public key, base64url. */
  VAPID_PUBLIC_KEY?: string
  /** mailto: or https: address the push services can reach us at. */
  VAPID_SUBJECT?: string

  // Secrets
  KEYRING: unknown
  VAPID_PRIVATE_KEY?: unknown
  OTEL_EXPORTER_OTLP_ENDPOINT?: string
  OTEL_EXPORTER_OTLP_HEADERS?: unknown
  // CREDENTIAL_<NAME> for each API key in CREDENTIAL_HOSTS.
}

export const RELYING_PARTY = new Token<RelyingParty>('relying-party', Object as never)
export const APP_TOOL_SERVERS = new Token<ToolServer[]>('app-tool-servers', Array)
/** Notifications to everyone's devices. Only bound when the VAPID keys are set. */
export const APP_PUSH = new Token<WebPushNotifier>('app-push', WebPushNotifier)

/** What a tools function gets, to build this app's own tool servers. */
export interface AppToolsContext<E extends PwaEnv = PwaEnv> {
  env: E
  /** For sealing anything a tool stores, bound to its own id. */
  cipher: Cipher
  /**
   * Sends a notification to every device that turned them on, or only to the
   * devices of people in `to.roles`. Throws if notifications aren't set up.
   */
  notify(notice: Notice, to?: { roles: string[] }): Promise<void>
  registry: Registry
}

export interface PwaOptions<E extends PwaEnv = PwaEnv> {
  /** The tool servers that run inside this Worker. MCP Workers in MCP_BINDINGS are added after these. */
  tools?: (t: AppToolsContext<E>) => ToolServer[]
  /** Who can do what (see roles.ts). Default: admin does everything, staff run the automations. */
  roles?: Roles
}

const VERSION = '0.1.0'
const LOCAL = new Set(['localhost', '127.0.0.1', '[::1]'])

/** The relying party from PUBLIC_URL. https only, except on this machine for wrangler dev. */
export function relyingParty(env: Pick<PwaEnv, 'APP_NAME' | 'PUBLIC_URL'>): RelyingParty {
  if (!env.PUBLIC_URL) throw new ConfigError('PUBLIC_URL is not set')
  let url: URL
  try { url = new URL(env.PUBLIC_URL) } catch { throw new ConfigError('PUBLIC_URL is not a URL') }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOCAL.has(url.hostname))) throw new ConfigError('PUBLIC_URL must be https')
  if (url.pathname !== '/' || url.search || url.hash) throw new ConfigError('PUBLIC_URL is an origin only, with no path')
  return { id: url.hostname, name: (env.APP_NAME || 'App').slice(0, 60), origin: url.origin }
}

const days = (raw: string | undefined, fallback: number) => {
  if (raw === undefined || raw === '') return fallback
  const n = Number(raw)
  if (!Number.isFinite(n) || n <= 0 || n > 400) throw new ConfigError('Session days must be between 0 and 400')
  return n
}

export class PwaModule<E extends PwaEnv = PwaEnv> extends Module {
  protected readonly env: E
  protected readonly options: PwaOptions<E>
  constructor(env: E, options: PwaOptions<E> = {}) {
    super()
    this.env = env
    this.options = options
  }

  register(c: Registry) {
    this.kernel(c)
    this.telemetry(c)
    this.security(c)
    this.records(c)
    this.channels(c)
    this.tools(c)
    this.app(c)
  }

  protected kernel(c: Registry) {
    c.bind(Clock, () => new SystemClock())
    c.bind(Logger, () => new JsonLogger({ client: 'pwa' }))
    const rp = relyingParty(this.env)
    c.bind(RELYING_PARTY, () => rp)
    // Built now, so a mistake in the roles stops the Worker starting rather than surfacing on a click.
    const access = new Access(this.options.roles ?? DEFAULT_ROLES)
    c.bind(Access, () => access)
  }

  /** Same as CoreModule: every port traced, logs through telemetry. */
  protected telemetry(c: Registry) {
    const resource = { serviceName: 'pf-pwa', serviceVersion: VERSION, environment: this.env.ENVIRONMENT ?? 'production', client: 'pwa' }
    c.bind(Telemetry, c => this.env.OTEL_EXPORTER_OTLP_ENDPOINT
      ? new OtlpTelemetry({ resource, endpoint: this.env.OTEL_EXPORTER_OTLP_ENDPOINT, headers: this.env.OTEL_EXPORTER_OTLP_HEADERS ? c.get(SecretStore).ref('OTEL_EXPORTER_OTLP_HEADERS') : undefined })
      : new CloudflareTelemetry(resource))
    c.bind(Logger, c => new TelemetryLogger(c.get(Telemetry)))
    c.intercept(instrument(() => c.get(Telemetry)))
  }

  protected security(c: Registry) {
    c.bind(SecretStore, () => new CloudflareSecretStore(this.env))
    c.bind(Cipher, c => AesGcmCipher.fromSecret(c.get(SecretStore).ref('KEYRING')))
  }

  protected records(c: Registry) {
    c.bind(AuditLog, c => new D1AuditLog(this.env.DB, c.get(Clock)))
    c.bind(AccountStore, () => new D1AccountStore(this.env.DB))
    c.bind(SessionStore, () => new D1SessionStore(this.env.DB))
    c.bind(ChallengeStore, () => new D1ChallengeStore(this.env.DB))
    c.bind(PendingCallStore, c => new D1PendingCallStore(this.env.DB, c.get(Cipher)))
    c.bind(PushSubscriptionStore, c => new KvPushSubscriptionStore(this.env.KV, c.get(Cipher)))
  }

  protected channels(c: Registry) {
    const { VAPID_PUBLIC_KEY: publicKey, VAPID_PRIVATE_KEY, VAPID_SUBJECT: subject } = this.env
    if (!publicKey || !VAPID_PRIVATE_KEY) return
    if (!subject || !/^(mailto:|https:\/\/)/.test(subject)) throw new ConfigError('VAPID_SUBJECT must be a mailto: or https: address')
    c.bind(APP_PUSH, c => new WebPushNotifier({
      subscriptions: c.get(PushSubscriptionStore), clock: c.get(Clock),
      vapid: { publicKey, privateKey: c.get(SecretStore).ref('VAPID_PRIVATE_KEY'), subject },
    }))
  }

  protected notify(c: Registry) {
    return async (notice: Notice, to?: { roles: string[] }) => {
      if (!c.has(APP_PUSH)) throw new ConfigError('Notifications are not set up: VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY and VAPID_SUBJECT')
      if (!to) return (c.get(APP_PUSH) as Notifier).notify(notice)
      const accounts = c.get(AccountStore)
      const people = (await accounts.people()).filter(p => to.roles.includes(p.role))
      const endpoints = (await Promise.all(people.map(p => accounts.pushOf({ userId: p.id })))).flat()
      await c.get(APP_PUSH).notify(notice, { endpoints })
    }
  }

  /** Our own tools, then any MCP Workers. Override to change the set. */
  protected toolServers(c: Registry): ToolServer[] {
    const own: AppToolsContext<E> = { env: this.env, cipher: c.get(Cipher), notify: this.notify(c), registry: c }
    const servers = this.options.tools ? this.options.tools(own) : []
    for (const binding of (this.env.MCP_BINDINGS ?? '').split(',').map(s => s.trim()).filter(Boolean)) {
      const fetcher = (this.env as unknown as Record<string, unknown>)[binding] as Fetcher | undefined
      if (!fetcher || typeof fetcher.fetch !== 'function') throw new ConfigError(`${binding} is not a service binding`)
      servers.push(new McpToolServer(binding.toLowerCase().replace(/^mcp_/, ''), { binding: fetcher }))
    }
    return servers
  }

  protected tools(c: Registry) {
    c.bind(APP_TOOL_SERVERS, c => this.toolServers(c))
    c.bind(ToolBox, c => new ToolBox(c.get(APP_TOOL_SERVERS), c.get(Logger)))
    let hosts: Record<string, string[]> = {}
    if (this.env.CREDENTIAL_HOSTS) {
      try { hosts = JSON.parse(this.env.CREDENTIAL_HOSTS) } catch { throw new ConfigError('CREDENTIAL_HOSTS is not valid JSON') }
    }
    c.bind(CredentialBroker, c => new CredentialBroker({ secrets: c.get(SecretStore), hosts, audit: c.get(AuditLog) }))
  }

  protected app(c: Registry) {
    c.bind(Sessions, c => new Sessions({
      store: c.get(SessionStore), accounts: c.get(AccountStore), clock: c.get(Clock),
      idleDays: days(this.env.SESSION_IDLE_DAYS, 14), maxDays: days(this.env.SESSION_MAX_DAYS, 90),
    }))
    c.bind(Passkeys, c => new Passkeys({
      rp: c.get(RELYING_PARTY), accounts: c.get(AccountStore), access: c.get(Access), challenges: c.get(ChallengeStore),
      sessions: c.get(Sessions), audit: c.get(AuditLog), clock: c.get(Clock), push: c.get(PushSubscriptionStore),
    }))
    c.bind(Calls, c => new Calls({
      tools: c.get(ToolBox), pending: c.get(PendingCallStore), passkeys: c.get(Passkeys), access: c.get(Access),
      credentials: c.get(CredentialBroker), audit: c.get(AuditLog), clock: c.get(Clock), logger: c.get(Logger),
    }))
  }
}
