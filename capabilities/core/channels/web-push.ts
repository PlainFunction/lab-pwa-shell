import { Port } from '../kernel/port'
import { UpstreamError } from '../kernel/errors'
import { b64url, concat, fromB64url, randomBytes, sha256Hex, utf8 } from '../kernel/encoding'
import type { Clock } from '../kernel/clock'
import type { Cipher } from '../security/cipher'
import type { SecretRef } from '../secrets/secrets'
import { HttpClient, type Fetch } from '../security/egress'
import { Notifier, type Notice } from './channel'

// Web Push: notifications on the owner's phone or laptop without an app store
// app or SMS. Works on Android, desktop browsers, and iPhone once the site is
// added to the home screen (iOS 16.4+).
//
// The payload is encrypted to the device (RFC 8291), so Apple, Google and
// Mozilla's push services carry it without being able to read it. VAPID
// (RFC 8292) proves the push came from us.

export interface PushSubscription {
  endpoint: string
  keys: { p256dh: string; auth: string }
}

/** Where the owner's devices are remembered. */
export abstract class PushSubscriptionStore extends Port {
  abstract list(): Promise<PushSubscription[]>
  abstract add(sub: PushSubscription): Promise<void>
  abstract remove(endpoint: string): Promise<void>
}

export class MemoryPushSubscriptionStore extends PushSubscriptionStore {
  readonly #subs = new Map<string, PushSubscription>()
  async list() { return [...this.#subs.values()] }
  async add(s: PushSubscription) { this.#subs.set(s.endpoint, s) }
  async remove(endpoint: string) { this.#subs.delete(endpoint) }
  describe() { return { name: 'Memory push subscriptions', use: 'Tests', personalInfo: [], storesIn: 'Memory' } }
}

/** KV, with each subscription sealed (its keys are what let us reach the device). */
export class KvPushSubscriptionStore extends PushSubscriptionStore {
  readonly #kv: KVNamespace
  readonly #cipher: Cipher
  constructor(kv: KVNamespace, cipher: Cipher) {
    super()
    this.#kv = kv
    this.#cipher = cipher
  }
  #key = async (endpoint: string) => `push:${await sha256Hex(endpoint)}`
  async list() {
    const { keys } = await this.#kv.list({ prefix: 'push:' })
    const subs = await Promise.all(keys.map(async k => {
      const sealed = await this.#kv.get(k.name)
      return sealed ? this.#cipher.decryptJson<PushSubscription>(sealed, k.name).catch(() => undefined) : undefined
    }))
    return subs.filter((s): s is PushSubscription => !!s)
  }
  async add(s: PushSubscription) {
    const key = await this.#key(s.endpoint)
    await this.#kv.put(key, await this.#cipher.encryptJson(s, key))
  }
  async remove(endpoint: string) { await this.#kv.delete(await this.#key(endpoint)) }
  describe() { return { name: 'KV push subscriptions', use: "Remembering the owner's devices for notifications", personalInfo: [], storesIn: 'Cloudflare Workers KV, encrypted' } }
}

/**
 * VAPID keys. Generate once per client with `npx web-push generate-vapid-keys`
 * (or any P-256 generator). The public key goes to the browser when it
 * subscribes; the private key is a Worker secret.
 */
export interface VapidKeys {
  /** Uncompressed P-256 public key, base64url (65 bytes). */
  publicKey: string
  /** P-256 private scalar `d`, base64url (32 bytes). */
  privateKey: string
  /** `mailto:` or `https:` contact for the push service. */
  subject: string
}

export class WebPushNotifier extends Notifier {
  readonly #subs: PushSubscriptionStore
  readonly #vapid: () => Promise<VapidKeys>
  readonly #clock: Clock
  readonly #http: HttpClient
  #signingKey?: Promise<CryptoKey>

  static readonly PUSH_SERVICES = ['fcm.googleapis.com', '*.push.apple.com', '*.push.services.mozilla.com', '*.notify.windows.com']

  constructor(opts: { subscriptions: PushSubscriptionStore; vapid: VapidKeys | { publicKey: string; privateKey: SecretRef; subject: string }; clock: Clock; fetch?: Fetch }) {
    super()
    this.#subs = opts.subscriptions
    const v = opts.vapid
    this.#vapid = async () => ({ ...v, privateKey: typeof v.privateKey === 'string' ? v.privateKey : (await v.privateKey.get()).reveal() })
    this.#clock = opts.clock
    this.#http = new HttpClient({ service: 'Web Push', allow: WebPushNotifier.PUSH_SERVICES, fetch: opts.fetch })
  }

  /** To every subscribed device, or only to `to.endpoints` (say, the devices of the people in one role). */
  async notify(n: Notice, to?: { endpoints: string[] }) {
    const only = to && new Set(to.endpoints)
    const subs = (await this.#subs.list()).filter(s => !only || only.has(s.endpoint))
    if (subs.length === 0) throw new UpstreamError('Web Push', 0, 'no devices subscribed')
    const payload = utf8(JSON.stringify({ title: n.title, body: n.body, url: n.url, tag: n.tag }))
    const results = await Promise.allSettled(subs.map(s => this.#send(s, payload, n.urgency ?? 'normal')))
    if (results.every(r => r.status === 'rejected')) throw new UpstreamError('Web Push', 0, 'no device accepted the notice')
  }

  async #send(sub: PushSubscription, payload: Uint8Array<ArrayBuffer>, urgency: string) {
    const url = new URL(sub.endpoint)
    const { publicKey, subject } = await this.#vapid()
    const jwt = await this.#vapidJwt(url.origin, subject)
    const res = await this.#http.request(url, {
      method: 'POST',
      headers: {
        authorization: `vapid t=${jwt}, k=${publicKey}`,
        'content-encoding': 'aes128gcm',
        'content-type': 'application/octet-stream',
        ttl: String(24 * 3600),
        urgency,
      },
      body: await encryptPayload(sub, payload),
    })
    // Gone: the owner uninstalled or revoked. Forget the device.
    if (res.status === 404 || res.status === 410) {
      await this.#subs.remove(sub.endpoint)
      throw new UpstreamError('Web Push', res.status, 'subscription expired')
    }
    if (!res.ok) throw new UpstreamError('Web Push', res.status)
  }

  async #vapidJwt(audience: string, subject: string) {
    this.#signingKey ??= (async () => {
      const { publicKey, privateKey } = await this.#vapid()
      const pub = fromB64url(publicKey)
      return crypto.subtle.importKey('jwk', {
        kty: 'EC', crv: 'P-256', d: privateKey, x: b64url(pub.slice(1, 33)), y: b64url(pub.slice(33, 65)), ext: true,
      }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
    })()
    const header = b64url(utf8(JSON.stringify({ typ: 'JWT', alg: 'ES256' })))
    const exp = Math.floor(this.#clock.now().getTime() / 1000) + 12 * 3600
    const claims = b64url(utf8(JSON.stringify({ aud: audience, exp, sub: subject })))
    // Web Crypto's ECDSA output is already the raw r||s that JWS wants.
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await this.#signingKey, utf8(`${header}.${claims}`))
    return `${header}.${claims}.${b64url(sig)}`
  }

  describe() {
    return { name: 'Web Push', use: "Notifications on the owner's phone, encrypted to the device", personalInfo: [], storesIn: 'Not stored; push services relay it encrypted', egress: WebPushNotifier.PUSH_SERVICES }
  }
}

async function hkdf(salt: Uint8Array<ArrayBuffer>, ikm: Uint8Array<ArrayBuffer>, info: Uint8Array<ArrayBuffer>, bytes: number) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8))
}

/** RFC 8291 aes128gcm, one record. Exported for the round-trip test. */
export async function encryptPayload(sub: PushSubscription, plaintext: Uint8Array<ArrayBuffer>, salt = randomBytes(16)): Promise<Uint8Array<ArrayBuffer>> {
  const uaPublic = fromB64url(sub.keys.p256dh)
  const authSecret = fromB64url(sub.keys.auth)

  const local = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']) as CryptoKeyPair
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', local.publicKey) as ArrayBuffer)
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  // workers-types spells the field $public; the runtime takes the standard name.
  const ecdh = { name: 'ECDH', public: uaKey } as unknown as SubtleCryptoDeriveKeyAlgorithm
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits(ecdh, local.privateKey, 256))

  const ikm = await hkdf(authSecret, ecdhSecret, concat(utf8('WebPush: info\0'), uaPublic, asPublic), 32)
  const cek = await hkdf(salt, ikm, utf8('Content-Encoding: aes128gcm\0'), 16)
  const nonce = await hkdf(salt, ikm, utf8('Content-Encoding: nonce\0'), 12)

  // 0x02 marks the last (only) record.
  const padded = concat(plaintext, new Uint8Array([2]))
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt'])
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, padded))

  const rs = new Uint8Array(4)
  new DataView(rs.buffer).setUint32(0, 4096)
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ciphertext)
}
