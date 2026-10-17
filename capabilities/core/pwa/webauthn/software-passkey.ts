import { b64url, concat, fromB64url, randomBytes, utf8 } from '../../kernel/encoding'
import { encodeCbor, type Cbor } from './cbor'
import type { AssertionJSON, RegistrationJSON } from './webauthn'

// A passkey made in software, for tests: it answers the same options a phone
// would and signs the same bytes, so the real checks run against it. Every
// field can be bent (origin, RP id, flags, counter) to test the refusals.

export interface CreationOptions { challenge: string; rp: { id?: string; name: string }; user: { id: string; name: string } }
export interface RequestOptions { challenge: string; rpId?: string }

export interface Bend {
  origin?: string
  rpId?: string
  /** Face ID, fingerprint or PIN. Default true. */
  verified?: boolean
  type?: string
  crossOrigin?: boolean
}

function rawToDer(raw: Uint8Array): Uint8Array<ArrayBuffer> {
  const int = (b: Uint8Array) => {
    let v = b
    while (v.length > 1 && v[0] === 0 && !(v[1] & 0x80)) v = v.subarray(1)
    if (v[0] & 0x80) v = concat(new Uint8Array([0]), v)
    return concat(new Uint8Array([0x02, v.length]), v)
  }
  const body = concat(int(raw.subarray(0, 32)), int(raw.subarray(32)))
  return concat(new Uint8Array([0x30, body.length]), body)
}

export class SoftwarePasskey {
  readonly origin: string
  readonly id: Uint8Array<ArrayBuffer>
  readonly alg: -7 | -8
  /** Starts at 0, as synced passkeys stay. Set it to count like a security key does. */
  counter = 0
  counts = false
  /** Like iCloud Keychain or Google Password Manager. False is a passkey bound to one device. */
  synced = true
  userHandle?: string
  readonly #keys: CryptoKeyPair

  private constructor(origin: string, alg: -7 | -8, keys: CryptoKeyPair) {
    this.origin = origin
    this.alg = alg
    this.#keys = keys
    this.id = randomBytes(16)
  }

  static async create(origin: string, alg: -7 | -8 = -7): Promise<SoftwarePasskey> {
    const keys = alg === -7
      ? await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair
      : await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair
    return new SoftwarePasskey(origin, alg, keys)
  }

  get credentialId() { return b64url(this.id) }

  async #cose(): Promise<Uint8Array> {
    const jwk = await crypto.subtle.exportKey('jwk', this.#keys.publicKey) as JsonWebKey
    const m = this.alg === -7
      ? new Map<Cbor, Cbor>([[1, 2], [3, -7], [-1, 1], [-2, fromB64url(jwk.x!)], [-3, fromB64url(jwk.y!)]])
      : new Map<Cbor, Cbor>([[1, 1], [3, -8], [-1, 6], [-2, fromB64url(jwk.x!)]])
    return encodeCbor(m)
  }

  #clientData(type: string, challenge: string, bend: Bend) {
    return utf8(JSON.stringify({ type: bend.type ?? type, challenge, origin: bend.origin ?? this.origin, crossOrigin: bend.crossOrigin ?? false }))
  }

  async #authData(rpId: string, flags: number, attested?: Uint8Array) {
    const count = new Uint8Array(4)
    if (this.counts) this.counter++
    new DataView(count.buffer).setUint32(0, this.counter)
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(rpId)))
    return concat(hash, new Uint8Array([flags]), count, ...(attested ? [attested] : []))
  }

  /** What `navigator.credentials.create` would hand back, as JSON. */
  async register(options: CreationOptions, bend: Bend = {}): Promise<RegistrationJSON> {
    const rpId = bend.rpId ?? options.rp.id ?? new URL(this.origin).hostname
    this.userHandle = options.user.id
    const idLength = new Uint8Array([this.id.length >> 8, this.id.length & 0xff])
    const attested = concat(new Uint8Array(16), idLength, this.id, await this.#cose())
    // UP, UV unless bent, BE when synced, and AT.
    const flags = 0x01 | (bend.verified === false ? 0 : 0x04) | (this.synced ? 0x08 : 0) | 0x40
    const authData = await this.#authData(rpId, flags, attested)
    const attestationObject = encodeCbor(new Map<Cbor, Cbor>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))
    return {
      id: this.credentialId, rawId: this.credentialId, type: 'public-key',
      response: { clientDataJSON: b64url(this.#clientData('webauthn.create', options.challenge, bend)), attestationObject: b64url(attestationObject), transports: ['internal'] },
    }
  }

  /** What `navigator.credentials.get` would hand back, as JSON. */
  async sign(options: RequestOptions, bend: Bend = {}): Promise<AssertionJSON> {
    const rpId = bend.rpId ?? options.rpId ?? new URL(this.origin).hostname
    const flags = 0x01 | (bend.verified === false ? 0 : 0x04) | (this.synced ? 0x08 : 0)
    const authData = await this.#authData(rpId, flags)
    const clientData = this.#clientData('webauthn.get', options.challenge, bend)
    const signed = concat(authData, new Uint8Array(await crypto.subtle.digest('SHA-256', clientData)))
    const sig = this.alg === -7
      ? rawToDer(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.#keys.privateKey, signed)))
      : new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, this.#keys.privateKey, signed))
    return {
      id: this.credentialId, rawId: this.credentialId, type: 'public-key',
      response: { clientDataJSON: b64url(clientData), authenticatorData: b64url(authData), signature: b64url(sig), userHandle: this.userHandle },
    }
  }
}
