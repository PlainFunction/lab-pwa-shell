import { z } from 'zod'
import { NotAllowedError, ValidationError } from '../../kernel/errors'
import { b64url, concat, fromB64url, fromUtf8, timingSafeEqual, utf8 } from '../../kernel/encoding'
import { decodeCbor, decodeCborAt, type Cbor } from './cbor'

// Checking passkeys (WebAuthn Level 3) on the server, with Web Crypto only.
//
// Registration: the browser's clientDataJSON must carry our challenge and our
// origin, and the authenticator data must be for our RP id, with the person
// present and verified (Face ID, a fingerprint or a PIN). We don't check
// attestation: we ask for none, and trust comes from the one-time invite the
// passkey was made with, not from who made the authenticator.
//
// Sign-in and confirming: the same checks, then the signature over
// authenticatorData + SHA-256(clientDataJSON) with the key we stored.

/** Who we are to the browser. `id` is the host name passkeys are bound to; `origin` is the exact origin pages are served from. */
export interface RelyingParty { id: string; name: string; origin: string }

/** COSE algorithm ids we accept, most preferred first: ES256, Ed25519, RS256. */
export const ALGORITHMS = [-7, -8, -257] as const

const b64 = z.string().regex(/^[A-Za-z0-9_-]*$/).max(16_384)

/** What the browser sends after `navigator.credentials.create`, binary fields as base64url. */
export const registrationSchema = z.object({
  id: b64.min(1).max(1366),
  rawId: b64.min(1).max(1366),
  type: z.literal('public-key'),
  response: z.object({
    clientDataJSON: b64.min(1),
    attestationObject: b64.min(1),
    transports: z.array(z.string().max(32)).max(8).optional(),
  }),
})

/** What the browser sends after `navigator.credentials.get`. */
export const assertionSchema = z.object({
  id: b64.min(1).max(1366),
  rawId: b64.min(1).max(1366),
  type: z.literal('public-key'),
  response: z.object({
    clientDataJSON: b64.min(1),
    authenticatorData: b64.min(37),
    signature: b64.min(1),
    userHandle: b64.max(128).nullish(),
  }),
})

export type RegistrationJSON = z.infer<typeof registrationSchema>
export type AssertionJSON = z.infer<typeof assertionSchema>

const FLAG_UP = 0x01
const FLAG_UV = 0x04
const FLAG_BE = 0x08
const FLAG_AT = 0x40

export interface AuthData {
  rpIdHash: Uint8Array
  flags: number
  signCount: number
  /** Only when a passkey was just made. */
  attested?: { aaguid: Uint8Array; credentialId: Uint8Array; publicKey: Uint8Array }
}

export function parseAuthData(bytes: Uint8Array): AuthData {
  if (bytes.length < 37) throw new ValidationError('Authenticator data is too short')
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const flags = bytes[32]
  const out: AuthData = { rpIdHash: bytes.slice(0, 32), flags, signCount: view.getUint32(33) }
  if (flags & FLAG_AT) {
    if (bytes.length < 55) throw new ValidationError('Authenticator data is too short')
    const idLength = view.getUint16(53)
    if (idLength > 1023 || 55 + idLength > bytes.length) throw new ValidationError('Credential id is the wrong length')
    const credentialId = bytes.slice(55, 55 + idLength)
    const { end } = decodeCborAt(bytes, 55 + idLength)
    out.attested = { aaguid: bytes.slice(37, 53), credentialId, publicKey: bytes.slice(55 + idLength, end) }
  }
  return out
}

interface ClientData { type: string; challenge: string; origin: string; crossOrigin?: boolean }

/** The challenge a browser says it signed. Untrusted until the checks below pass; only used to look the challenge up. */
export function claimedChallenge(clientDataJSON: string): string {
  try {
    const data = JSON.parse(fromUtf8(fromB64url(clientDataJSON))) as Partial<ClientData>
    return typeof data.challenge === 'string' ? data.challenge : ''
  } catch {
    return ''
  }
}

function checkClientData(clientDataJSON: Uint8Array, type: 'webauthn.create' | 'webauthn.get', challenge: string, rp: RelyingParty) {
  let data: Partial<ClientData>
  try { data = JSON.parse(fromUtf8(clientDataJSON)) } catch { throw new ValidationError('clientDataJSON is not JSON') }
  if (data.type !== type) throw new NotAllowedError(`Expected ${type}`)
  if (typeof data.challenge !== 'string' || !timingSafeEqual(utf8(data.challenge), utf8(challenge))) throw new NotAllowedError('Wrong challenge')
  if (data.origin !== rp.origin) throw new NotAllowedError('Wrong origin')
  // Our pages never embed each other, so a passkey prompt from inside a frame isn't ours.
  if (data.crossOrigin === true) throw new NotAllowedError('Cross-origin request')
}

async function checkAuthData(auth: AuthData, rp: RelyingParty) {
  const want = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(rp.id)))
  if (!timingSafeEqual(auth.rpIdHash, want)) throw new NotAllowedError('Passkey is for another site')
  if (!(auth.flags & FLAG_UP)) throw new NotAllowedError('Nobody was present')
  // Present isn't enough: we want Face ID, a fingerprint or the device PIN, every time.
  if (!(auth.flags & FLAG_UV)) throw new NotAllowedError('The person was not verified')
}

const field = (m: Map<Cbor, Cbor>, k: number): Cbor => m.get(k)
const bytesOf = (v: Cbor, what: string, length?: number): Uint8Array<ArrayBuffer> => {
  if (!(v instanceof Uint8Array) || (length !== undefined && v.length !== length)) throw new ValidationError(`COSE key has a bad ${what}`)
  return new Uint8Array(v)
}

export interface ImportedKey { alg: number; key: CryptoKey; verify: string | SubtleCryptoSignAlgorithm }

/** A COSE public key (RFC 9053) as a Web Crypto key we can verify with. */
export async function importCoseKey(cose: Uint8Array): Promise<ImportedKey> {
  const m = decodeCbor(cose)
  if (!(m instanceof Map)) throw new ValidationError('COSE key is not a map')
  const kty = field(m, 1)
  const alg = field(m, 3)
  if (alg === -7) {
    if (kty !== 2 || field(m, -1) !== 1) throw new ValidationError('ES256 key must be EC2 on P-256')
    const jwk = { kty: 'EC', crv: 'P-256', x: b64url(bytesOf(field(m, -2), 'x', 32)), y: b64url(bytesOf(field(m, -3), 'y', 32)) }
    return { alg, key: await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']), verify: { name: 'ECDSA', hash: 'SHA-256' } }
  }
  if (alg === -8) {
    if (kty !== 1 || field(m, -1) !== 6) throw new ValidationError('EdDSA key must be OKP on Ed25519')
    return { alg, key: await crypto.subtle.importKey('raw', bytesOf(field(m, -2), 'x', 32), { name: 'Ed25519' }, false, ['verify']), verify: { name: 'Ed25519' } }
  }
  if (alg === -257) {
    if (kty !== 3) throw new ValidationError('RS256 key must be RSA')
    const n = bytesOf(field(m, -1), 'modulus')
    if (n.length < 256) throw new ValidationError('RSA keys under 2048 bits are refused')
    const jwk = { kty: 'RSA', alg: 'RS256', n: b64url(n), e: b64url(bytesOf(field(m, -2), 'exponent')) }
    return { alg, key: await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']), verify: { name: 'RSASSA-PKCS1-v1_5' } }
  }
  throw new ValidationError(`COSE algorithm ${String(alg)} is not supported`)
}

/**
 * ECDSA signatures from authenticators are DER (a SEQUENCE of two INTEGERs);
 * Web Crypto wants r and s side by side, each 32 bytes.
 */
export function derToRaw(der: Uint8Array): Uint8Array<ArrayBuffer> {
  const fail = () => { throw new ValidationError('Signature is not DER') }
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2) fail()
  let pos = 2
  const int = () => {
    if (der[pos] !== 0x02) fail()
    const len = der[pos + 1]
    if (len < 1 || len > 33 || pos + 2 + len > der.length) fail()
    let v = der.subarray(pos + 2, pos + 2 + len)
    pos += 2 + len
    while (v.length > 32 && v[0] === 0) v = v.subarray(1)
    if (v.length > 32) fail()
    const out = new Uint8Array(32)
    out.set(v, 32 - v.length)
    return out
  }
  const r = int()
  const s = int()
  if (pos !== der.length) fail()
  return concat(r, s)
}

export interface VerifiedRegistration {
  credentialId: string
  /** The COSE key, base64url, as stored. */
  publicKey: string
  alg: number
  signCount: number
  /** A synced passkey (iCloud Keychain, Google Password Manager) comes back on a new phone; a device-bound one doesn't. */
  synced: boolean
}

export async function verifyRegistration(input: unknown, o: { rp: RelyingParty; challenge: string }): Promise<VerifiedRegistration> {
  const parsed = registrationSchema.safeParse(input)
  if (!parsed.success) throw new ValidationError('Not a passkey registration')
  const cred = parsed.data
  checkClientData(fromB64url(cred.response.clientDataJSON), 'webauthn.create', o.challenge, o.rp)

  const attestation = decodeCbor(fromB64url(cred.response.attestationObject))
  if (!(attestation instanceof Map)) throw new ValidationError('Attestation is not a map')
  const authBytes = attestation.get('authData')
  if (!(authBytes instanceof Uint8Array)) throw new ValidationError('Attestation has no authenticator data')
  const auth = parseAuthData(authBytes)
  await checkAuthData(auth, o.rp)
  if (!auth.attested) throw new ValidationError('No passkey was made')

  const id = b64url(auth.attested.credentialId)
  if (id !== cred.rawId || id !== cred.id) throw new ValidationError('Credential id does not match')
  const { alg } = await importCoseKey(auth.attested.publicKey)
  if (!(ALGORITHMS as readonly number[]).includes(alg)) throw new ValidationError('Algorithm not offered')
  return { credentialId: id, publicKey: b64url(auth.attested.publicKey), alg, signCount: auth.signCount, synced: !!(auth.flags & FLAG_BE) }
}

export interface VerifiedAssertion {
  credentialId: string
  signCount: number
  /** The user id the passkey was made for, when the browser sends it. */
  userHandle?: string
}

export async function verifyAssertion(input: unknown, o: { rp: RelyingParty; challenge: string; publicKey: string; signCount: number }): Promise<VerifiedAssertion> {
  const parsed = assertionSchema.safeParse(input)
  if (!parsed.success) throw new ValidationError('Not a passkey assertion')
  const cred = parsed.data
  if (cred.id !== cred.rawId) throw new ValidationError('Credential id does not match')
  const clientData = fromB64url(cred.response.clientDataJSON)
  checkClientData(clientData, 'webauthn.get', o.challenge, o.rp)

  const authBytes = fromB64url(cred.response.authenticatorData)
  const auth = parseAuthData(authBytes)
  await checkAuthData(auth, o.rp)

  const { key, alg, verify } = await importCoseKey(fromB64url(o.publicKey))
  const signed = concat(authBytes, new Uint8Array(await crypto.subtle.digest('SHA-256', clientData)))
  const raw = fromB64url(cred.response.signature)
  const signature = alg === -7 ? derToRaw(raw) : raw
  if (!(await crypto.subtle.verify(verify, key, signature, signed))) throw new NotAllowedError('Bad passkey signature')

  // Synced passkeys always say 0. A device that counts and goes backwards may have been copied.
  if ((auth.signCount !== 0 || o.signCount !== 0) && auth.signCount <= o.signCount) throw new NotAllowedError('Passkey counter went backwards')
  return { credentialId: cred.id, signCount: auth.signCount, userHandle: cred.response.userHandle ?? undefined }
}
