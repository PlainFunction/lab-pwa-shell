import { Port } from '../kernel/port'
import { NotAllowedError } from '../kernel/errors'
import { fromB64url, fromUtf8, utf8 } from '../kernel/encoding'
import type { Clock } from '../kernel/clock'
import type { Cache } from '../cache/cache'
import { HttpClient, type Fetch } from './egress'

export interface Principal {
  /** Email for a person, or the service token's client id for a machine. */
  id: string
  email?: string
  kind: 'person' | 'service'
  /** Which verifier vouched for them. */
  via: string
}

/**
 * Works out who is making a request, or throws NotAllowedError.
 * Every admin route calls this. There's no "trusted network": being on the
 * office wifi or knowing a URL counts for nothing.
 */
export abstract class IdentityVerifier extends Port {
  abstract verify(request: Request): Promise<Principal>
}

interface Jwk { kid: string; kty: string; n: string; e: string; alg?: string }
interface AccessClaims {
  aud: string | string[]
  iss: string
  exp: number
  nbf?: number
  iat?: number
  email?: string
  sub?: string
  common_name?: string
  type?: string
}

/**
 * Cloudflare Access (Zero Trust). Put the admin routes behind an Access
 * application (one-time PIN to the owner's email, or Google/Microsoft login)
 * and Access adds a signed JWT to every request that gets through. This checks
 * that JWT, so a request that somehow skips Access is still refused.
 *
 * Signing keys are cached for an hour (they rotate every six weeks and old
 * ones stay published for a while). An unknown `kid` forces one refetch.
 */
export class CloudflareAccessVerifier extends IdentityVerifier {
  readonly #team: string
  readonly #aud: string
  readonly #cache: Cache
  readonly #clock: Clock
  readonly #http: HttpClient

  constructor(opts: { teamDomain: string; audience: string; cache: Cache; clock: Clock; fetch?: Fetch }) {
    super()
    // Accept "myteam" or "myteam.cloudflareaccess.com".
    this.#team = opts.teamDomain.replace(/^https:\/\//, '').replace(/\.cloudflareaccess\.com\/?$/, '')
    if (!/^[a-z0-9-]+$/i.test(this.#team)) throw new NotAllowedError('Bad Access team domain')
    this.#aud = opts.audience
    this.#cache = opts.cache
    this.#clock = opts.clock
    this.#http = new HttpClient({ service: 'Cloudflare Access', allow: [`${this.#team}.cloudflareaccess.com`], fetch: opts.fetch })
  }

  get issuer() { return `https://${this.#team}.cloudflareaccess.com` }

  async #keys(force = false): Promise<Jwk[]> {
    const key = `access-jwks:${this.#team}`
    if (force) await this.#cache.delete(key)
    return this.#cache.getOrSet(key, 3600, async () =>
      (await this.#http.json<{ keys: Jwk[] }>(`${this.issuer}/cdn-cgi/access/certs`)).keys)
  }

  async verify(request: Request): Promise<Principal> {
    const jwt = request.headers.get('cf-access-jwt-assertion')
    if (!jwt) throw new NotAllowedError('No Access token')
    const [h, p, s] = jwt.split('.')
    if (!h || !p || !s) throw new NotAllowedError('Malformed Access token')

    let header: { alg: string; kid: string }
    let claims: AccessClaims
    try {
      header = JSON.parse(fromUtf8(fromB64url(h)))
      claims = JSON.parse(fromUtf8(fromB64url(p)))
    } catch {
      throw new NotAllowedError('Malformed Access token')
    }
    if (header.alg !== 'RS256') throw new NotAllowedError('Unexpected token algorithm')

    let jwk = (await this.#keys()).find(k => k.kid === header.kid)
    if (!jwk) jwk = (await this.#keys(true)).find(k => k.kid === header.kid)
    if (!jwk) throw new NotAllowedError('Unknown signing key')

    const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, fromB64url(s), utf8(`${h}.${p}`))
    if (!ok) throw new NotAllowedError('Bad signature')

    const now = Math.floor(this.#clock.now().getTime() / 1000)
    const skew = 60
    const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
    if (claims.iss !== this.issuer) throw new NotAllowedError('Wrong issuer')
    if (!auds.includes(this.#aud)) throw new NotAllowedError('Wrong audience')
    if (claims.exp + skew < now) throw new NotAllowedError('Token expired')
    if (claims.nbf && claims.nbf - skew > now) throw new NotAllowedError('Token not yet valid')

    if (claims.email) return { id: claims.email.toLowerCase(), email: claims.email.toLowerCase(), kind: 'person', via: 'cloudflare-access' }
    if (claims.common_name) return { id: claims.common_name, kind: 'service', via: 'cloudflare-access' }
    throw new NotAllowedError('Token names nobody')
  }

  describe() {
    return {
      name: 'Cloudflare Access',
      use: 'Checking who is signed in before they can see or approve anything',
      personalInfo: ['email'],
      storesIn: 'Nowhere (verified per request)',
      egress: [`${this.#team}.cloudflareaccess.com`],
    }
  }
}

/** For tests and local dev only: trusts a fixed principal. Refuses to run with a real Access config. */
export class FixedIdentityVerifier extends IdentityVerifier {
  readonly #principal: Principal | undefined
  constructor(principal?: Principal) {
    super()
    this.#principal = principal
  }
  async verify(): Promise<Principal> {
    if (!this.#principal) throw new NotAllowedError('Nobody signed in')
    return this.#principal
  }
  describe() {
    return { name: 'Fixed identity (dev only)', use: 'Local development', personalInfo: [], storesIn: 'Nowhere' }
  }
}
