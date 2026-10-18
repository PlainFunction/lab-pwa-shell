import { IMAGE_TYPES, MAX_IMAGE_BYTES, type FileData } from '../slack-agent/tools/contract'
import { ValidationError } from '../kernel/errors'
import { b64url, fromUtf8, utf8 } from '../kernel/encoding'
import { Port, type Manifest } from '../kernel/port'
import type { Cipher } from '../security/cipher'

// Photos people add to a form in the app, for a `ui.image` field. The shell
// uploads the photo first and puts its id in the call's arguments, so a call
// stays a small JSON object and the passkey still signs exactly what runs:
// the id is the SHA-256 of the bytes. Uploads belong to the person who made
// them and expire, so they're scratch space, not storage. A tool that keeps a
// photo (a scan) copies it somewhere of its own.

/** An hour: long enough to fill in a form and find the passkey. */
export const UPLOAD_TTL_SECONDS = 3600

export interface Upload { id: string; name: string; mimetype: string; size: number }

const cleanName = (name: string) => name.replace(/[\u0000-\u001f/\\]+/g, ' ').trim().slice(0, 120) || 'photo'

/** Checks a photo before it's kept, and works out its id. */
export async function prepareUpload(bytes: Uint8Array<ArrayBuffer>, mimetype: string, name: string): Promise<Upload> {
  if (!(IMAGE_TYPES as readonly string[]).includes(mimetype)) throw new ValidationError('Photos only: JPEG, PNG, GIF or WebP')
  if (bytes.length === 0 || bytes.length > MAX_IMAGE_BYTES) throw new ValidationError('The photo is empty or over 10 MB')
  return { id: b64url(await crypto.subtle.digest('SHA-256', bytes)), name: cleanName(name), mimetype, size: bytes.length }
}

export abstract class UploadStore extends Port {
  /** Keeps a photo for this person. The same photo twice is the same id. */
  abstract put(userId: string, upload: Upload, bytes: Uint8Array<ArrayBuffer>): Promise<void>
  /** This person's photo, or undefined if it isn't theirs or has expired. */
  abstract get(userId: string, id: string): Promise<FileData | undefined>
}

/**
 * Workers KV, sealed with AES-256-GCM bound to the person and the id, so a
 * value can't be read as someone else's. KV holds up to 25 MiB a value, which
 * a 10 MB photo fits sealed. It's eventually consistent between locations, but
 * the upload and the call come from the same phone seconds apart, which reads
 * back in the same location.
 */
export class KvUploadStore extends UploadStore {
  readonly #kv: KVNamespace
  readonly #cipher: Cipher
  constructor(kv: KVNamespace, cipher: Cipher) {
    super()
    this.#kv = kv
    this.#cipher = cipher
  }

  #key = (userId: string, id: string) => `upload:${userId}:${id}`

  async put(userId: string, upload: Upload, bytes: Uint8Array<ArrayBuffer>) {
    const key = this.#key(userId, upload.id)
    const [body, meta] = await Promise.all([
      this.#cipher.encrypt(bytes, `${key}:bytes`),
      this.#cipher.encrypt(utf8(JSON.stringify({ name: upload.name, mimetype: upload.mimetype })), `${key}:meta`),
    ])
    await this.#kv.put(key, body, { expirationTtl: UPLOAD_TTL_SECONDS, metadata: { meta } })
  }

  async get(userId: string, id: string): Promise<FileData | undefined> {
    const key = this.#key(userId, id)
    const { value, metadata } = await this.#kv.getWithMetadata<{ meta: string }>(key)
    if (!value || !metadata?.meta) return undefined
    try {
      const bytes = await this.#cipher.decrypt(value, `${key}:bytes`)
      const { name, mimetype } = JSON.parse(fromUtf8(await this.#cipher.decrypt(metadata.meta, `${key}:meta`))) as { name: string; mimetype: string }
      return { id, name, mimetype, bytes }
    } catch {
      // Sealed with a key that's since been dropped: as good as expired.
      return undefined
    }
  }

  describe(): Manifest {
    return { name: 'Photo uploads (KV)', use: 'Photos added to a form, until the automation runs', personalInfo: ['whatever is in the photo'], storesIn: 'Cloudflare KV, AES-256-GCM encrypted, deleted after an hour' }
  }
}

/** For tests. */
export class MemoryUploadStore extends UploadStore {
  readonly files = new Map<string, FileData>()
  async put(userId: string, upload: Upload, bytes: Uint8Array<ArrayBuffer>) {
    this.files.set(`${userId}:${upload.id}`, { id: upload.id, name: upload.name, mimetype: upload.mimetype, bytes: bytes.slice() })
  }
  async get(userId: string, id: string) { return this.files.get(`${userId}:${id}`) }
  describe() { return { name: 'Photo uploads (memory)', use: 'Tests', personalInfo: [], storesIn: 'Memory' } }
}
