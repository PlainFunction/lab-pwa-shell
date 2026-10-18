import { DocumentReader, type InboundFile } from '../ai/document-reader'
import type { Cache } from '../cache/cache'
import { sha256Hex } from '../kernel/encoding'
import { mergeManifest, type Manifest } from '../kernel/port'

/**
 * Reads each file once. The scanner reads a page to work out what it is, and
 * if it's a bill, BillCapture reads the same page again. Keyed by the hash of
 * the bytes, so the second read (and a re-sent photo) costs nothing.
 *
 * The text can hold names and addresses, so hand this a scoped, encrypted cache.
 */
export class CachedDocumentReader extends DocumentReader {
  readonly #inner: DocumentReader
  readonly #cache: Cache
  readonly #ttl: number

  constructor(inner: DocumentReader, cache: Cache, ttlSeconds = 24 * 3600) {
    super()
    this.#inner = inner
    this.#cache = cache
    this.#ttl = ttlSeconds
  }

  async toText(file: InboundFile) {
    return this.#cache.getOrSet(`doc:${await sha256Hex(file.bytes)}`, this.#ttl, () => this.#inner.toText(file))
  }

  describe(): Manifest {
    return mergeManifest(this.#inner.describe(), { name: 'Read once', use: this.#inner.describe().use, storesIn: `${this.#cache.describe().storesIn} (text, a day)` })
  }
}
