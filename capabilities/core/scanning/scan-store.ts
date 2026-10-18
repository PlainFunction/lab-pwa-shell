import { Port, type Manifest } from '../kernel/port'
import type { InboundFile } from '../ai/document-reader'

// Where scanned originals are kept. The paper usually goes in the bin once it's
// scanned, so the original photo or PDF is the record, not the text we read
// off it. Keyed by the SHA-256 of the bytes, so the same photo sent twice (a
// double tap, a retry on bad reception) is filed once.

export const SCAN_KINDS = ['bill', 'job-sheet', 'delivery-docket', 'other'] as const
export type ScanKind = (typeof SCAN_KINDS)[number]

export interface ScanRecord {
  /** SHA-256 of the original, hex. Also the id. */
  id: string
  name: string
  type: string
  size: number
  kind: ScanKind
  /** Short label for the list, e.g. "Reece receipt, PEX fittings". */
  title: string
  /** Date on the document, YYYY-MM-DD, when it had one. */
  date?: string
  scannedBy: string
  scannedAt: string
  /** What happened next, e.g. `approval:<id>` for a bill waiting on the owner. */
  routedTo?: string
}

export abstract class ScanStore extends Port {
  abstract get(id: string): Promise<ScanRecord | undefined>
  abstract put(file: InboundFile, record: ScanRecord): Promise<void>
  abstract open(id: string): Promise<{ record: ScanRecord; bytes: Uint8Array<ArrayBuffer> } | undefined>
  /** Newest first. */
  abstract recent(limit: number): Promise<ScanRecord[]>
}

const KEY = (id: string) => `scans/${id}`

/**
 * R2, in the client's own bucket (create it with `--jurisdiction` or
 * `--location oc` so it stays in Australia). The record rides along as custom
 * metadata, so one list call gives the recent scans without a database.
 */
export class R2ScanStore extends ScanStore {
  readonly #bucket: R2Bucket
  constructor(bucket: R2Bucket) {
    super()
    this.#bucket = bucket
  }

  async get(id: string) {
    const head = await this.#bucket.head(KEY(id))
    return head ? readRecord(head) : undefined
  }

  async put(file: InboundFile, record: ScanRecord) {
    await this.#bucket.put(KEY(record.id), file.bytes, {
      httpMetadata: { contentType: file.type },
      customMetadata: { record: JSON.stringify(record) },
      sha256: record.id,
    })
  }

  async open(id: string) {
    const obj = await this.#bucket.get(KEY(id))
    const record = obj && readRecord(obj)
    if (!obj || !record) return undefined
    return { record, bytes: new Uint8Array(await obj.arrayBuffer()) }
  }

  async recent(limit: number) {
    // R2 lists by key, and our keys are hashes, so sort here. Fine for a few
    // thousand scans; past that, keep an index in D1.
    const out: ScanRecord[] = []
    let cursor: string | undefined
    do {
      // `include` is honoured from compatibility date 2022-08-04; the default types predate it.
      const page = await this.#bucket.list({ prefix: 'scans/', include: ['customMetadata'], cursor } as R2ListOptions)
      for (const o of page.objects) { const r = readRecord(o); if (r) out.push(r) }
      cursor = page.truncated ? page.cursor : undefined
    } while (cursor)
    return out.sort((a, b) => b.scannedAt.localeCompare(a.scannedAt)).slice(0, limit)
  }

  describe(): Manifest {
    return { name: 'Scans (Cloudflare R2)', use: 'Keeping the original of every scanned document', personalInfo: ['whatever is on the paper: names, addresses, signatures'], storesIn: 'Cloudflare R2, the client\'s own bucket in Australia' }
  }
}

function readRecord(o: { customMetadata?: Record<string, string> }): ScanRecord | undefined {
  const raw = o.customMetadata?.record
  if (!raw) return undefined
  try { return JSON.parse(raw) as ScanRecord } catch { return undefined }
}

/** For tests and dry runs. */
export class MemoryScanStore extends ScanStore {
  readonly files = new Map<string, { record: ScanRecord; bytes: Uint8Array<ArrayBuffer> }>()
  async get(id: string) { return this.files.get(id)?.record }
  async put(file: InboundFile, record: ScanRecord) { this.files.set(record.id, { record: structuredClone(record), bytes: file.bytes.slice() }) }
  async open(id: string) { return this.files.get(id) }
  async recent(limit: number) { return [...this.files.values()].map(f => f.record).sort((a, b) => b.scannedAt.localeCompare(a.scannedAt)).slice(0, limit) }
  describe() { return { name: 'Scans (memory)', use: 'Tests', personalInfo: [], storesIn: 'Memory' } }
}
