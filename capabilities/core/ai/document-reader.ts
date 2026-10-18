import { Port } from '../kernel/port'
import { UpstreamError } from '../kernel/errors'

export interface InboundFile { name: string; type: string; bytes: Uint8Array<ArrayBuffer> }

/** Turns a PDF, image or Office file into text a model can read. */
export abstract class DocumentReader extends Port {
  abstract toText(file: InboundFile): Promise<string>
}

/**
 * Workers AI document conversion (`env.AI.toMarkdown`). PDFs, images (with OCR
 * and a description), spreadsheets and Word files. Runs on Cloudflare, through
 * AI Gateway when given one, with logging off (the papers are bills and receipts).
 */
export class WorkersAiDocumentReader extends DocumentReader {
  readonly #ai: Ai
  readonly #gateway?: { id: string; collectLog?: boolean }
  constructor(ai: Ai, opts: { gateway?: { id: string; collectLog?: boolean } } = {}) {
    super()
    this.#ai = ai
    this.#gateway = opts.gateway
  }

  async toText(file: InboundFile) {
    const options = this.#gateway ? { gateway: { id: this.#gateway.id, collectLog: this.#gateway.collectLog ?? false } } : undefined
    const out = await this.#ai.toMarkdown({ name: file.name, blob: new Blob([file.bytes], { type: file.type }) }, options)
    if (out.format === 'error') throw new UpstreamError('Workers AI toMarkdown', 0, out.error)
    return out.data
  }

  describe() {
    return { name: 'Workers AI document conversion', use: 'Reading supplier bills and receipts', personalInfo: ['supplier details'], usesAi: true, storesIn: this.#gateway?.collectLog ? 'Cloudflare AI Gateway logs' : 'Not stored (Cloudflare)' }
  }
}

/** Plain text files pass straight through. For tests and .txt/.csv attachments. */
export class PlainTextReader extends DocumentReader {
  async toText(file: InboundFile) { return new TextDecoder().decode(file.bytes) }
  describe() { return { name: 'Plain text', use: 'Reading text attachments', personalInfo: [], storesIn: 'Not stored' } }
}
