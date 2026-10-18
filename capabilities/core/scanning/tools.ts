import { z } from 'zod'
import { LocalToolServer, out, tool, ui } from '../slack-agent/tools/contract'
import type { DocumentScanner } from './scanner'
import type { ScanRecord, ScanStore } from './scan-store'

// Scanning as tools, so it runs wherever tools do: the app (a photo from the
// phone's camera) and the Slack agent (a photo attached in a thread). The
// photo arrives as a `ui.image` value and is read with `ctx.file`, so the
// caller decides which photos a call can reach.
//
// `scan` files things, so it isn't read-only: the app asks for a passkey and
// Slack shows the form first. `recent` only reads.

export const KIND_LABELS: Record<ScanRecord['kind'], string> = {
  'bill': 'Bill', 'job-sheet': 'Job sheet', 'delivery-docket': 'Delivery docket', 'other': 'Other',
}

const dated = (r: Pick<ScanRecord, 'kind' | 'date'>) => `${KIND_LABELS[r.kind]}${r.date ? `, dated ${r.date}` : ''}`
const day = (iso: string) => new Date(iso).toLocaleDateString('en-AU', { timeZone: 'Australia/Sydney', day: 'numeric', month: 'short' })

export interface ScanToolsOptions {
  scanner: DocumentScanner
  store: ScanStore
  /** Shown under each result, e.g. that a lab reads with a stand-in. */
  note?: string
}

export function scanTools({ scanner, store, note }: ScanToolsOptions) {
  return new LocalToolServer('scans', {
    scan: tool({
      title: 'Scan a document',
      description: 'Reads a photo of a receipt, bill, delivery docket or signed job sheet, works out what it is and files it',
      input: z.object({
        photo: ui.image('Photo of the document', { description: 'Flat on a table, in good light, with the whole page in frame' }),
      }),
      output: z.object({
        title: out.header('Scanned'),
        filed: out.field('Filed as').optional(),
        next: out.text('What happens next'),
        note: out.context('Note').optional(),
      }),
      run: async ({ photo }, ctx) => {
        const f = await ctx.file(photo)
        const result = await scanner.scan({ name: f.name, type: f.mimetype, bytes: new Uint8Array(f.bytes) }, { id: ctx.user, kind: 'person', via: 'tool' })
        if (result.status === 'unreadable') {
          return { title: "Couldn't read that", next: "There wasn't enough text in the photo. Try again with more light, flat on a table, with the whole page in frame.", note }
        }
        const r = result.record
        const next = result.status === 'duplicate'
          ? 'This one was already scanned, so nothing new was filed.'
          : r.routedTo ? "It's waiting for the owner to approve before it goes into the accounts." : "It's filed."
        return { title: r.title, filed: dated(r), next, note }
      },
    }),
    recent: tool({
      title: 'Recent scans',
      description: 'The last documents scanned, newest first',
      input: z.object({}),
      output: z.object({
        scans: out.list('Scanned'),
        note: out.context('Note').optional(),
      }),
      annotations: { readOnlyHint: true },
      run: async () => ({
        scans: (await store.recent(20)).map(r => ({ title: r.title, detail: `${dated(r)}${r.routedTo ? '. Waiting for approval' : ''}`, meta: day(r.scannedAt) })),
        note,
      }),
    }),
  }, {
    use: 'Scanning paperwork from a photo',
    personalInfo: ['whatever is on the paper: names, addresses, signatures'],
    checkedBy: 'Bills wait for the owner to approve before they reach the accounts',
    storesIn: 'Originals in the scan store',
  })
}
