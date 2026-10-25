import {
  AuditLog, Cipher, Clock, DEFAULT_GATEWAY, DocumentReader, DocumentScanner, Logger, R2ScanStore, ScriptedLanguageModel, WorkersAiDocumentReader, WorkersAiModel,
  scanTools, type AppToolsContext, type PwaEnv,
} from '#capabilities'

// Scanning paperwork from the phone's camera: our scanning capability as one
// more automation. The photo is uploaded with the form, approved with a
// passkey like anything that changes something, read, sorted and filed in R2.
//
// With the AI binding it reads photos with Workers AI, every call through AI
// Gateway (AI_GATEWAY_ID, or "default", made on the first call). Without it (wrangler dev
// with no Cloudflare login) every photo reads as the same sample receipt, and
// the result says so, so the rest of it can still be tried on a laptop.

export interface LabEnv extends PwaEnv {
  SCANS: R2Bucket
  AI?: Ai
  AI_GATEWAY_ID?: string
}

const SAMPLE = [
  'REECE PLUMBING  Marrickville', 'TAX INVOICE', 'Date: 17/10/2026',
  '2 x PEX 20mm elbow   $11.00', '1 x Tempering valve 15mm   $89.50', 'TOTAL (inc GST)  $111.50',
].join('\n')

/** Stands in for Workers AI: whatever the photo, it reads as the sample receipt. */
class SampleReader extends DocumentReader {
  async toText() { return SAMPLE }
  describe() { return { name: 'Sample reader', use: 'Trying scanning without Workers AI', personalInfo: [], storesIn: 'Not stored' } }
}

export function scanningTools({ env, registry }: AppToolsContext<LabEnv>) {
  const store = new R2ScanStore(env.SCANS, registry.get(Cipher))
  const ai = env.AI
  const gateway = { id: env.AI_GATEWAY_ID || DEFAULT_GATEWAY }
  const scanner = new DocumentScanner({
    reader: ai ? new WorkersAiDocumentReader(ai, { gateway }) : new SampleReader(),
    model: ai ? new WorkersAiModel({ ai, gateway }) : new ScriptedLanguageModel(JSON.stringify({ kind: 'bill', title: 'Reece receipt (sample)', date: '2026-10-17' })),
    store, audit: registry.get(AuditLog), clock: registry.get(Clock), logger: registry.get(Logger),
  })
  return scanTools({ scanner, store, note: ai ? undefined : "Workers AI isn't connected, so every photo reads as the same sample receipt." })
}
