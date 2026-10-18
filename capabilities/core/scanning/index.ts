// Scanning paperwork: a photo in, read with a DocumentReader, sorted by a
// LanguageModel, the original kept in a ScanStore, bills on to BillCapture.
// See README.spec.md. Like the Slack agent and the app, it has its own entry
// point rather than going through core's index, because its tools use the
// Slack agent's tool contract.

export { DocumentScanner, SCAN_TYPES, MAX_SCAN_BYTES, type ScanResult, type BillRouter } from './scanner'
export { ScanStore, R2ScanStore, MemoryScanStore, SCAN_KINDS, type ScanKind, type ScanRecord } from './scan-store'
export { CachedDocumentReader } from './cached-reader'
export { scanTools, KIND_LABELS, type ScanToolsOptions } from './tools'
