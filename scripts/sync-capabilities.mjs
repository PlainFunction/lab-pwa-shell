// Copies the capabilities this lab uses into ./capabilities, so the lab can be
// shared as its own repo. The list isn't kept by hand: it's every file that
// ./capabilities/index.ts reaches, followed through relative imports, plus
// EXTRA below: the schema, and the shell, which the browser loads rather than
// the Worker. TypeScript in EXTRA is followed through its imports too.
//
//   node scripts/sync-capabilities.mjs           copy (after changing capabilities/ or index.ts)
//   node scripts/sync-capabilities.mjs --check   fail if any copy differs, is missing or is no longer used (CI)
//
// Never edit the copies. Change capabilities/ in the monorepo and sync.

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const LAB = join(dirname(fileURLToPath(import.meta.url)), '..')
const SOURCE = join(LAB, '..', '..', 'capabilities')
const TARGET = join(LAB, 'capabilities')
const INDEX = join(TARGET, 'index.ts')
const EXTRA = [
  'core/schema.sql',
  'core/pwa/shell/app.ts', 'core/pwa/shell/sw.ts', 'core/pwa/shell/index.html', 'core/pwa/shell/app.css',
  'core/pwa/shell/build.mjs', 'core/pwa/shell/icons.mjs', 'core/pwa/shell/tsconfig.json', 'core/pwa/shell/tsconfig.sw.json',
]
const check = process.argv.includes('--check')

// On its own (a copy of this folder, or its public repo) there's nothing to sync
// from, and the copies are the code.
if (!existsSync(join(SOURCE, 'core'))) {
  console.log('✓ capabilities: no source here, so the copies in capabilities/ are used as they are')
  process.exit(0)
}

const posix = p => p.split(sep).join('/')
const IMPORT = /(?:import|export)[^'"]*?from\s+'(\.[^']+)'/g

/** Relative imports of a file, resolved to paths under capabilities/. */
function importsOf(text, fromRel) {
  const out = []
  for (const m of text.matchAll(IMPORT)) {
    const base = posix(join(dirname(fromRel), m[1]))
    const hit = [`${base}.ts`, `${base}/index.ts`, base].find(c => c.endsWith('.ts') && existsSync(join(SOURCE, c)))
    if (!hit) throw new Error(`${fromRel} imports ${m[1]}, which isn't in capabilities/`)
    out.push(hit)
  }
  return out
}

const needed = new Set()
const walk = rel => {
  if (needed.has(rel)) return
  needed.add(rel)
  for (const next of importsOf(readFileSync(join(SOURCE, rel), 'utf8'), rel)) walk(next)
}
for (const rel of importsOf(readFileSync(INDEX, 'utf8'), 'index.ts')) walk(rel)
for (const rel of EXTRA) rel.endsWith('.ts') ? walk(rel) : needed.add(rel)

const problems = []
for (const rel of [...needed].sort()) {
  const want = readFileSync(join(SOURCE, rel))
  const at = join(TARGET, rel)
  const have = existsSync(at) ? readFileSync(at) : undefined
  if (have && have.equals(want)) continue
  if (check) { problems.push(`${have ? 'differs' : 'missing'}: capabilities/${rel}`); continue }
  mkdirSync(dirname(at), { recursive: true })
  writeFileSync(at, want)
  console.log(`copied capabilities/${rel}`)
}

// Copies the index no longer reaches.
const listed = dir => readdirSync(dir).flatMap(n => statSync(join(dir, n)).isDirectory() ? listed(join(dir, n)) : [join(dir, n)])
const core = join(TARGET, 'core')
for (const file of existsSync(core) ? listed(core) : []) {
  const rel = posix(relative(TARGET, file))
  if (needed.has(rel)) continue
  if (check) problems.push(`no longer used: capabilities/${rel}`)
  else { rmSync(file); console.log(`removed capabilities/${rel}`) }
}

if (problems.length) {
  console.error(`✗ capabilities copy is out of date (${problems.length}). Run: node labs/pwa-shell/scripts/sync-capabilities.mjs\n  ${problems.join('\n  ')}`)
  process.exit(1)
}
console.log(`✓ capabilities: ${needed.size} files ${check ? 'match' : 'in sync with'} capabilities/`)
