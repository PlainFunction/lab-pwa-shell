import { ValidationError } from '../../kernel/errors'
import { concat, utf8 } from '../../kernel/encoding'

// Just enough CBOR (RFC 8949) for WebAuthn: the attestation object and COSE
// keys. Authenticators use CTAP2's canonical form, so lengths are always
// definite and there are no floats; anything else is refused rather than guessed.

export type Cbor = number | string | boolean | null | undefined | Uint8Array | Cbor[] | Map<Cbor, Cbor>

const MAX_DEPTH = 8
const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false })

/** Decodes one value starting at `offset`, and says where it ended. COSE keys sit in the middle of authData, so the end matters. */
export function decodeCborAt(bytes: Uint8Array, offset = 0): { value: Cbor; end: number } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let pos = offset

  const need = (n: number) => {
    if (n > bytes.length - pos) throw new ValidationError('CBOR ended early')
  }

  const read = (depth: number): Cbor => {
    if (depth > MAX_DEPTH) throw new ValidationError('CBOR nested too deeply')
    need(1)
    const initial = bytes[pos++]
    const major = initial >> 5
    const info = initial & 31

    if (major === 7) {
      if (info === 20) return false
      if (info === 21) return true
      if (info === 22) return null
      if (info === 23) return undefined
      throw new ValidationError('CBOR value not supported')
    }

    let n: number
    if (info < 24) n = info
    else if (info === 24) { need(1); n = bytes[pos]; pos += 1 }
    else if (info === 25) { need(2); n = view.getUint16(pos); pos += 2 }
    else if (info === 26) { need(4); n = view.getUint32(pos); pos += 4 }
    else if (info === 27) {
      need(8)
      const big = view.getBigUint64(pos)
      pos += 8
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new ValidationError('CBOR number too big')
      n = Number(big)
    } else throw new ValidationError('CBOR indefinite lengths not supported')

    switch (major) {
      case 0: return n
      case 1: return -1 - n
      case 2: { need(n); const out = bytes.slice(pos, pos + n); pos += n; return out }
      case 3: { need(n); const out = text.decode(bytes.subarray(pos, pos + n)); pos += n; return out }
      case 4: {
        // Every item is at least a byte, so a claimed length past the end is a lie.
        need(n)
        const out: Cbor[] = []
        for (let i = 0; i < n; i++) out.push(read(depth + 1))
        return out
      }
      case 5: {
        need(n * 2)
        const out = new Map<Cbor, Cbor>()
        for (let i = 0; i < n; i++) {
          const key = read(depth + 1)
          if (out.has(key)) throw new ValidationError('CBOR map has a key twice')
          out.set(key, read(depth + 1))
        }
        return out
      }
      // A tag: the value it wraps is what we want.
      case 6: return read(depth + 1)
      default: throw new ValidationError('CBOR value not supported')
    }
  }

  return { value: read(0), end: pos }
}

/** Decodes a whole buffer. Bytes left over mean it isn't what it claims to be. */
export function decodeCbor(bytes: Uint8Array): Cbor {
  const { value, end } = decodeCborAt(bytes)
  if (end !== bytes.length) throw new ValidationError('CBOR has bytes left over')
  return value
}

function head(major: number, n: number): Uint8Array {
  if (n < 24) return new Uint8Array([(major << 5) | n])
  if (n < 0x100) return new Uint8Array([(major << 5) | 24, n])
  if (n < 0x10000) return new Uint8Array([(major << 5) | 25, n >> 8, n & 0xff])
  const out = new Uint8Array(5)
  out[0] = (major << 5) | 26
  new DataView(out.buffer).setUint32(1, n)
  return out
}

/** The other direction, for software passkeys in tests and anything that builds COSE keys. */
export function encodeCbor(value: Cbor): Uint8Array<ArrayBuffer> {
  if (value === false) return new Uint8Array([0xf4])
  if (value === true) return new Uint8Array([0xf5])
  if (value === null) return new Uint8Array([0xf6])
  if (value === undefined) return new Uint8Array([0xf7])
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || Math.abs(value) > 0xffffffff) throw new ValidationError('Only small integers encode')
    return concat(value >= 0 ? head(0, value) : head(1, -1 - value))
  }
  if (typeof value === 'string') { const b = utf8(value); return concat(head(3, b.length), b) }
  if (value instanceof Uint8Array) return concat(head(2, value.length), value)
  if (Array.isArray(value)) return concat(head(4, value.length), ...value.map(encodeCbor))
  const parts: Uint8Array[] = [head(5, value.size)]
  for (const [k, v] of value) parts.push(encodeCbor(k), encodeCbor(v))
  return concat(...parts)
}
