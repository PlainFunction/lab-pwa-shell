// Draws the app's icons as PNGs with nothing but node:zlib: the client's
// colour with a white tick. A client with a logo swaps these for their own
// (same file names and sizes); these make sure an app always installs.

import { deflateSync } from 'node:zlib'

const CRC = new Uint32Array(256).map((_, n) => {
  let c = n
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
  return c >>> 0
})
const crc32 = buf => {
  let c = 0xffffffff
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function chunk(type, data) {
  const out = Buffer.alloc(12 + data.length)
  out.writeUInt32BE(data.length, 0)
  out.write(type, 4, 'ascii')
  data.copy(out, 8)
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length)
  return out
}

function png(size, pixel) {
  const raw = Buffer.alloc(size * (size * 4 + 1))
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = pixel(x + 0.5, y + 0.5)
      raw.set([r, g, b, a], y * (size * 4 + 1) + 1 + x * 4)
    }
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(size, 0)
  ihdr.writeUInt32BE(size, 4)
  ihdr.set([8, 6, 0, 0, 0], 8)
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))])
}

const hexRgb = hex => {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex)
  if (!m) throw new Error(`Not a colour: ${hex}`)
  const n = parseInt(m[1], 16)
  return [n >> 16, (n >> 8) & 255, n & 255]
}

const clamp = v => Math.max(0, Math.min(1, v))
const segment = (px, py, [ax, ay], [bx, by]) => {
  const t = clamp(((px - ax) * (bx - ax) + (py - ay) * (by - ay)) / ((bx - ax) ** 2 + (by - ay) ** 2))
  return Math.hypot(px - (ax + t * (bx - ax)), py - (ay + t * (by - ay)))
}
const TICK = [[0.30, 0.52], [0.44, 0.66], [0.71, 0.37]]

/**
 * `full`: square to the edge (maskable icons and Apple's, which the system rounds itself).
 * `scale` shrinks the tick, so it stays inside a maskable icon's safe zone.
 */
function icon(size, colour, { full = false, scale = 1 } = {}) {
  const [r, g, b] = hexRgb(colour)
  const radius = full ? 0 : 0.22
  return png(size, (x, y) => {
    const u = x / size
    const v = y / size
    // Rounded square: distance outside the corner circles, with a pixel of edge softening.
    const dx = Math.max(Math.abs(u - 0.5) - (0.5 - radius), 0)
    const dy = Math.max(Math.abs(v - 0.5) - (0.5 - radius), 0)
    const bg = full ? 1 : clamp((radius - Math.hypot(dx, dy)) * size + 0.5)
    const tu = (u - 0.5) / scale + 0.5
    const tv = (v - 0.5) / scale + 0.5
    const d = Math.min(segment(tu, tv, TICK[0], TICK[1]), segment(tu, tv, TICK[1], TICK[2]))
    const tick = clamp((0.045 - d) * size * scale + 0.5)
    const mix = c => Math.round(c * (1 - tick) + 255 * tick)
    return [mix(r), mix(g), mix(b), Math.round(255 * Math.max(bg, tick * bg))]
  })
}

/**
 * Android's status-bar badge: only the alpha channel is used, so it's a white
 * tick on nothing. A coloured square here shows up as a plain white blob.
 */
function badge(size) {
  return png(size, (x, y) => {
    const u = x / size
    const v = y / size
    const d = Math.min(segment(u, v, TICK[0], TICK[1]), segment(u, v, TICK[1], TICK[2]))
    return [255, 255, 255, Math.round(255 * clamp((0.07 - d) * size + 0.5))]
  })
}

/** Every icon the manifest, iOS and notifications ask for, by file name. */
export function icons(colour) {
  return {
    'badge-96.png': badge(96),
    'icon-192.png': icon(192, colour),
    'icon-512.png': icon(512, colour),
    'icon-maskable-512.png': icon(512, colour, { full: true, scale: 0.8 }),
    'apple-touch-icon.png': icon(180, colour, { full: true }),
  }
}
