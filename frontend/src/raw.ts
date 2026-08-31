/**
 * Raw HTTP bytes <-> editable text.
 *
 * Editor text is treated as latin-1: one character per byte, so every byte
 * round-trips exactly. That matters for a security tool - we must never
 * silently rewrite what the operator typed.
 */

export function b64ToRaw(b64: string | null | undefined): string {
  if (!b64) return ''
  try {
    return atob(b64)
  } catch {
    return ''
  }
}

/** Convert editor text back to bytes, UTF-8 encoding only what cannot be a byte. */
export function rawToBytes(raw: string): Uint8Array {
  const out: number[] = []
  const encoder = new TextEncoder()
  for (const ch of raw) {
    const code = ch.codePointAt(0)!
    if (code <= 0xff) {
      out.push(code)
    } else {
      // A typed character outside latin-1 becomes its UTF-8 bytes; existing
      // real bytes in 0x00-0xff are left exactly as they are.
      out.push(...encoder.encode(ch))
    }
  }
  return new Uint8Array(out)
}

export function rawToB64(raw: string): string {
  const bytes = rawToBytes(raw)
  let binary = ''
  const CHUNK = 0x8000
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK))
  }
  return btoa(binary)
}

export function byteLength(raw: string): number {
  return rawToBytes(raw).length
}

/** Split a raw message into its head and body halves. */
export function splitMessage(raw: string): { head: string; body: string } {
  let idx = raw.indexOf('\r\n\r\n')
  let len = 4
  if (idx === -1) {
    idx = raw.indexOf('\n\n')
    len = 2
  }
  if (idx === -1) return { head: raw, body: '' }
  return { head: raw.slice(0, idx), body: raw.slice(idx + len) }
}

/** Replace a raw message's body, keeping the head untouched. */
export function replaceBody(raw: string, body: string): string {
  const idx = raw.indexOf('\r\n\r\n')
  if (idx === -1) return raw + '\r\n\r\n' + body
  return raw.slice(0, idx + 4) + body
}

export function firstLine(raw: string): string {
  const nl = raw.indexOf('\n')
  return (nl === -1 ? raw : raw.slice(0, nl)).replace(/\r$/, '')
}

/** Pretty-print JSON / indent XML-ish bodies for the "Pretty" view. */
export function prettifyBody(body: string, contentType: string): string {
  const type = contentType.toLowerCase()
  const trimmed = body.trim()
  if (!trimmed) return body
  if (type.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2)
    } catch {
      return body
    }
  }
  if (type.includes('xml') || type.includes('html')) {
    // Cheap structural indent: one tag per line, nested by depth.
    const tokens = trimmed.replace(/>\s*</g, '><').split(/(<[^>]+>)/).filter((t) => t.trim())
    let depth = 0
    const lines: string[] = []
    for (const token of tokens) {
      if (/^<\//.test(token)) depth = Math.max(0, depth - 1)
      lines.push('  '.repeat(depth) + token.trim())
      if (/^<[^/!?]/.test(token) && !/\/>$/.test(token) && !/^<(br|img|meta|link|input|hr)\b/i.test(token)) {
        depth += 1
      }
    }
    return lines.join('\n')
  }
  return body
}

/** Hex + ASCII dump, for inspecting bytes that are not printable text. */
export function hexDump(raw: string): string {
  const bytes = rawToBytes(raw)
  const lines: string[] = []
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const slice = bytes.subarray(offset, offset + 16)
    const hex: string[] = []
    let ascii = ''
    for (let i = 0; i < 16; i++) {
      hex.push(i < slice.length ? slice[i].toString(16).padStart(2, '0') : '  ')
      if (i < slice.length) {
        ascii += slice[i] >= 0x20 && slice[i] < 0x7f ? String.fromCharCode(slice[i]) : '.'
      }
    }
    const gapped = hex.slice(0, 8).join(' ') + '  ' + hex.slice(8).join(' ')
    lines.push(`${offset.toString(16).padStart(8, '0')}  ${gapped}  |${ascii}|`)
  }
  return lines.join('\n') || '(empty)'
}

export function extractContentType(raw: string): string {
  const { head } = splitMessage(raw)
  for (const line of head.split('\n')) {
    const [name, ...rest] = line.split(':')
    if (name.trim().toLowerCase() === 'content-type') return rest.join(':').trim()
  }
  return ''
}

export const MARKER = '§'
