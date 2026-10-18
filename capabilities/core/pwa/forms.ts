// Tool schemas to web forms and back. The same tool contract the Slack agent
// draws as Block Kit (ui.* and out.* hints under `x-slack`) is drawn here as
// plain HTML inputs, so one tool definition works in both places.
//
// No DOM and no imports: the shell bundles this for the browser, and the
// Worker uses it to refuse tools the app can't draw before anyone sees them.

export interface Hint { element: string; label: string; multiline?: boolean }
export interface Prop { type?: string; enum?: unknown[]; description?: string; minimum?: number; maximum?: number; maxLength?: number; 'x-slack'?: Hint }
export interface Schema { properties?: Record<string, Prop>; required?: string[] }

/** `image` is a photo: the shell uploads it and the value is the upload's id. */
export type FieldKind = 'text' | 'textarea' | 'number' | 'email' | 'url' | 'date' | 'time' | 'select' | 'checkbox' | 'image'

export interface Field {
  name: string
  label: string
  kind: FieldKind
  required: boolean
  description?: string
  options?: string[]
  maxLength?: number
}

const INPUTS: Record<string, FieldKind> = {
  plain_text_input: 'text', number_input: 'number', email_text_input: 'email', url_text_input: 'url',
  datepicker: 'date', timepicker: 'time', static_select: 'select', checkboxes: 'checkbox', image_select: 'image',
}

/** Slack-only inputs: a Slack user, a channel. They mean nothing in the app. */
export const SLACK_ONLY = ['users_select', 'conversations_select']

export class UnsupportedField extends Error {}

/** The form for a tool's input schema. Throws UnsupportedField for anything the app can't draw. */
export function fieldsOf(schema: Schema): Field[] {
  const required = new Set(schema.required ?? [])
  return Object.entries(schema.properties ?? {}).map(([name, prop]) => {
    const hint = prop['x-slack']
    if (!hint) throw new UnsupportedField(`${name} has no hint`)
    const base = INPUTS[hint.element]
    if (!base) throw new UnsupportedField(`${name} is a ${hint.element}, which only works in Slack`)
    const kind: FieldKind = base === 'text' && hint.multiline ? 'textarea' : base
    return {
      name, label: hint.label, kind, required: required.has(name) && kind !== 'checkbox',
      ...(prop.description ? { description: prop.description } : {}),
      ...(kind === 'select' ? { options: (prop.enum ?? []).map(String) } : {}),
      ...(prop.maxLength ? { maxLength: prop.maxLength } : {}),
    }
  })
}

/** What someone typed, as the schema wants it. Empty is left out, so optional fields stay optional. */
export function readField(field: Field, raw: string | boolean): unknown {
  if (field.kind === 'checkbox') return raw === true || raw === 'on' || raw === 'true'
  const text = String(raw).trim()
  if (text === '') return undefined
  if (field.kind === 'number') return Number(text)
  // A time input gives HH:MM; the contract wants HH:MM or HH:MM:SS, which this is.
  return text
}

export function readForm(fields: Field[], raw: Record<string, string | boolean>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const f of fields) {
    const v = readField(f, raw[f.name] ?? '')
    if (v !== undefined) out[f.name] = v
  }
  return out
}

/** Required fields still empty, by label. */
export const missing = (fields: Field[], args: Record<string, unknown>) =>
  fields.filter(f => f.required && (args[f.name] === undefined || args[f.name] === '')).map(f => f.label)

export type ShownKind = 'header' | 'field' | 'text' | 'context' | 'image' | 'link' | 'list'
/** A row of an `out.list`. Same shape as the contract's ListItem; repeated so this file imports nothing. */
export interface ShownItem { title: string; detail?: string; meta?: string }
export interface Shown { kind: ShownKind; label: string; value: string; items?: ShownItem[] }

const OUTPUTS = new Set<string>(['header', 'field', 'text', 'context', 'image', 'link', 'list'])

const str = (v: unknown) => typeof v === 'string' && v ? v : undefined
const itemsOf = (v: unknown): ShownItem[] => (Array.isArray(v) ? v : [])
  .filter((i): i is Record<string, unknown> => !!i && typeof i === 'object' && typeof (i as { title?: unknown }).title === 'string')
  .map(i => ({ title: String(i.title), detail: str(i.detail), meta: str(i.meta) }))

/** A tool's result, in the order its output schema lists it. Unknown or empty fields are skipped. */
export function shownOf(schema: Schema | undefined, content: Record<string, unknown>): Shown[] {
  const out: Shown[] = []
  for (const [name, prop] of Object.entries(schema?.properties ?? {})) {
    const hint = prop['x-slack']
    const value = content[name]
    if (!hint || !OUTPUTS.has(hint.element) || value === undefined || value === null || value === '') continue
    if (hint.element === 'list') {
      const items = itemsOf(value)
      out.push({ kind: 'list', label: hint.label, value: String(items.length), items })
      continue
    }
    out.push({ kind: hint.element as ShownKind, label: hint.label, value: String(value) })
  }
  return out
}

/** What's about to happen, as label and value, for the screen that asks for a passkey. `photos` names uploads by id. */
export function summaryOf(fields: Field[], args: Record<string, unknown>, photos: Record<string, string> = {}): { label: string; value: string }[] {
  const value = (f: Field, v: unknown) => f.kind === 'checkbox' ? (v ? 'Yes' : 'No') : f.kind === 'image' ? photos[String(v)] ?? 'A photo' : String(v)
  return fields.filter(f => args[f.name] !== undefined).map(f => ({ label: f.label, value: value(f, args[f.name]) }))
}
