import { useRef } from 'react'
import { api, PayloadRule, PayloadSet, Wordlist } from '../api'

const RULE_KINDS: PayloadRule['kind'][] = [
  'prefix', 'suffix', 'upper', 'lower', 'reverse', 'strip',
  'url_encode', 'url_encode_all', 'base64', 'hex', 'md5', 'sha1', 'sha256',
]

const RULES_WITH_VALUE = new Set<PayloadRule['kind']>(['prefix', 'suffix'])

/** Rough count so the operator can see the size before starting. */
export function payloadSetSize(set: PayloadSet): number {
  if (set.kind === 'numbers') {
    const step = Math.abs(set.number_step) || 1
    return Math.max(0, Math.floor(Math.abs(set.number_to - set.number_from) / step) + 1)
  }
  if (set.kind === 'brute') {
    const base = Math.max(1, new Set(set.charset).size)
    let total = 0
    for (let len = Math.max(1, set.min_length); len <= Math.max(set.min_length, set.max_length); len++) {
      total += base ** len
    }
    return total
  }
  if (set.wordlist) return -1 // resolved server-side
  return set.payloads.filter((p) => p !== '').length
}

interface Props {
  index: number
  set: PayloadSet
  wordlists: Wordlist[]
  onChange: (patch: Partial<PayloadSet>) => void
  onWordlistsChanged: () => void
  showToast: (text: string, kind?: 'ok' | 'error') => void
  required: boolean
}

export function PayloadSetEditor({
  index, set, wordlists, onChange, onWordlistsChanged, showToast, required,
}: Props) {
  const fileInput = useRef<HTMLInputElement>(null)
  const size = payloadSetSize(set)

  const importFile = async (file: File) => {
    const text = await file.text()
    const name = file.name
    try {
      const saved = await api.saveWordlist(name, text)
      onWordlistsChanged()
      onChange({ wordlist: name, payloads: [] })
      showToast(`Loaded ${name} — ${saved.lines.toLocaleString()} payloads`)
    } catch (error) {
      showToast(`Could not save wordlist: ${String(error)}`, 'error')
    }
  }

  const saveTyped = async () => {
    const name = window.prompt('Save these payloads as a reusable wordlist named:')
    if (!name) return
    try {
      await api.saveWordlist(name, set.payloads.join('\n'))
      onWordlistsChanged()
      showToast(`Saved wordlist "${name}"`)
    } catch (error) {
      showToast(`Could not save: ${String(error)}`, 'error')
    }
  }

  const updateRule = (ruleIndex: number, patch: Partial<PayloadRule>) => {
    onChange({
      rules: set.rules.map((rule, i) => (i === ruleIndex ? { ...rule, ...patch } : rule)),
    })
  }

  return (
    <div className="card">
      <h3>
        Payload set {index + 1}
        {!required && <span className="dim" style={{ fontWeight: 400 }}> — unused for this attack type</span>}
        <span className="spacer" />
        <span className="dim" style={{ fontWeight: 400, marginLeft: 10 }}>
          {size < 0 ? 'from wordlist' : `${size.toLocaleString()} payloads`}
        </span>
      </h3>
      <div className="card-body">
        <div className="row">
          <label className="field">
            Type
            <select
              value={set.kind}
              onChange={(event) => onChange({ kind: event.target.value as PayloadSet['kind'] })}
            >
              <option value="list">Simple list / wordlist</option>
              <option value="numbers">Numbers</option>
              <option value="brute">Brute forcer (character set)</option>
            </select>
          </label>
        </div>

        {set.kind === 'list' && (
          <>
            <div className="row">
              <label className="field">
                Wordlist
                <select
                  className="w-md"
                  value={set.wordlist}
                  onChange={(event) => onChange({ wordlist: event.target.value })}
                >
                  <option value="">— type payloads below —</option>
                  {wordlists.map((list) => (
                    <option key={list.name} value={list.name}>
                      {list.name} ({list.lines.toLocaleString()})
                    </option>
                  ))}
                </select>
              </label>
              <button className="sm" onClick={() => fileInput.current?.click()}>
                Load from file…
              </button>
              <input
                ref={fileInput}
                type="file"
                accept=".txt,.lst,.dic,text/plain"
                style={{ display: 'none' }}
                onChange={(event) => {
                  const file = event.target.files?.[0]
                  if (file) void importFile(file)
                  event.target.value = ''
                }}
              />
              {set.wordlist && (
                <button
                  className="sm danger"
                  onClick={async () => {
                    if (!window.confirm(`Delete wordlist "${set.wordlist}"?`)) return
                    await api.deleteWordlist(set.wordlist)
                    onChange({ wordlist: '' })
                    onWordlistsChanged()
                  }}
                >
                  Delete wordlist
                </button>
              )}
            </div>

            {!set.wordlist && (
              <>
                <textarea
                  className="mono"
                  rows={8}
                  spellCheck={false}
                  placeholder={'admin\nroot\npassword\n123456'}
                  value={set.payloads.join('\n')}
                  onChange={(event) => onChange({ payloads: event.target.value.split('\n') })}
                />
                <div className="row">
                  <button className="sm" onClick={() => void saveTyped()}>Save as wordlist…</button>
                  <p className="hint">One payload per line. Blank lines are ignored.</p>
                </div>
              </>
            )}
          </>
        )}

        {set.kind === 'numbers' && (
          <div className="row">
            <label className="field">
              From
              <input
                type="number" className="w-sm" value={set.number_from}
                onChange={(event) => onChange({ number_from: Number(event.target.value) })}
              />
            </label>
            <label className="field">
              To
              <input
                type="number" className="w-sm" value={set.number_to}
                onChange={(event) => onChange({ number_to: Number(event.target.value) })}
              />
            </label>
            <label className="field">
              Step
              <input
                type="number" className="w-xs" value={set.number_step}
                onChange={(event) => onChange({ number_step: Number(event.target.value) || 1 })}
              />
            </label>
          </div>
        )}

        {set.kind === 'brute' && (
          <>
            <div className="row">
              <label className="field grow">
                Characters
                <input
                  type="text" className="mono grow" value={set.charset}
                  onChange={(event) => onChange({ charset: event.target.value })}
                />
              </label>
              <label className="field">
                Min len
                <input
                  type="number" className="w-xs" min={1} value={set.min_length}
                  onChange={(event) => onChange({ min_length: Number(event.target.value) || 1 })}
                />
              </label>
              <label className="field">
                Max len
                <input
                  type="number" className="w-xs" min={1} value={set.max_length}
                  onChange={(event) => onChange({ max_length: Number(event.target.value) || 1 })}
                />
              </label>
            </div>
            <p className="hint">
              Every combination is generated, so length grows the count exponentially:
              {' '}{new Set(set.charset).size} characters at length {set.max_length} alone is{' '}
              {(new Set(set.charset).size ** Math.max(1, set.max_length)).toLocaleString()} payloads.
            </p>
          </>
        )}

        <div>
          <div className="row" style={{ marginBottom: 6 }}>
            <b style={{ fontSize: 12 }}>Payload processing</b>
            <button
              className="sm"
              onClick={() => onChange({
                rules: [...set.rules, { kind: 'prefix', value: '', enabled: true }],
              })}
            >
              + Add rule
            </button>
          </div>
          <div className="rules">
            {set.rules.map((rule, ruleIndex) => (
              <div className="rule" key={ruleIndex}>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={rule.enabled}
                    onChange={(event) => updateRule(ruleIndex, { enabled: event.target.checked })}
                  />
                </label>
                <select
                  value={rule.kind}
                  onChange={(event) => updateRule(ruleIndex, {
                    kind: event.target.value as PayloadRule['kind'],
                  })}
                >
                  {RULE_KINDS.map((kind) => (
                    <option key={kind} value={kind}>{kind.replace(/_/g, ' ')}</option>
                  ))}
                </select>
                {RULES_WITH_VALUE.has(rule.kind) ? (
                  <input
                    type="text"
                    placeholder="text to add"
                    value={rule.value}
                    onChange={(event) => updateRule(ruleIndex, { value: event.target.value })}
                  />
                ) : (
                  <span className="grow" />
                )}
                <button
                  className="sm ghost"
                  onClick={() => onChange({ rules: set.rules.filter((_, i) => i !== ruleIndex) })}
                >
                  ×
                </button>
              </div>
            ))}
            {set.rules.length === 0 && (
              <p className="hint">
                Rules run in order on every payload — for example <code>prefix</code> then{' '}
                <code>base64</code>. URL-encoding of unsafe characters happens separately,
                in Options.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
