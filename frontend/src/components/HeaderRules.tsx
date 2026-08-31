import { useState } from 'react'
import { HeaderRule } from '../api'

interface Suggestion {
  name: string
  value?: string
  target?: HeaderRule['target']
  action?: HeaderRule['action']
  hint?: string
}

/**
 * Headers worth reaching for, grouped by what you are trying to do. Response
 * entries default to `remove`, which is nearly always the intent there.
 */
const CATALOGUE: { group: string; items: Suggestion[] }[] = [
  {
    group: 'Client IP (request)',
    items: [
      { name: 'X-Forwarded-For', value: '127.0.0.1', hint: 'The usual one' },
      { name: 'X-Real-IP', value: '127.0.0.1' },
      { name: 'X-Originating-IP', value: '127.0.0.1' },
      { name: 'X-Client-IP', value: '127.0.0.1' },
      { name: 'X-Remote-IP', value: '127.0.0.1' },
      { name: 'X-Remote-Addr', value: '127.0.0.1' },
      { name: 'True-Client-IP', value: '127.0.0.1', hint: 'Akamai' },
      { name: 'CF-Connecting-IP', value: '127.0.0.1', hint: 'Cloudflare' },
      { name: 'Forwarded', value: 'for=127.0.0.1;proto=https', hint: 'RFC 7239' },
    ],
  },
  {
    group: 'Routing and host (request)',
    items: [
      { name: 'X-Forwarded-Host', value: 'internal.local' },
      { name: 'X-Forwarded-Proto', value: 'https' },
      { name: 'X-Forwarded-Port', value: '443' },
      { name: 'X-Original-URL', value: '/admin' },
      { name: 'X-Rewrite-URL', value: '/admin' },
      { name: 'X-HTTP-Method-Override', value: 'PUT' },
    ],
  },
  {
    group: 'Identity and client (request)',
    items: [
      { name: 'User-Agent', value: 'Mozilla/5.0' },
      { name: 'Referer', value: 'https://example.com/' },
      { name: 'Origin', value: 'https://example.com' },
      { name: 'Authorization', value: 'Bearer ' },
      { name: 'Cookie', value: 'session=' },
      { name: 'X-Api-Key', value: '' },
      { name: 'X-Requested-With', value: 'XMLHttpRequest' },
      { name: 'Accept-Language', value: 'en-US,en;q=0.9' },
      { name: 'Cache-Control', value: 'no-cache' },
    ],
  },
  {
    group: 'Strip from responses',
    items: [
      { name: 'Content-Security-Policy', target: 'response', action: 'remove' },
      { name: 'Strict-Transport-Security', target: 'response', action: 'remove' },
      { name: 'X-Frame-Options', target: 'response', action: 'remove' },
      { name: 'X-Content-Type-Options', target: 'response', action: 'remove' },
      { name: 'Content-Security-Policy-Report-Only', target: 'response', action: 'remove' },
    ],
  },
  {
    group: 'Set on responses',
    items: [
      { name: 'Access-Control-Allow-Origin', value: '*', target: 'response' },
      { name: 'Access-Control-Allow-Credentials', value: 'true', target: 'response' },
      { name: 'Cache-Control', value: 'no-store', target: 'response' },
      { name: 'Set-Cookie', value: '', target: 'response', action: 'add' },
    ],
  },
]

const FLAT: Record<string, Suggestion> = {}
for (const { group, items } of CATALOGUE) {
  for (const item of items) FLAT[`${group}::${item.name}`] = item
}

export function HeaderRules({
  rules, onChange, disabled,
}: {
  rules: HeaderRule[]
  onChange: (rules: HeaderRule[]) => void
  disabled?: boolean
}) {
  const [picker, setPicker] = useState('')

  const add = (suggestion?: Suggestion) => {
    onChange([...rules, {
      enabled: true,
      target: suggestion?.target ?? 'request',
      action: suggestion?.action ?? 'set',
      name: suggestion?.name ?? '',
      value: suggestion?.value ?? '',
    }])
  }

  const update = (index: number, patch: Partial<HeaderRule>) =>
    onChange(rules.map((rule, i) => (i === index ? { ...rule, ...patch } : rule)))

  return (
    <>
      <div className="row">
        <select
          className="w-md"
          disabled={disabled}
          value={picker}
          onChange={(event) => {
            const key = event.target.value
            setPicker('')
            if (!key) return
            if (key === '__custom__') add()
            else add(FLAT[key])
          }}
        >
          <option value="">Add a header…</option>
          {CATALOGUE.map(({ group, items }) => (
            <optgroup label={group} key={group}>
              {items.map((item) => (
                <option value={`${group}::${item.name}`} key={`${group}::${item.name}`}>
                  {item.name}{item.hint ? ` — ${item.hint}` : ''}
                </option>
              ))}
            </optgroup>
          ))}
          <optgroup label="Other">
            <option value="__custom__">Custom header…</option>
          </optgroup>
        </select>
        <span className="dim">
          {rules.length === 0
            ? 'no rules'
            : `${rules.length} rule${rules.length === 1 ? '' : 's'}`}
        </span>
      </div>

      {rules.length > 0 && (
        <div className="header-rules">
          {rules.map((rule, index) => (
            <div className="header-rule" key={index}>
              <label className="toggle" title="Enable this rule">
                <input
                  type="checkbox"
                  disabled={disabled}
                  checked={rule.enabled}
                  onChange={(e) => update(index, { enabled: e.target.checked })}
                />
              </label>
              <select
                disabled={disabled}
                value={rule.target}
                title="Which direction to rewrite"
                onChange={(e) => update(index, {
                  target: e.target.value as HeaderRule['target'],
                })}
              >
                <option value="request">Request</option>
                <option value="response">Response</option>
              </select>
              <select
                disabled={disabled}
                value={rule.action}
                onChange={(e) => update(index, {
                  action: e.target.value as HeaderRule['action'],
                })}
                title={'Set: replace it, or add it when absent\n'
                  + 'Add: append another instance\n'
                  + 'Remove: delete every instance'}
              >
                <option value="set">Set</option>
                <option value="add">Add</option>
                <option value="remove">Remove</option>
              </select>
              <input
                type="text"
                className="mono hr-name"
                disabled={disabled}
                placeholder="Header-Name"
                value={rule.name}
                onChange={(e) => update(index, { name: e.target.value })}
              />
              <input
                type="text"
                className="mono hr-value"
                disabled={disabled || rule.action === 'remove'}
                placeholder={rule.action === 'remove' ? '(no value needed)' : 'value'}
                value={rule.action === 'remove' ? '' : rule.value}
                onChange={(e) => update(index, { value: e.target.value })}
              />
              <button
                className="sm ghost"
                disabled={disabled}
                title="Delete this rule"
                onClick={() => onChange(rules.filter((_, i) => i !== index))}
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}
    </>
  )
}
