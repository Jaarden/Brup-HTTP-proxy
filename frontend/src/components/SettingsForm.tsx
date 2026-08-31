import { createContext, useContext, useEffect, useState } from 'react'
import { api, ApiError, ScopeRule, Settings } from '../api'
import { useApp } from '../store'
import { HeaderRules } from './HeaderRules'
import { VpnCard } from './VpnCard'

type Mode = 'system' | 'project'
type Key = keyof Settings
type Draft = Record<string, unknown>

/** Editable list of regex scope rules. */
function RuleList({
  rules, onChange, placeholder, disabled,
}: {
  rules: ScopeRule[]
  onChange: (rules: ScopeRule[]) => void
  placeholder: string
  disabled?: boolean
}) {
  return (
    <div className="rules">
      {rules.map((rule, index) => (
        <div className="rule" key={index}>
          <label className="toggle">
            <input
              type="checkbox"
              disabled={disabled}
              checked={rule.enabled}
              onChange={(e) => onChange(rules.map((r, i) =>
                i === index ? { ...r, enabled: e.target.checked } : r))}
            />
          </label>
          <input
            type="text"
            disabled={disabled}
            placeholder={placeholder}
            value={rule.pattern}
            onChange={(e) => onChange(rules.map((r, i) =>
              i === index ? { ...r, pattern: e.target.value } : r))}
          />
          <button
            className="sm ghost"
            disabled={disabled}
            onClick={() => onChange(rules.filter((_, i) => i !== index))}
          >
            ×
          </button>
        </div>
      ))}
      <div>
        <button
          className="sm"
          disabled={disabled}
          onClick={() => onChange([...rules, { enabled: true, pattern: '' }])}
        >
          + Add rule
        </button>
      </div>
    </div>
  )
}

/** Editable list of short strings (extensions, hostnames). */
function ChipList({
  values, onChange, placeholder, disabled,
}: {
  values: string[]
  onChange: (values: string[]) => void
  placeholder: string
  disabled?: boolean
}) {
  const [text, setText] = useState('')
  const add = () => {
    const parts = text.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean)
    if (parts.length) onChange([...new Set([...values, ...parts])])
    setText('')
  }
  return (
    <>
      <div className="chips">
        {values.map((value) => (
          <span className="chip" key={value}>
            {value}
            <button
              disabled={disabled}
              onClick={() => onChange(values.filter((v) => v !== value))}
            >
              ×
            </button>
          </span>
        ))}
        {values.length === 0 && <span className="hint">none</span>}
      </div>
      <div className="row">
        <input
          type="text"
          className="w-md mono"
          disabled={disabled}
          placeholder={placeholder}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              add()
            }
          }}
        />
        <button className="sm" disabled={disabled} onClick={add}>Add</button>
      </div>
    </>
  )
}

function describe(value: unknown): string {
  if (Array.isArray(value)) {
    if (value.length === 0) return 'none'
    if (typeof value[0] === 'object') {
      return `${value.length} rule${value.length === 1 ? '' : 's'}`
    }
    return value.join(', ')
  }
  if (typeof value === 'boolean') return value ? 'on' : 'off'
  if (value === '') return 'empty'
  return String(value)
}

/**
 * Shared state for the field components below.
 *
 * These MUST live at module level. Defining them inside SettingsForm gives them
 * a new identity on every render, which makes React unmount and remount the
 * subtree instead of updating it - and a remounted <input> loses focus, so
 * typing dropped out after every keystroke.
 */
interface FieldCtx {
  mode: Mode
  system: Settings
  isOverridden: (k: Key) => boolean
  valueOf: <K extends Key>(k: K) => Settings[K]
  setValue: (k: Key, value: unknown) => void
  toggleOverride: (k: Key, on: boolean) => void
  editable: (k: Key) => boolean
}

const FieldContext = createContext<FieldCtx | null>(null)

function useField(): FieldCtx {
  const ctx = useContext(FieldContext)
  if (!ctx) throw new Error('field components must be inside a FieldContext')
  return ctx
}

/**
 * A boolean setting. In project mode this is a single tri-state control -
 * inherit, on, off - rather than an override checkbox plus a value checkbox,
 * which reads as two unrelated switches.
 */
function BoolRow({ k, label, hint }: {
  k: Key
  label: string
  hint?: React.ReactNode
}) {
  const { mode, system, isOverridden, valueOf, setValue } = useField()
  const inherited = mode === 'project' && !isOverridden(k)
  const current = inherited ? 'inherit' : (valueOf(k) ? 'on' : 'off')

  return (
    <div className={`setting${inherited ? ' inherited' : ''}`}>
      <div className="setting-head">
        <b>{label}</b>
        <select
          className="state"
          value={current}
          onChange={(event) => {
            if (event.target.value === 'inherit') setValue(k, null)
            else setValue(k, event.target.value === 'on')
          }}
        >
          {mode === 'project' && (
            <option value="inherit">Inherit ({system[k] ? 'on' : 'off'})</option>
          )}
          <option value="on">On</option>
          <option value="off">Off</option>
        </select>
        {mode === 'project' && !inherited && <span className="tag edited">overridden</span>}
      </div>
      {hint && <p className="hint">{hint}</p>}
    </div>
  )
}

/** A non-boolean setting: an override switch plus its control. */
function Row({ k, label, children, hint }: {
  k: Key
  label: string
  children: React.ReactNode
  hint?: React.ReactNode
}) {
  const { mode, system, isOverridden, toggleOverride } = useField()
  const inherited = mode === 'project' && !isOverridden(k)
  return (
    <div className={`setting${inherited ? ' inherited' : ''}`}>
      <div className="setting-head">
        {mode === 'project' && (
          <label className="toggle" title="Override the system setting for this project">
            <input
              type="checkbox"
              checked={!inherited}
              onChange={(event) => toggleOverride(k, event.target.checked)}
            />
          </label>
        )}
        <b>{label}</b>
        {mode === 'project' && (
          inherited
            ? <span className="dim" style={{ fontSize: 11.5 }}>
                inherits <code>{describe(system[k])}</code>
              </span>
            : <span className="tag edited">overridden</span>
        )}
      </div>
      <div className="setting-body">{children}</div>
      {hint && <p className="hint">{hint}</p>}
    </div>
  )
}

function NumField({ k, width = 'w-sm' }: { k: Key; width?: string }) {
  const { valueOf, setValue, editable } = useField()
  const committed = Number(valueOf(k))
  // Held as text so the field can be briefly empty while being retyped
  // instead of snapping to 0 on the first backspace.
  const [text, setText] = useState(String(committed))
  useEffect(() => setText(String(committed)), [committed])

  return (
    <input
      type="number"
      className={width}
      disabled={!editable(k)}
      value={text}
      onChange={(event) => {
        setText(event.target.value)
        if (event.target.value !== '') setValue(k, Number(event.target.value))
      }}
      onBlur={() => setText(String(committed))}
    />
  )
}

function TextField({ k, placeholder, width = 'w-lg' }: {
  k: Key
  placeholder?: string
  width?: string
}) {
  const { valueOf, setValue, editable } = useField()
  return (
    <input
      type="text"
      className={`${width} mono`}
      disabled={!editable(k)}
      placeholder={placeholder}
      value={String(valueOf(k) ?? '')}
      onChange={(event) => setValue(k, event.target.value)}
    />
  )
}


export function SettingsForm({ mode }: { mode: Mode }) {
  const {
    settingsInfo, status, showToast, saveSystemSettings, saveProjectSettings,
    refreshStatus, activeProject, renameProject,
  } = useApp()
  const [draft, setDraft] = useState<Draft>({})
  const [saving, setSaving] = useState(false)

  // A project switch or an external settings change makes the draft stale.
  useEffect(() => setDraft({}), [settingsInfo?.project_id, mode])

  if (!settingsInfo) return <div className="empty"><p>Loading settings…</p></div>
  const { system, overrides } = settingsInfo

  const isOverridden = (key: Key): boolean => {
    if (key in draft) return draft[key] !== null
    return Object.prototype.hasOwnProperty.call(overrides, key)
  }

  /** The value the control should show. */
  function valueOf<K extends Key>(key: K): Settings[K] {
    if (key in draft && draft[key] !== null) return draft[key] as Settings[K]
    if (mode === 'system') return system[key]
    if (isOverridden(key)) return (overrides as Settings)[key]
    return system[key]
  }

  const setValue = (key: Key, value: unknown) =>
    setDraft((prev) => ({ ...prev, [key]: value }))

  const toggleOverride = (key: Key, on: boolean) =>
    setDraft((prev) => ({ ...prev, [key]: on ? valueOf(key) : null }))

  const editable = (key: Key) => mode === 'system' || isOverridden(key)
  const dirty = Object.keys(draft).length > 0
  const overrideCount = Object.keys({ ...overrides, ...draft })
    .filter((k) => isOverridden(k as Key)).length

  const save = async () => {
    setSaving(true)
    try {
      if (mode === 'system') await saveSystemSettings(draft as Partial<Settings>)
      else await saveProjectSettings(draft)
      setDraft({})
      showToast(mode === 'system' ? 'System settings saved' : 'Project settings saved')
      await refreshStatus()
    } catch (error) {
      showToast(error instanceof ApiError ? error.message : String(error), 'error')
    } finally {
      setSaving(false)
    }
  }

  const restartListener = async () => {
    try {
      await api.proxyControl('restart')
      await refreshStatus()
      showToast('Listener restarted')
    } catch (error) {
      showToast(error instanceof ApiError ? error.message : String(error), 'error')
    }
  }

  const proxy = status?.proxy

  const fieldCtx: FieldCtx = {
    mode, system, isOverridden, valueOf, setValue, toggleOverride, editable,
  }

  return (
    <FieldContext.Provider value={fieldCtx}>
    <div className="pane">
      <div className="toolbar tight">
        <button className="primary" disabled={!dirty || saving} onClick={() => void save()}>
          {saving ? 'Saving…' : dirty ? 'Save changes' : 'Saved'}
        </button>
        <button disabled={!dirty} onClick={() => setDraft({})}>Revert</button>

        {mode === 'project' ? (
          <>
            <label className="field">
              Project name
              <input
                type="text"
                className="w-md"
                key={activeProject?.id}
                defaultValue={activeProject?.name ?? ''}
                onBlur={(event) => {
                  const name = event.target.value.trim()
                  if (activeProject && name && name !== activeProject.name) {
                    void renameProject(activeProject.id, name)
                    showToast('Project renamed')
                  }
                }}
              />
            </label>
            <span className="dim">
              {overrideCount === 0
                ? 'Everything inherited from System settings'
                : `${overrideCount} setting${overrideCount === 1 ? '' : 's'} overridden`}
            </span>
            {Object.keys(overrides).length > 0 && (
              <button
                className="sm"
                onClick={() => setDraft(
                  Object.fromEntries(Object.keys(overrides).map((k) => [k, null])),
                )}
              >
                Clear all overrides
              </button>
            )}
          </>
        ) : (
          <span className="dim">Applies to every project unless a project overrides it</span>
        )}

        <span className="spacer" />
        {mode === 'system' && (
          <>
            <span className="dim">
              Listening on {proxy?.listeners.length ? proxy.listeners.join(', ') : 'nothing'}
            </span>
            <button className="sm" onClick={() => void restartListener()}>
              Restart listener
            </button>
          </>
        )}
      </div>

      <div className="pane-scroll">
        <div className="settings">
          {mode === 'system' && (
            <div className="card">
              <h3>Proxy listener <span className="tag">system only</span></h3>
              <div className="card-body">
                <div className="row">
                  <label className="field">Bind address <TextField k="proxy_host" width="w-md" /></label>
                  <label className="field">Port <NumField k="proxy_port" /></label>
                </div>
                <p className="hint">
                  Shared by every project — there is one listener, so this cannot be
                  overridden per project. Inside the container BRUP binds{' '}
                  <code>0.0.0.0</code>; reach it from your machine at{' '}
                  <code>127.0.0.1:9081</code> as published by Docker. Changing the port
                  here also means changing the published port in{' '}
                  <code>docker-compose.yml</code>.
                </p>
                <div className="row">
                  <label className="toggle">
                    <input
                      type="checkbox"
                      checked={Boolean(valueOf('invisible_tls_enabled'))}
                      onChange={(e) => setValue('invisible_tls_enabled', e.target.checked)}
                    />
                    Run an invisible HTTPS listener
                  </label>
                  <label className="field">Port <NumField k="invisible_tls_port" /></label>
                </div>
                <p className="hint">
                  Terminates TLS directly for transparently redirected port 443
                  traffic, choosing a certificate from the SNI hostname.
                </p>
              </div>
            </div>
          )}

          {mode === 'system' && <VpnCard />}

          <div className="card">
            <h3>Invisible proxying</h3>
            <div className="card-body">
              <BoolRow
                k="invisible_proxy"
                label="Support clients that are not proxy-aware"
                hint={<>
                  A proxy-aware client sends <code>GET http://host/path</code> or a{' '}
                  <code>CONNECT</code>. A client that does not know it is proxied sends
                  plain <code>GET /path</code>; that only works with this on, and BRUP
                  then takes the target from the <code>Host</code> header.
                </>}
              />
              <Row
                k="invisible_default_host"
                label="Fallback host"
                hint="Used only when a request arrives with no Host header at all."
              >
                <TextField k="invisible_default_host" placeholder="(from Host header)" width="w-md" />
              </Row>
            </div>
          </div>

          <div className="card">
            <h3>Interception</h3>
            <div className="card-body">
              <BoolRow k="intercept_enabled" label="Interception enabled" />
              <BoolRow k="intercept_requests" label="Hold requests" />
              <BoolRow
                k="intercept_responses"
                label="Hold responses"
                hint="Holding responses halts every matching response, which is rarely what you want while browsing."
              />
              <Row
                k="intercept_skip_extensions"
                label="Never hold these file extensions"
                hint="Keeps static asset noise out of the intercept queue."
              >
                <ChipList
                  values={valueOf('intercept_skip_extensions')}
                  disabled={!editable('intercept_skip_extensions')}
                  onChange={(v) => setValue('intercept_skip_extensions', v)}
                  placeholder="css, png, woff2"
                />
              </Row>
            </div>
          </div>

          <div className="card">
            <h3>Scope</h3>
            <div className="card-body">
              <Row
                k="scope_include"
                label="Include (regex against the full URL)"
                hint="Leave empty to include everything. With any include rule set, only matching URLs are in scope."
              >
                <RuleList
                  rules={valueOf('scope_include')}
                  disabled={!editable('scope_include')}
                  onChange={(v) => setValue('scope_include', v)}
                  placeholder="^https?://target\.example\.com"
                />
              </Row>
              <Row
                k="scope_exclude"
                label="Exclude (regex)"
                hint="Out-of-scope traffic is still proxied so the site keeps working — it is just never held for interception."
              >
                <RuleList
                  rules={valueOf('scope_exclude')}
                  disabled={!editable('scope_exclude')}
                  onChange={(v) => setValue('scope_exclude', v)}
                  placeholder="\.(png|jpg|woff2)(\?|$)"
                />
              </Row>
            </div>
          </div>

          <div className="card">
            <h3>HTTP/2</h3>
            <div className="card-body">
              {mode === 'system' && (
                <div className="setting">
                  <div className="setting-head">
                    <b>Advertise HTTP/2 to clients</b>
                    <select
                      className="state"
                      value={valueOf('listen_http2') ? 'on' : 'off'}
                      onChange={(event) =>
                        setValue('listen_http2', event.target.value === 'on')}
                    >
                      <option value="on">On</option>
                      <option value="off">Off</option>
                    </select>
                    <span className="tag">system only</span>
                  </div>
                  <p className="hint">
                    Offers <code>h2</code> alongside <code>http/1.1</code> in the TLS
                    handshake, and the browser chooses. A listener property, so it is
                    shared by every project. Turn it off to force every client onto
                    HTTP/1.1.
                  </p>
                </div>
              )}
              <BoolRow
                k="upstream_http2"
                label="Offer HTTP/2 to origin servers"
                hint={<>
                  When a server declines, BRUP speaks HTTP/1.1 to it and translates,
                  so an HTTP/2 client still gets a coherent HTTP/2 response. Turn this
                  off to force a target onto HTTP/1.1 and compare how it behaves —
                  differences between the two paths are worth looking at.
                </>}
              />
            </div>
          </div>

          <div className="card">
            <h3>Header rules</h3>
            <div className="card-body">
              <Row
                k="header_rules"
                label="Rewrite headers on proxied traffic"
                hint={<>
                  Applied in order to traffic through the proxy, <b>before</b>{' '}
                  interception — so a held request shows what will really be sent, and
                  your edits there still win. Repeater and Intruder are left alone,
                  since you are editing the raw request by hand there anyway.{' '}
                  <code>Content-Length</code> and <code>Transfer-Encoding</code> cannot
                  be rewritten: they carry the message framing.
                </>}
              >
                <HeaderRules
                  rules={valueOf('header_rules')}
                  disabled={!editable('header_rules')}
                  onChange={(v) => setValue('header_rules', v)}
                />
              </Row>
            </div>
          </div>

          <div className="card">
            <h3>Upstream and TLS</h3>
            <div className="card-body">
              <Row k="upstream_proxy" label="Upstream proxy">
                <TextField k="upstream_proxy" placeholder="http://corp-proxy:3128" />
              </Row>
              <BoolRow
                k="upstream_verify_tls"
                label="Verify server certificates"
                hint="Off by default so you can test hosts with self-signed or expired certificates."
              />
              <Row k="connect_timeout" label="Connect timeout (seconds)">
                <NumField k="connect_timeout" width="w-xs" />
              </Row>
              <Row k="read_timeout" label="Read timeout (seconds)">
                <NumField k="read_timeout" width="w-xs" />
              </Row>
              <Row
                k="tls_passthrough_hosts"
                label="TLS pass-through hosts"
                hint={<>Tunnelled without interception, for hosts that pin certificates.{' '}
                  <code>*.example.com</code> matches subdomains.</>}
              >
                <ChipList
                  values={valueOf('tls_passthrough_hosts')}
                  disabled={!editable('tls_passthrough_hosts')}
                  onChange={(v) => setValue('tls_passthrough_hosts', v)}
                  placeholder="*.googleapis.com"
                />
              </Row>
            </div>
          </div>

          <div className="card">
            <h3>History</h3>
            <div className="card-body">
              <BoolRow k="logging_enabled" label="Log traffic to HTTP history" />
              <BoolRow k="log_out_of_scope" label="Include out-of-scope traffic" />
              <Row k="max_history" label="Keep at most (items)">
                <NumField k="max_history" />
              </Row>
              <Row
                k="max_stored_body"
                label="Max stored response (bytes)"
                hint="Larger responses are still forwarded in full to the browser; only the stored copy is truncated."
              >
                <NumField k="max_stored_body" />
              </Row>
            </div>
          </div>

          {mode === 'system' && <CaCard />}
        </div>
      </div>
    </div>
    </FieldContext.Provider>
  )
}

function CaCard() {
  const { status } = useApp()
  return (
    <div className="card">
      <h3>CA certificate <span className="tag">system wide</span></h3>
      <div className="card-body">
        <p className="hint">
          To read HTTPS traffic BRUP presents certificates it signs itself. Install
          this CA in the browser or OS trust store you are testing with — and only
          there. Anything trusting it can have its TLS traffic read by whoever holds
          the key on the <code>/data</code> volume. One CA serves every project, so
          you install it once.
        </p>
        <div className="row">
          <a href="/api/ca/cert.pem" download>
            <button>Download CA (.pem)</button>
          </a>
          <a href="/api/ca/cert.der" download>
            <button>Download CA (.der — Windows/Android)</button>
          </a>
        </div>
        <dl className="kv">
          <dt>SHA-256</dt>
          <dd style={{ fontSize: 11 }}>{status?.ca.fingerprint_sha256 ?? '—'}</dd>
          <dt>Expires</dt>
          <dd>{status?.ca.not_valid_after?.slice(0, 10) ?? '—'}</dd>
        </dl>
        <p className="hint">
          Firefox: Settings → Privacy &amp; Security → Certificates → View Certificates
          → Authorities → Import, then tick "Trust this CA to identify websites".
          Chrome and Safari use the OS trust store.
        </p>
      </div>
    </div>
  )
}
