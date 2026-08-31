import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  api, ApiError, AttackConfig, AttackPreview, AttackSummary, AttackType,
  defaultPayloadSet, ResultDetail, ResultRow, Wordlist,
} from '../api'
import { MessageViewer } from '../components/MessageViewer'
import { PayloadSetEditor } from '../components/PayloadSetEditor'
import { RawEditor } from '../components/RawEditor'
import { Split } from '../components/Split'
import { b64ToRaw, MARKER, rawToB64 } from '../raw'
import { useApp } from '../store'

type SubTab = 'positions' | 'payloads' | 'options' | 'results'

const ATTACK_TYPES: { value: AttackType; label: string; blurb: string }[] = [
  {
    value: 'sniper',
    label: 'Sniper',
    blurb: 'One payload set. Each position is attacked in turn while the others keep '
      + 'their original value. Requests = positions × payloads.',
  },
  {
    value: 'battering_ram',
    label: 'Battering ram',
    blurb: 'One payload set. The same payload is placed in every position at once. '
      + 'Requests = payloads.',
  },
  {
    value: 'pitchfork',
    label: 'Pitchfork',
    blurb: 'One payload set per position, advanced in lockstep. Stops with the '
      + 'shortest set. Good for paired credentials.',
  },
  {
    value: 'cluster_bomb',
    label: 'Cluster bomb',
    blurb: 'One payload set per position, trying every combination. Requests multiply, '
      + 'so keep the sets small.',
  },
]

function statusClass(status: number | null) {
  return status ? `s${Math.floor(status / 100)}xx` : ''
}

export function Intruder() {
  const { intruder, setIntruder, showToast, subTab, setSubTab, projectEpoch } = useApp()
  const tab = (['positions', 'payloads', 'options', 'results'].includes(subTab)
    ? subTab
    : 'positions') as SubTab
  const setTab = setSubTab
  const [preview, setPreview] = useState<AttackPreview | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)
  const [wordlists, setWordlists] = useState<Wordlist[]>([])
  const templateRef = useRef<HTMLTextAreaElement>(null)

  const [attacks, setAttacks] = useState<AttackSummary[]>([])
  const [results, setResults] = useState<ResultRow[]>([])
  const [detail, setDetail] = useState<ResultDetail | null>(null)
  const [sortKey, setSortKey] = useState<keyof ResultRow>('idx')
  const [sortAsc, setSortAsc] = useState(true)
  const [filter, setFilter] = useState('')

  const { subscribe } = useApp()
  const activeId = intruder.activeAttackId
  const activeAttack = attacks.find((a) => a.id === activeId) ?? null

  const positionCount = useMemo(
    () => Math.floor((intruder.template.split(MARKER).length - 1) / 2),
    [intruder.template],
  )

  const setsNeeded = intruder.attackType === 'sniper' || intruder.attackType === 'battering_ram'
    ? 1
    : Math.max(1, positionCount)

  const loadWordlists = useCallback(() => {
    api.wordlists().then(setWordlists).catch(() => undefined)
  }, [])

  useEffect(loadWordlists, [loadWordlists])

  // Attacks belong to a project, so drop the loaded results on a switch.
  useEffect(() => {
    setResults([])
    setDetail(null)
  }, [projectEpoch])

  useEffect(() => {
    api.intruderList().then((list) => {
      setAttacks(list)
      if (list.length === 0) return
      setIntruder((prev) => {
        if (prev.activeAttackId) return prev
        // Nothing selected (e.g. after a page reload): adopt the newest attack
        // so an in-flight run stays visible.
        void api.intruderResults(list[0].id)
          .then((loaded) => setResults(loaded.items))
          .catch(() => undefined)
        return { ...prev, activeAttackId: list[0].id }
      })
    }).catch(() => undefined)
  }, [setIntruder, projectEpoch])

  // Keep the number of payload sets in step with what the attack type needs.
  useEffect(() => {
    setIntruder((prev) => {
      if (prev.payloadSets.length >= setsNeeded) return prev
      const next = [...prev.payloadSets]
      while (next.length < setsNeeded) next.push(defaultPayloadSet())
      return { ...prev, payloadSets: next }
    })
  }, [setsNeeded, setIntruder])

  const buildConfig = useCallback((): AttackConfig => ({
    host: intruder.host.trim(),
    port: intruder.port,
    tls: intruder.tls,
    template_b64: rawToB64(intruder.template),
    attack_type: intruder.attackType,
    payload_sets: intruder.payloadSets.slice(0, setsNeeded),
    concurrency: intruder.concurrency,
    delay_ms: intruder.delayMs,
    update_content_length: intruder.updateContentLength,
    url_encode_payloads: intruder.urlEncode,
    grep_match: intruder.grepMatch.split('\n').map((s) => s.trim()).filter(Boolean),
    max_requests: intruder.maxRequests,
    name: '',
  }), [intruder, setsNeeded])

  // Live results for the running attack.
  useEffect(() => subscribe((type, data) => {
    if (type === 'intruder_result') {
      const row = data as ResultRow & { completed: number; total: number }
      if (row.attack_id !== activeId) return
      setResults((prev) => (prev.some((r) => r.idx === row.idx) ? prev : [...prev, row]))
      setAttacks((prev) => prev.map((a) => (
        a.id === row.attack_id ? { ...a, completed: row.completed } : a
      )))
    } else if (type === 'intruder_started') {
      const summary = data as AttackSummary
      setAttacks((prev) => [summary, ...prev.filter((a) => a.id !== summary.id)])
    } else if (type === 'intruder_state' || type === 'intruder_done') {
      const summary = data as AttackSummary
      setAttacks((prev) => prev.map((a) => (a.id === summary.id ? summary : a)))
    }
  }), [subscribe, activeId])

  const refreshPreview = async () => {
    setPreviewError(null)
    if (!intruder.template.trim()) {
      setPreview(null)
      return
    }
    try {
      setPreview(await api.intruderPreview(buildConfig()))
    } catch (error) {
      setPreview(null)
      setPreviewError(error instanceof ApiError ? error.message : String(error))
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => void refreshPreview(), 350)
    return () => window.clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intruder.template, intruder.attackType, intruder.payloadSets, intruder.urlEncode,
      intruder.maxRequests, intruder.updateContentLength])

  const wrapSelection = () => {
    const node = templateRef.current
    if (!node) return
    const { selectionStart: start, selectionEnd: end } = node
    if (start === end) {
      showToast('Select the value you want to fuzz first', 'error')
      return
    }
    const text = intruder.template
    const next = text.slice(0, start) + MARKER + text.slice(start, end) + MARKER + text.slice(end)
    setIntruder((prev) => ({ ...prev, template: next }))
    window.setTimeout(() => node.setSelectionRange(end + 2, end + 2), 0)
  }

  const autoMark = async (mode: 'auto' | 'clear') => {
    try {
      const result = await api.markPositions(rawToB64(intruder.template), mode)
      setIntruder((prev) => ({ ...prev, template: b64ToRaw(result.raw_b64) }))
      showToast(mode === 'clear'
        ? 'Positions cleared'
        : `Marked ${result.positions} position${result.positions === 1 ? '' : 's'}`)
    } catch (error) {
      const message = error instanceof ApiError ? error.message : String(error)
      showToast(message, 'error')
    }
  }

  const start = async () => {
    if (!intruder.host.trim()) {
      showToast('Set a target host first', 'error')
      setTab('positions')
      return
    }
    try {
      const summary = await api.intruderStart(buildConfig())
      setAttacks((prev) => [summary, ...prev.filter((a) => a.id !== summary.id)])
      setIntruder((prev) => ({ ...prev, activeAttackId: summary.id }))
      setResults([])
      setDetail(null)
      setTab('results')
      showToast(`Attack started — ${summary.total.toLocaleString()} requests`)
    } catch (error) {
      const message = error instanceof ApiError ? error.message : String(error)
      showToast(message, 'error')
    }
  }

  const selectAttack = async (id: string) => {
    setIntruder((prev) => ({ ...prev, activeAttackId: id }))
    setDetail(null)
    try {
      const loaded = await api.intruderResults(id)
      setResults(loaded.items)
    } catch {
      setResults([])
    }
  }

  const control = async (action: 'pause' | 'resume' | 'stop') => {
    if (!activeId) return
    try {
      const summary = await api.intruderControl(activeId, action)
      setAttacks((prev) => prev.map((a) => (a.id === summary.id ? summary : a)))
    } catch (error) {
      showToast(error instanceof ApiError ? error.message : String(error), 'error')
    }
  }

  const sorted = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    const filtered = needle
      ? results.filter((row) =>
          row.payloads.join(' ').toLowerCase().includes(needle) ||
          String(row.status ?? '').includes(needle) ||
          (row.grep_hits ?? []).join(' ').toLowerCase().includes(needle))
      : results
    const copy = [...filtered]
    copy.sort((a, b) => {
      const av = a[sortKey], bv = b[sortKey]
      const an = typeof av === 'number' ? av : Number.NEGATIVE_INFINITY
      const bn = typeof bv === 'number' ? bv : Number.NEGATIVE_INFINITY
      if (typeof av === 'number' || typeof bv === 'number') return sortAsc ? an - bn : bn - an
      const as = String(av ?? ''), bs = String(bv ?? '')
      return sortAsc ? as.localeCompare(bs) : bs.localeCompare(as)
    })
    return copy
  }, [results, sortKey, sortAsc, filter])

  const sortBy = (key: keyof ResultRow) => {
    if (key === sortKey) setSortAsc((prev) => !prev)
    else {
      setSortKey(key)
      setSortAsc(true)
    }
  }

  const openResult = async (idx: number) => {
    if (!activeId) return
    try {
      setDetail(await api.intruderResult(activeId, idx))
    } catch {
      showToast('Could not load that result', 'error')
    }
  }

  const currentBlurb = ATTACK_TYPES.find((t) => t.value === intruder.attackType)!

  return (
    <div className="pane">
      <div className="subtabs">
        {(['positions', 'payloads', 'options', 'results'] as SubTab[]).map((name) => (
          <button
            key={name}
            className={`subtab${tab === name ? ' active' : ''}`}
            onClick={() => setTab(name)}
          >
            {name === 'positions'
              ? `Positions (${positionCount})`
              : name.charAt(0).toUpperCase() + name.slice(1)}
            {name === 'results' && activeAttack && activeAttack.status === 'running' && (
              <span className="badge" style={{ marginLeft: 6 }}>●</span>
            )}
          </button>
        ))}
        <span className="spacer" />
        <div style={{ padding: '2px 8px' }}>
          <button className="primary" onClick={() => void start()}>Start attack</button>
        </div>
      </div>

      {/* ------------------------------------------------------- positions */}
      {tab === 'positions' && (
        <div className="pane">
          <div className="toolbar tight">
            <label className="field">
              Host
              <input
                type="text" className="w-md mono" value={intruder.host} placeholder="example.com"
                onChange={(event) => setIntruder((p) => ({ ...p, host: event.target.value }))}
              />
            </label>
            <label className="field">
              Port
              <input
                type="number" className="w-xs mono" value={intruder.port}
                onChange={(event) => setIntruder((p) => ({ ...p, port: Number(event.target.value) || 0 }))}
              />
            </label>
            <label className="toggle">
              <input
                type="checkbox" checked={intruder.tls}
                onChange={(event) => setIntruder((p) => ({
                  ...p,
                  tls: event.target.checked,
                  port: event.target.checked ? (p.port === 80 ? 443 : p.port)
                                             : (p.port === 443 ? 80 : p.port),
                }))}
              />
              HTTPS
            </label>
            <span className="spacer" />
            <button onClick={wrapSelection}>Add § position</button>
            <button onClick={() => void autoMark('auto')}>Auto-mark params</button>
            <button className="danger" onClick={() => void autoMark('clear')}>Clear §</button>
          </div>

          <Split initial={0.62} storageKey="intruder-positions">
            <RawEditor
              ref={templateRef}
              title="Request template"
              value={intruder.template}
              onChange={(value) => setIntruder((p) => ({ ...p, template: value }))}
              placeholder={'Send a request here from HTTP history or Repeater, or paste one.'}
              status={
                <span style={{ color: positionCount ? 'var(--accent)' : 'var(--text-faint)' }}>
                  {positionCount} position{positionCount === 1 ? '' : 's'}
                </span>
              }
            />
            <div className="pane-scroll" style={{ padding: 13 }}>
              <div className="card">
                <h3>What will be sent</h3>
                <div className="card-body">
                  {previewError ? (
                    <p className="hint err">{previewError}</p>
                  ) : preview ? (
                    <>
                      <dl className="kv">
                        <dt>Positions</dt><dd>{preview.positions}</dd>
                        <dt>Payload sets</dt>
                        <dd>{preview.set_sizes.map((n) => n.toLocaleString()).join(' × ') || '—'}</dd>
                        <dt>Total requests</dt><dd>{preview.total.toLocaleString()}</dd>
                        <dt>Will send</dt>
                        <dd style={{ color: preview.total > preview.capped_at ? 'var(--yellow)' : undefined }}>
                          {preview.will_send.toLocaleString()}
                          {preview.total > preview.capped_at
                            && ` (capped — raise the limit in Options)`}
                        </dd>
                      </dl>
                      {preview.samples.length > 0 && (
                        <>
                          <b style={{ fontSize: 12 }}>First request</b>
                          <textarea
                            className="mono" readOnly rows={12}
                            value={b64ToRaw(preview.samples[0].raw_b64)}
                          />
                        </>
                      )}
                    </>
                  ) : (
                    <p className="hint">
                      Mark at least one payload position, then configure payloads.
                      Positions are shown as <span className="marker">§</span> around
                      the value they replace.
                    </p>
                  )}
                </div>
              </div>
            </div>
          </Split>
        </div>
      )}

      {/* -------------------------------------------------------- payloads */}
      {tab === 'payloads' && (
        <div className="pane-scroll">
          <div className="settings">
            <div className="card">
              <h3>Attack type</h3>
              <div className="card-body">
                <div className="row">
                  <select
                    className="w-md"
                    value={intruder.attackType}
                    onChange={(event) => setIntruder((p) => ({
                      ...p, attackType: event.target.value as AttackType,
                    }))}
                  >
                    {ATTACK_TYPES.map((entry) => (
                      <option key={entry.value} value={entry.value}>{entry.label}</option>
                    ))}
                  </select>
                  <p className="hint grow">{currentBlurb.blurb}</p>
                </div>
                {positionCount === 0 && (
                  <p className="hint" style={{ color: 'var(--yellow)' }}>
                    No positions are marked yet — set them on the Positions tab first.
                  </p>
                )}
                {setsNeeded > 1 && (
                  <p className="hint">
                    {currentBlurb.label} needs one payload set per position, so{' '}
                    {setsNeeded} sets are shown below.
                  </p>
                )}
              </div>
            </div>

            {intruder.payloadSets.slice(0, Math.max(setsNeeded, 1)).map((set, index) => (
              <PayloadSetEditor
                key={index}
                index={index}
                set={set}
                wordlists={wordlists}
                required={index < setsNeeded}
                showToast={showToast}
                onWordlistsChanged={loadWordlists}
                onChange={(patch) => setIntruder((prev) => ({
                  ...prev,
                  payloadSets: prev.payloadSets.map((s, i) => (i === index ? { ...s, ...patch } : s)),
                }))}
              />
            ))}
          </div>
        </div>
      )}

      {/* --------------------------------------------------------- options */}
      {tab === 'options' && (
        <div className="pane-scroll">
          <div className="settings">
            <div className="card">
              <h3>Request engine</h3>
              <div className="card-body">
                <div className="row">
                  <label className="field">
                    Concurrent requests
                    <input
                      type="number" className="w-xs" min={1} max={64} value={intruder.concurrency}
                      onChange={(event) => setIntruder((p) => ({
                        ...p, concurrency: Math.max(1, Number(event.target.value) || 1),
                      }))}
                    />
                  </label>
                  <label className="field">
                    Delay between requests (ms)
                    <input
                      type="number" className="w-sm" min={0} value={intruder.delayMs}
                      onChange={(event) => setIntruder((p) => ({
                        ...p, delayMs: Math.max(0, Number(event.target.value) || 0),
                      }))}
                    />
                  </label>
                  <label className="field">
                    Max requests
                    <input
                      type="number" className="w-sm" min={1} value={intruder.maxRequests}
                      onChange={(event) => setIntruder((p) => ({
                        ...p, maxRequests: Math.max(1, Number(event.target.value) || 1),
                      }))}
                    />
                  </label>
                </div>
                <p className="hint">
                  Concurrency and delay decide how hard you hit the target. Only test
                  systems you are authorised to test, and keep the rate low enough not
                  to cause an outage.
                </p>
              </div>
            </div>

            <div className="card">
              <h3>Payload handling</h3>
              <div className="card-body">
                <label className="toggle">
                  <input
                    type="checkbox" checked={intruder.urlEncode}
                    onChange={(event) => setIntruder((p) => ({ ...p, urlEncode: event.target.checked }))}
                  />
                  URL-encode characters outside <code>A-Z a-z 0-9 - _ . ~</code>
                </label>
                <label className="toggle">
                  <input
                    type="checkbox" checked={intruder.updateContentLength}
                    onChange={(event) => setIntruder((p) => ({
                      ...p, updateContentLength: event.target.checked,
                    }))}
                  />
                  Recalculate Content-Length for each request
                </label>
                <p className="hint">
                  Turn encoding off when a payload must reach the server byte for byte —
                  for example when testing how the target handles raw delimiters.
                </p>
              </div>
            </div>

            <div className="card">
              <h3>Grep — match</h3>
              <div className="card-body">
                <textarea
                  className="mono" rows={5}
                  placeholder={'Welcome back\nInvalid password\nSQL syntax'}
                  value={intruder.grepMatch}
                  onChange={(event) => setIntruder((p) => ({ ...p, grepMatch: event.target.value }))}
                />
                <p className="hint">
                  One expression per line. Each response is flagged in the results table
                  when it contains the text — the quickest way to spot the one login that
                  behaved differently.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* --------------------------------------------------------- results */}
      {tab === 'results' && (
        <div className="pane">
          <div className="toolbar tight">
            <label className="field">
              Attack
              <select
                className="w-md"
                value={activeId ?? ''}
                onChange={(event) => void selectAttack(event.target.value)}
              >
                <option value="">— none —</option>
                {attacks.map((attack) => (
                  <option key={attack.id} value={attack.id}>
                    {attack.attack_type} · {attack.host} · {attack.status}
                    {' '}({attack.completed}/{attack.total})
                  </option>
                ))}
              </select>
            </label>

            {activeAttack && (
              <>
                <div className="progress" title={`${activeAttack.completed} of ${activeAttack.total}`}>
                  <div style={{
                    width: `${activeAttack.total
                      ? (activeAttack.completed / activeAttack.total) * 100
                      : 0}%`,
                  }} />
                </div>
                <span className="dim mono">
                  {activeAttack.completed.toLocaleString()}/{activeAttack.total.toLocaleString()}
                  {activeAttack.errors > 0 && <span className="err"> · {activeAttack.errors} errors</span>}
                </span>
                {activeAttack.status === 'running' && (
                  <button className="sm" onClick={() => void control('pause')}>Pause</button>
                )}
                {activeAttack.status === 'paused' && (
                  <button className="sm" onClick={() => void control('resume')}>Resume</button>
                )}
                {(activeAttack.status === 'running' || activeAttack.status === 'paused') && (
                  <button className="sm danger" onClick={() => void control('stop')}>Stop</button>
                )}
                <span className={activeAttack.status === 'error' ? 'err' : 'dim'}>
                  {activeAttack.status}{activeAttack.message ? `: ${activeAttack.message}` : ''}
                </span>
              </>
            )}

            <span className="spacer" />
            <input
              type="search" className="w-md" placeholder="Filter results…"
              value={filter} onChange={(event) => setFilter(event.target.value)}
            />
            <span className="dim">{sorted.length.toLocaleString()} rows</span>
          </div>

          {!activeId ? (
            <div className="empty">
              <h4>No attack selected</h4>
              <p>
                Configure positions and payloads, then press <b>Start attack</b>.
                Results stream in here as they land.
              </p>
            </div>
          ) : (
            <Split vertical initial={0.5} storageKey="intruder-results">
              <div className="table-wrap">
                <table className="grid">
                  <thead>
                    <tr>
                      {([
                        ['idx', '#'], ['payloads', 'Payload'], ['status', 'Status'],
                        ['resp_len', 'Length'], ['words', 'Words'], ['duration_ms', 'ms'],
                        ['grep_hits', 'Grep'], ['error', 'Error'],
                      ] as [keyof ResultRow, string][]).map(([key, label]) => (
                        <th
                          key={key}
                          className={key === 'payloads' || key === 'grep_hits' || key === 'error' ? '' : 'num'}
                          onClick={() => sortBy(key)}
                        >
                          {label}{sortKey === key ? (sortAsc ? ' ▲' : ' ▼') : ''}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.map((row) => (
                      <tr
                        key={row.idx}
                        className={
                          (row.idx === detail?.idx ? 'selected ' : '') +
                          ((row.grep_hits ?? []).length > 0 ? 'row-yellow' : '')
                        }
                        onClick={() => void openResult(row.idx)}
                      >
                        <td className="num dim">{row.idx}</td>
                        <td className="mono">{row.payloads.join(' | ')}</td>
                        <td className={`num ${statusClass(row.status)}`}>{row.status ?? ''}</td>
                        <td className="num dim">{row.resp_len?.toLocaleString() ?? ''}</td>
                        <td className="num dim">{row.words ?? ''}</td>
                        <td className="num dim">{row.duration_ms ? Math.round(row.duration_ms) : ''}</td>
                        <td style={{ color: 'var(--yellow)' }}>{(row.grep_hits ?? []).join(', ')}</td>
                        <td className="err">{row.error ?? ''}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {detail ? (
                <Split initial={0.5} storageKey="intruder-detail">
                  <MessageViewer
                    title={`Request #${detail.idx} — ${detail.payloads.join(' | ')}`}
                    raw={b64ToRaw(detail.raw_request_b64)}
                  />
                  <MessageViewer
                    title="Response"
                    raw={b64ToRaw(detail.raw_response_b64)}
                    decodedBody={detail.decoded_body_b64 ? b64ToRaw(detail.decoded_body_b64) : null}
                    status={detail.error ? <span className="err">{detail.error}</span> : null}
                  />
                </Split>
              ) : (
                <div className="empty">
                  <p>Select a result row to see the exact request sent and the response.</p>
                </div>
              )}
            </Split>
          )}
        </div>
      )}
    </div>
  )
}
