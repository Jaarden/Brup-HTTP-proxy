import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, FlowDetail, FlowRow } from '../api'
import { MessageViewer } from '../components/MessageViewer'
import { Split } from '../components/Split'
import { b64ToRaw } from '../raw'
import { useApp, useFlowStream } from '../store'

const COLORS = ['', 'red', 'yellow', 'green', 'blue', 'purple']

function statusClass(status: number | null | undefined) {
  if (!status) return ''
  return `s${Math.floor(status / 100)}xx`
}

function fmtTime(ts: number) {
  return new Date(ts * 1000).toLocaleTimeString(undefined, { hour12: false })
}

function fmtBytes(n: number | null | undefined) {
  if (n == null) return ''
  if (n < 1024) return String(n)
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`
  return `${(n / 1024 / 1024).toFixed(1)}M`
}

export function History() {
  const { showToast, sendToRepeater, sendToIntruder, projectEpoch } = useApp()

  const [rows, setRows] = useState<FlowRow[]>([])
  const [total, setTotal] = useState(0)
  const [selected, setSelected] = useState<FlowDetail | null>(null)
  const [loading, setLoading] = useState(false)
  const [follow, setFollow] = useState(true)

  const [search, setSearch] = useState('')
  const [host, setHost] = useState('')
  const [method, setMethod] = useState('')
  const [source, setSource] = useState('')
  const [inScopeOnly, setInScopeOnly] = useState(false)
  const [hosts, setHosts] = useState<{ host: string; n: number }[]>([])

  const filters = { search, host, method, source, in_scope_only: inScopeOnly }
  const filtersRef = useRef(filters)
  filtersRef.current = filters

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const result = await api.history({ ...filtersRef.current, limit: 500 })
      setRows(result.items)
      setTotal(result.total)
    } catch (error) {
      showToast(`Could not load history: ${String(error)}`, 'error')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => {
    // projectEpoch changes when the active project does, which invalidates
    // both the rows and the host list.
    setSelected(null)
    void load()
    api.historyHosts().then(setHosts).catch(() => undefined)
  }, [load, search, host, method, source, inScopeOnly, projectEpoch])

  // A filtered view cannot be safely patched from the event stream, so live
  // append only applies to the unfiltered default view.
  const unfiltered = !search && !host && !method && !source && !inScopeOnly

  useFlowStream((type, data) => {
    if (type === 'history_cleared') {
      setRows([])
      setTotal(0)
      setSelected(null)
      return
    }
    if (type === 'flow_new') {
      if (!follow || !unfiltered) return
      setRows((prev) => [data as FlowRow, ...prev].slice(0, 500))
      setTotal((prev) => prev + 1)
      return
    }
    if (type === 'flow_update') {
      const patch = data as Partial<FlowRow> & { id: number }
      setRows((prev) => prev.map((row) => (row.id === patch.id ? { ...row, ...patch } : row)))
    }
  })

  const open = async (id: number) => {
    try {
      setSelected(await api.historyItem(id))
    } catch (error) {
      const message = error instanceof ApiError ? error.message : String(error)
      showToast(`Could not open flow: ${message}`, 'error')
    }
  }

  const clear = async () => {
    if (!window.confirm(`Delete all ${total.toLocaleString()} logged items? This cannot be undone.`)) {
      return
    }
    try {
      await api.clearHistory()
      setRows([])
      setTotal(0)
      setSelected(null)
      showToast('History cleared')
    } catch (error) {
      showToast(`Could not clear history: ${String(error)}`, 'error')
    }
  }

  const annotate = async (id: number, patch: { notes?: string; color?: string }) => {
    setRows((prev) => prev.map((row) => (row.id === id ? { ...row, ...patch } : row)))
    setSelected((prev) => (prev && prev.id === id ? { ...prev, ...patch } : prev))
    try {
      await api.annotate(id, patch)
    } catch {
      showToast('Could not save annotation', 'error')
    }
  }

  const handoff = selected && {
    host: selected.host,
    port: selected.port,
    tls: Boolean(selected.tls),
    raw: b64ToRaw(selected.raw_request_b64),
    label: `${selected.method ?? '?'} ${selected.host}`,
  }

  return (
    <div className="pane">
      <div className="toolbar tight">
        <input
          type="search"
          className="w-lg"
          placeholder="Filter by URL, host or method…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <select className="w-md" value={host} onChange={(event) => setHost(event.target.value)}>
          <option value="">All hosts</option>
          {hosts.map((entry) => (
            <option key={entry.host} value={entry.host}>{entry.host} ({entry.n})</option>
          ))}
        </select>
        <select className="w-sm" value={method} onChange={(event) => setMethod(event.target.value)}>
          <option value="">Any method</option>
          {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((verb) => (
            <option key={verb} value={verb}>{verb}</option>
          ))}
        </select>
        <select className="w-sm" value={source} onChange={(event) => setSource(event.target.value)}>
          <option value="">All sources</option>
          <option value="proxy">Proxy</option>
          <option value="repeater">Repeater</option>
        </select>
        <label className="toggle">
          <input
            type="checkbox"
            checked={inScopeOnly}
            onChange={(event) => setInScopeOnly(event.target.checked)}
          />
          In scope only
        </label>

        <span className="spacer" />

        <label className="toggle" title="Append new traffic as it arrives">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
          Follow
        </label>
        <span className="dim">
          {loading ? 'loading…' : `${rows.length} shown / ${total.toLocaleString()} logged`}
        </span>
        <button className="sm" onClick={() => void load()}>Refresh</button>
        <button className="sm danger" onClick={() => void clear()}>Clear</button>
      </div>

      <Split vertical initial={0.45} storageKey="history">
        <div className="table-wrap">
          <table className="grid">
            <colgroup>
              <col style={{ width: 58 }} />
              <col style={{ width: 76 }} />
              <col style={{ width: 66 }} />
              <col style={{ width: 190 }} />
              <col />
              <col style={{ width: 62 }} />
              <col style={{ width: 62 }} />
              <col style={{ width: 52 }} />
              <col style={{ width: 120 }} />
              <col style={{ width: 180 }} />
            </colgroup>
            <thead>
              <tr>
                <th className="num nosort">#</th>
                <th className="nosort">Time</th>
                <th className="nosort">Method</th>
                <th className="nosort">Host</th>
                <th className="nosort">URL</th>
                <th className="num nosort">Status</th>
                <th className="num nosort">Len</th>
                <th className="num nosort">ms</th>
                <th className="nosort">Type</th>
                <th className="nosort">Notes</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  className={
                    (row.id === selected?.id ? 'selected ' : '') +
                    (row.color ? `row-${row.color}` : '')
                  }
                  onClick={() => void open(row.id)}
                >
                  <td className="num dim">{row.id}</td>
                  <td className="mono dim">{fmtTime(row.ts)}</td>
                  <td className="mono">{row.method}</td>
                  <td>
                    {row.host}
                    {row.tls ? <span className="tag tls" style={{ marginLeft: 4 }}>TLS</span> : null}
                    {row.source === 'repeater' ? <span className="tag" style={{ marginLeft: 4 }}>RPT</span> : null}
                    {row.was_edited ? <span className="tag edited" style={{ marginLeft: 4 }}>ED</span> : null}
                  </td>
                  <td className="mono" title={row.url ?? ''}>
                    {(row.url ?? '').replace(/^https?:\/\/[^/]+/, '') || '/'}
                  </td>
                  <td className={`num ${statusClass(row.status)}`}>{row.status ?? ''}</td>
                  <td className="num dim">{fmtBytes(row.resp_len)}</td>
                  <td className="num dim">{row.duration_ms ? Math.round(row.duration_ms) : ''}</td>
                  <td className="dim">{row.mime ?? ''}</td>
                  <td className={row.error ? 'err' : 'dim'}>{row.error ?? row.notes ?? ''}</td>
                </tr>
              ))}
              {rows.length === 0 && !loading && (
                <tr>
                  <td colSpan={10} style={{ padding: 20, textAlign: 'center', color: 'var(--text-faint)' }}>
                    No traffic logged yet. Point your browser at the proxy and load a page.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {selected ? (
          <div className="pane">
            <div className="toolbar tight">
              <b className="mono" style={{ fontSize: 12 }}>
                #{selected.id} {selected.method} {selected.url}
              </b>
              <span className="spacer" />
              {handoff && (
                <>
                  <button className="sm" onClick={() => sendToRepeater(handoff)}>→ Repeater</button>
                  <button className="sm" onClick={() => sendToIntruder(handoff)}>→ Intruder</button>
                </>
              )}
              <span className="dim">Highlight</span>
              {COLORS.map((color) => (
                <button
                  key={color || 'none'}
                  className="sm ghost"
                  title={color || 'none'}
                  onClick={() => void annotate(selected.id, { color })}
                  style={{
                    width: 20, padding: 0,
                    background: color ? `var(--${color})` : 'transparent',
                    border: `1px solid ${color ? 'transparent' : 'var(--border-strong)'}`,
                  }}
                >
                  {color ? '' : '×'}
                </button>
              ))}
              <input
                type="text"
                className="w-md"
                placeholder="Note…"
                defaultValue={selected.notes ?? ''}
                key={`note-${selected.id}`}
                onBlur={(event) => void annotate(selected.id, { notes: event.target.value })}
              />
            </div>
            <Split initial={0.5} storageKey="history-detail">
              <MessageViewer
                title="Request"
                raw={b64ToRaw(selected.raw_request_b64)}
              />
              <MessageViewer
                title="Response"
                raw={b64ToRaw(selected.raw_response_b64)}
                decodedBody={selected.decoded_body_b64 ? b64ToRaw(selected.decoded_body_b64) : null}
                status={
                  selected.error ? <span className="err">{selected.error}</span> : null
                }
              />
            </Split>
          </div>
        ) : (
          <div className="empty">
            <p>Select an item above to inspect its request and response.</p>
          </div>
        )}
      </Split>
    </div>
  )
}
