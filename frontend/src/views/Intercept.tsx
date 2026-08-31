import { useEffect, useMemo, useState } from 'react'
import { api, ApiError } from '../api'
import { RawEditor } from '../components/RawEditor'
import { b64ToRaw, rawToB64 } from '../raw'
import { useApp } from '../store'

export function Intercept() {
  const {
    pending, settings, saveProjectSettings, showToast, sendToRepeater, sendToIntruder,
    activeProjectId, projects,
  } = useApp()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const [dirty, setDirty] = useState(false)

  const selected = useMemo(
    () => pending.find((item) => item.id === selectedId) ?? pending[0] ?? null,
    [pending, selectedId],
  )

  // Load the selected message into the editor, discarding any stale draft.
  useEffect(() => {
    if (!selected) {
      setDraft('')
      setDirty(false)
      return
    }
    setDraft(b64ToRaw(selected.raw_b64))
    setDirty(false)
  }, [selected?.id]) // eslint-disable-line react-hooks/exhaustive-deps

  const act = async (fn: () => Promise<unknown>, label: string) => {
    try {
      await fn()
    } catch (error) {
      const message = error instanceof ApiError ? error.message : String(error)
      showToast(`${label} failed: ${message}`, 'error')
    }
  }

  const forward = () => {
    if (!selected) return
    const id = selected.id
    const edited = dirty ? rawToB64(draft) : undefined
    setSelectedId(null)
    void act(() => api.forward(id, edited), 'Forward')
  }

  const drop = () => {
    if (!selected) return
    const id = selected.id
    setSelectedId(null)
    void act(() => api.drop(id), 'Drop')
  }

  const interceptOn = settings?.intercept_enabled ?? false

  return (
    <div className="pane">
      <div className="toolbar">
        <button
          className={`bigtoggle${interceptOn ? ' on' : ''}`}
          onClick={() => void saveProjectSettings({ intercept_enabled: !interceptOn })}
        >
          Intercept is {interceptOn ? 'on' : 'off'}
        </button>

        <button className="primary" disabled={!selected} onClick={forward}>
          Forward
        </button>
        <button className="danger" disabled={!selected} onClick={drop}>
          Drop
        </button>
        <button
          disabled={pending.length === 0}
          onClick={() => void act(() => api.forwardAll(), 'Forward all')}
        >
          Forward all ({pending.length})
        </button>
        <button
          className="danger"
          disabled={pending.length === 0}
          onClick={() => void act(() => api.dropAll(), 'Drop all')}
        >
          Drop all
        </button>

        <span className="spacer" />

        <label className="toggle">
          <input
            type="checkbox"
            checked={settings?.intercept_requests ?? true}
            onChange={(event) => void saveProjectSettings({ intercept_requests: event.target.checked })}
          />
          Requests
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={settings?.intercept_responses ?? false}
            onChange={(event) => void saveProjectSettings({ intercept_responses: event.target.checked })}
          />
          Responses
        </label>

        <button
          className="ghost"
          disabled={!selected}
          onClick={() => selected && sendToRepeater({
            host: selected.host, port: selected.port, tls: selected.tls,
            raw: draft, label: `${selected.method} ${selected.host}`,
          })}
        >
          → Repeater
        </button>
        <button
          className="ghost"
          disabled={!selected || selected.kind !== 'request'}
          onClick={() => selected && sendToIntruder({
            host: selected.host, port: selected.port, tls: selected.tls,
            raw: draft, label: `${selected.method} ${selected.host}`,
          })}
        >
          → Intruder
        </button>
      </div>

      {pending.length === 0 ? (
        <div className="empty">
          <h4>Nothing is being held</h4>
          {interceptOn ? (
            <p>
              Interception is on. Browse through the proxy and the next matching
              request will appear here, paused, for you to edit before it is sent.
            </p>
          ) : (
            <p>
              Interception is off, so traffic passes straight through and is only
              logged to HTTP history. Turn it on above to hold requests.
            </p>
          )}
        </div>
      ) : (
        <div className="split">
          <div className="pending-list">
            {pending.map((item) => (
              <div
                key={item.id}
                className={`pending-item${item.id === selected?.id ? ' active' : ''}`}
                onClick={() => setSelectedId(item.id)}
              >
                <div>
                  <span className={`tag${item.kind === 'response' ? '' : ' tls'}`}>
                    {item.kind === 'response' ? `← ${item.status ?? '?'}` : item.method}
                  </span>{' '}
                  {item.host}
                  {item.tls && <span className="tag tls" style={{ marginLeft: 5 }}>TLS</span>}
                </div>
                <span className="u">{item.url}</span>
                {item.project_id !== activeProjectId && (
                  <span className="tag edited" title="Captured under another project">
                    {projects.find((p) => p.id === item.project_id)?.name ?? 'other project'}
                  </span>
                )}
              </div>
            ))}
          </div>

          <div className="half" style={{ flexGrow: 1 }}>
            <RawEditor
              value={draft}
              onChange={(value) => {
                setDraft(value)
                setDirty(true)
              }}
              onSubmit={forward}
              title={
                selected
                  ? `Held ${selected.kind} — ${selected.url}`
                  : 'Held message'
              }
              status={dirty ? <span style={{ color: 'var(--yellow)' }}>edited</span> : null}
              toolbar={
                <span className="dim" style={{ fontWeight: 400, textTransform: 'none' }}>
                  Ctrl+Enter to forward
                </span>
              }
            />
          </div>
        </div>
      )}
    </div>
  )
}
