import { useEffect, useState } from 'react'
import { api, ApiError, RepeaterResult } from '../api'
import { MessageViewer } from '../components/MessageViewer'
import { RawEditor } from '../components/RawEditor'
import { Split } from '../components/Split'
import { b64ToRaw, rawToB64 } from '../raw'
import { RepeaterTab, useApp } from '../store'

interface TabResult {
  result: RepeaterResult | null
  sending: boolean
}

export function Repeater() {
  const {
    repeaterTabs, setRepeaterTabs, activeRepeaterTab, setActiveRepeaterTab,
    showToast, sendToIntruder, repeaterLoaded, projectEpoch,
  } = useApp()

  const [results, setResults] = useState<Record<string, TabResult>>({})
  const [updateLength, setUpdateLength] = useState(true)
  const [historyIndex, setHistoryIndex] = useState<Record<string, number>>({})

  const tab = repeaterTabs.find((t) => t.id === activeRepeaterTab) ?? repeaterTabs[0]

  // Responses belong to the project whose tabs produced them.
  useEffect(() => {
    setResults({})
    setHistoryIndex({})
  }, [projectEpoch])

  const patchTab = (id: string, patch: Partial<RepeaterTab>) => {
    setRepeaterTabs((prev) => prev.map((t) => (t.id === id ? { ...t, ...patch } : t)))
  }

  const addTab = () => {
    const id = `r-${Date.now().toString(36)}`
    setRepeaterTabs((prev) => [...prev, {
      id,
      name: `Tab ${prev.length + 1}`,
      host: tab?.host ?? '',
      port: tab?.port ?? 80,
      tls: tab?.tls ?? false,
      raw: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
      history: [],
    }])
    setActiveRepeaterTab(id)
  }

  const closeTab = (id: string) => {
    setRepeaterTabs((prev) => {
      const next = prev.filter((t) => t.id !== id)
      if (next.length === 0) {
        return [{
          id: `r-${Date.now().toString(36)}`,
          name: 'Tab 1', host: '', port: 80, tls: false,
          raw: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n', history: [],
        }]
      }
      if (id === activeRepeaterTab) setActiveRepeaterTab(next[next.length - 1].id)
      return next
    })
  }

  const send = async () => {
    if (!tab) return
    if (!tab.host.trim()) {
      showToast('Set a target host first', 'error')
      return
    }
    setResults((prev) => ({ ...prev, [tab.id]: { result: null, sending: true } }))
    // Keep a per-tab trail so an experiment can be walked back.
    patchTab(tab.id, {
      history: [...tab.history.slice(-49), { raw: tab.raw, at: Date.now() }],
    })
    try {
      const result = await api.repeaterSend({
        host: tab.host.trim(),
        port: tab.port,
        tls: tab.tls,
        raw_b64: rawToB64(tab.raw),
        update_content_length: updateLength,
        log: true,
      })
      setResults((prev) => ({ ...prev, [tab.id]: { result, sending: false } }))
      if (!result.ok) showToast(result.error ?? 'Request failed', 'error')
    } catch (error) {
      const message = error instanceof ApiError ? error.message : String(error)
      setResults((prev) => ({ ...prev, [tab.id]: { result: null, sending: false } }))
      showToast(`Send failed: ${message}`, 'error')
    }
  }

  const stepHistory = (delta: number) => {
    if (!tab || tab.history.length === 0) return
    const current = historyIndex[tab.id] ?? tab.history.length
    const next = Math.min(tab.history.length - 1, Math.max(0, current + delta))
    setHistoryIndex((prev) => ({ ...prev, [tab.id]: next }))
    patchTab(tab.id, { raw: tab.history[next].raw })
  }

  if (!repeaterLoaded) {
    return <div className="empty"><p>Loading this project's Repeater tabs…</p></div>
  }
  if (!tab) return null

  const state = results[tab.id] ?? { result: null, sending: false }
  const responseRaw = b64ToRaw(state.result?.raw_response_b64 ?? null)

  return (
    <div className="pane">
      <div className="rtabs">
        {repeaterTabs.map((entry) => (
          <button
            key={entry.id}
            className={`rtab${entry.id === tab.id ? ' active' : ''}`}
            onClick={() => setActiveRepeaterTab(entry.id)}
            onDoubleClick={() => {
              const name = window.prompt('Rename tab', entry.name)
              if (name) patchTab(entry.id, { name })
            }}
            title="Double-click to rename"
          >
            {entry.name}
            <span
              className="x"
              role="button"
              tabIndex={-1}
              onClick={(event) => {
                event.stopPropagation()
                closeTab(entry.id)
              }}
            >
              ×
            </span>
          </button>
        ))}
        <button className="rtab" onClick={addTab} title="New tab">+</button>
      </div>

      <div className="toolbar tight">
        <button className="primary" onClick={() => void send()} disabled={state.sending}>
          {state.sending ? 'Sending…' : 'Send'}
        </button>
        <label className="field">
          Host
          <input
            type="text"
            className="w-md mono"
            value={tab.host}
            placeholder="example.com"
            onChange={(event) => patchTab(tab.id, { host: event.target.value })}
          />
        </label>
        <label className="field">
          Port
          <input
            type="number"
            className="w-xs mono"
            value={tab.port}
            onChange={(event) => patchTab(tab.id, { port: Number(event.target.value) || 0 })}
          />
        </label>
        <label className="toggle">
          <input
            type="checkbox"
            checked={tab.tls}
            onChange={(event) => patchTab(tab.id, {
              tls: event.target.checked,
              // Follow the conventional port unless it was customised.
              port: event.target.checked
                ? (tab.port === 80 ? 443 : tab.port)
                : (tab.port === 443 ? 80 : tab.port),
            })}
          />
          HTTPS
        </label>
        <label className="toggle" title="Recalculate Content-Length before sending">
          <input
            type="checkbox"
            checked={updateLength}
            onChange={(event) => setUpdateLength(event.target.checked)}
          />
          Fix Content-Length
        </label>

        <span className="spacer" />

        <button className="sm" disabled={tab.history.length === 0} onClick={() => stepHistory(-1)}>
          ‹ Prev
        </button>
        <button className="sm" disabled={tab.history.length === 0} onClick={() => stepHistory(1)}>
          Next ›
        </button>
        <button
          className="sm ghost"
          onClick={() => sendToIntruder({
            host: tab.host, port: tab.port, tls: tab.tls, raw: tab.raw,
            label: `${tab.name}`,
          })}
        >
          → Intruder
        </button>
      </div>

      <Split initial={0.5} storageKey="repeater">
        <RawEditor
          title="Request"
          value={tab.raw}
          onChange={(value) => patchTab(tab.id, { raw: value })}
          onSubmit={() => void send()}
          toolbar={
            <span className="dim" style={{ fontWeight: 400, textTransform: 'none' }}>
              Ctrl+Enter to send · first line ends HTTP/2 to send over HTTP/2
            </span>
          }
        />
        {state.result || state.sending ? (
          <MessageViewer
            title="Response"
            raw={responseRaw}
            decodedBody={
              state.result?.decoded_body_b64 ? b64ToRaw(state.result.decoded_body_b64) : null
            }
            status={
              state.sending ? (
                <span>sending…</span>
              ) : state.result?.error ? (
                <span className="err">{state.result.error}</span>
              ) : (
                <>
                  <span className={`s${Math.floor((state.result?.status ?? 0) / 100)}xx`}>
                    {state.result?.status} {state.result?.reason}
                  </span>
                  {state.result?.protocol === 'h2' && <span className="tag h2">h2</span>}
                  <span>{Math.round(state.result?.duration_ms ?? 0)} ms</span>
                </>
              )
            }
          />
        ) : (
          <div className="empty">
            <h4>No response yet</h4>
            <p>
              Edit the request on the left and press Send (or Ctrl+Enter). Requests
              sent here also appear in HTTP history, tagged <span className="tag">RPT</span>.
            </p>
          </div>
        )}
      </Split>
    </div>
  )
}
