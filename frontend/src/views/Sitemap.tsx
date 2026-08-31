import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, ApiError, FlowDetail, FlowRow, SiteNode } from '../api'
import { MessageViewer } from '../components/MessageViewer'
import { Split } from '../components/Split'
import { b64ToRaw } from '../raw'
import { useApp, useFlowStream } from '../store'

function statusClass(status: number | null | undefined) {
  return status ? `s${Math.floor(status / 100)}xx` : ''
}

function fmtBytes(n: number | null | undefined) {
  if (n == null) return ''
  if (n < 1024) return String(n)
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}K`
  return `${(n / 1024 / 1024).toFixed(1)}M`
}

/** The status worth showing on a folded-up branch: worst wins. */
function headlineStatus(statuses: number[]): number | null {
  if (statuses.length === 0) return null
  const bad = statuses.filter((s) => s >= 400)
  if (bad.length) return Math.max(...bad)
  return statuses[0]
}

function TreeRow({
  node, depth, expanded, onToggle, selectedKey, onSelect,
}: {
  node: SiteNode
  depth: number
  expanded: Set<string>
  onToggle: (key: string) => void
  selectedKey: string | null
  onSelect: (node: SiteNode) => void
}) {
  const hasChildren = node.children.length > 0
  const isOpen = expanded.has(node.key)
  const status = headlineStatus(node.statuses)

  return (
    <>
      <div
        className={`treerow${node.key === selectedKey ? ' active' : ''}`}
        style={{ paddingLeft: 6 + depth * 14 }}
        onClick={() => onSelect(node)}
      >
        <span
          className="caret"
          onClick={(event) => {
            event.stopPropagation()
            if (hasChildren) onToggle(node.key)
          }}
        >
          {hasChildren ? (isOpen ? '▾' : '▸') : '·'}
        </span>
        <span
          className={`tname${node.in_scope ? '' : ' dim'}`}
          title={node.url}
        >
          {node.name}
        </span>
        {node.methods.length > 0 && (
          <span className="tmethods">{node.methods.join(' ')}</span>
        )}
        {status != null && <span className={`tstatus ${statusClass(status)}`}>{status}</span>}
        <span className="badge quiet">{node.subtree_count}</span>
      </div>
      {isOpen && node.children.map((child) => (
        <TreeRow
          key={child.key}
          node={child}
          depth={depth + 1}
          expanded={expanded}
          onToggle={onToggle}
          selectedKey={selectedKey}
          onSelect={onSelect}
        />
      ))}
    </>
  )
}

export function Sitemap() {
  const {
    showToast, sendToRepeater, sendToIntruder, settings, subTab, setSubTab,
    projectEpoch,
  } = useApp()

  const [hosts, setHosts] = useState<SiteNode[]>([])
  const [truncated, setTruncated] = useState(false)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [selected, setSelected] = useState<SiteNode | null>(null)
  const [inScopeOnly, setInScopeOnly] = useState(false)
  const [recursive, setRecursive] = useState(true)
  const [loading, setLoading] = useState(false)

  const [items, setItems] = useState<FlowRow[]>([])
  const [itemTotal, setItemTotal] = useState(0)
  const [detail, setDetail] = useState<FlowDetail | null>(null)

  const load = useCallback(async (opts?: { keepSelection?: boolean }) => {
    setLoading(true)
    try {
      const map = await api.sitemap(inScopeOnly)
      setHosts(map.hosts)
      setTruncated(map.truncated)
      setExpanded((prev) => {
        if (prev.size > 0 || opts?.keepSelection) return prev
        // First load: open the hosts so the tree is not a wall of carets.
        return new Set(map.hosts.map((host) => host.key))
      })
    } catch (error) {
      showToast(`Could not load sitemap: ${String(error)}`, 'error')
    } finally {
      setLoading(false)
    }
  }, [inScopeOnly, showToast])

  useEffect(() => {
    // A project switch replaces the whole tree.
    setSelected(null)
    setItems([])
    setDetail(null)
    setExpanded(new Set())
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, projectEpoch])

  // Grow the tree as you browse, without hammering the endpoint.
  const pending = useRef<number | undefined>(undefined)
  useFlowStream((type) => {
    if (type === 'history_cleared') {
      setHosts([])
      setSelected(null)
      setItems([])
      setDetail(null)
      return
    }
    if (type !== 'flow_new') return
    if (pending.current) window.clearTimeout(pending.current)
    pending.current = window.setTimeout(() => void load({ keepSelection: true }), 1500)
  })
  useEffect(() => () => {
    if (pending.current) window.clearTimeout(pending.current)
  }, [])

  const loadItems = useCallback(async (node: SiteNode, deep: boolean) => {
    try {
      const result = await api.sitemapItems(node.origin, node.path, deep)
      setItems(result.items)
      setItemTotal(result.total)
    } catch (error) {
      showToast(`Could not load items: ${String(error)}`, 'error')
    }
  }, [showToast])

  const select = useCallback((node: SiteNode) => {
    setSelected(node)
    setDetail(null)
    setSubTab(encodeURIComponent(node.url))
    void loadItems(node, recursive)
  }, [recursive, loadItems, setSubTab])

  // Restore the node named in the URL once the tree is available.
  useEffect(() => {
    if (!subTab || hosts.length === 0) return
    let wanted: string
    try {
      wanted = decodeURIComponent(subTab)
    } catch {
      return
    }
    if (selected?.url === wanted) return

    const stack: SiteNode[] = [...hosts]
    let found: SiteNode | null = null
    while (stack.length) {
      const node = stack.pop()!
      if (node.url === wanted) {
        found = node
        break
      }
      stack.push(...node.children)
    }
    if (!found) return

    // Open every ancestor so the node is actually visible in the tree.
    const keys = [found.origin]
    let walked = ''
    for (const segment of found.path.split('/').filter(Boolean)) {
      walked += `/${segment}`
      keys.push(found.origin + walked)
    }
    setExpanded((prev) => new Set([...prev, ...keys]))
    setSelected(found)
    void loadItems(found, recursive)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [subTab, hosts])

  useEffect(() => {
    if (selected) void loadItems(selected, recursive)
  }, [recursive, selected, loadItems])

  const toggle = (key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const allKeys = useMemo(() => {
    const keys: string[] = []
    const walk = (nodes: SiteNode[]) => {
      for (const node of nodes) {
        if (node.children.length) keys.push(node.key)
        walk(node.children)
      }
    }
    walk(hosts)
    return keys
  }, [hosts])

  const openItem = async (id: number) => {
    try {
      setDetail(await api.historyItem(id))
    } catch (error) {
      showToast(error instanceof ApiError ? error.message : String(error), 'error')
    }
  }

  const scope = async (kind: 'include' | 'exclude', wholeHost: boolean) => {
    if (!selected) return
    try {
      const result = await api.addToScope({
        origin: selected.origin,
        path: selected.path,
        kind,
        whole_host: wholeHost,
      })
      showToast(result.added
        ? `Added to ${kind} scope: ${result.pattern}`
        : `Already in ${kind} scope`)
      void load({ keepSelection: true })
    } catch (error) {
      showToast(error instanceof ApiError ? error.message : String(error), 'error')
    }
  }

  const handoff = detail && {
    host: detail.host,
    port: detail.port,
    tls: Boolean(detail.tls),
    raw: b64ToRaw(detail.raw_request_b64),
    label: `${detail.method ?? '?'} ${detail.host}`,
  }

  const totalItems = hosts.reduce((sum, host) => sum + host.subtree_count, 0)

  return (
    <div className="pane">
      <div className="toolbar tight">
        <button className="sm" onClick={() => void load({ keepSelection: true })}>
          {loading ? 'Loading…' : 'Refresh'}
        </button>
        <button className="sm" onClick={() => setExpanded(new Set(allKeys))}>Expand all</button>
        <button className="sm" onClick={() => setExpanded(new Set())}>Collapse all</button>
        <label className="toggle">
          <input
            type="checkbox"
            checked={inScopeOnly}
            onChange={(event) => setInScopeOnly(event.target.checked)}
          />
          In scope only
        </label>

        <span className="spacer" />

        {selected && (
          <>
            <span className="dim mono" title={selected.url}>
              {selected.url.length > 60 ? `…${selected.url.slice(-60)}` : selected.url}
            </span>
            <button className="sm" onClick={() => void scope('include', true)}>
              + Host to scope
            </button>
            {selected.kind === 'path' && (
              <button className="sm" onClick={() => void scope('exclude', false)}>
                − Exclude branch
              </button>
            )}
          </>
        )}
        <span className="dim">
          {hosts.length} host{hosts.length === 1 ? '' : 's'} · {totalItems.toLocaleString()} items
          {truncated && <span style={{ color: 'var(--yellow)' }}> · truncated</span>}
        </span>
      </div>

      <Split initial={0.28} storageKey="sitemap">
        <div className="tree">
          {hosts.length === 0 ? (
            <div className="empty">
              <h4>Nothing mapped yet</h4>
              <p>
                {settings?.logging_enabled === false
                  ? 'History logging is off, so no traffic is being recorded.'
                  : 'Browse through the proxy and the hosts and paths you touch will appear here as a tree.'}
              </p>
            </div>
          ) : (
            hosts.map((host) => (
              <TreeRow
                key={host.key}
                node={host}
                depth={0}
                expanded={expanded}
                onToggle={toggle}
                selectedKey={selected?.key ?? null}
                onSelect={select}
              />
            ))
          )}
        </div>

        {selected ? (
          <Split vertical initial={0.42} storageKey="sitemap-detail">
            <div className="pane">
              <div className="panel-title">
                <span>Items</span>
                <label className="toggle" style={{ fontWeight: 400, textTransform: 'none' }}>
                  <input
                    type="checkbox"
                    checked={recursive}
                    onChange={(event) => setRecursive(event.target.checked)}
                  />
                  include sub-paths
                </label>
                <span className="spacer" />
                <span className="dim" style={{ fontWeight: 400 }}>
                  {items.length} of {itemTotal.toLocaleString()}
                </span>
              </div>
              <div className="table-wrap">
                <table className="grid">
                  <colgroup>
                    <col style={{ width: 58 }} />
                    <col style={{ width: 66 }} />
                    <col />
                    <col style={{ width: 62 }} />
                    <col style={{ width: 62 }} />
                    <col style={{ width: 52 }} />
                    <col style={{ width: 120 }} />
                    <col style={{ width: 70 }} />
                  </colgroup>
                  <thead>
                    <tr>
                      <th className="num nosort">#</th>
                      <th className="nosort">Method</th>
                      <th className="nosort">URL</th>
                      <th className="num nosort">Status</th>
                      <th className="num nosort">Len</th>
                      <th className="num nosort">ms</th>
                      <th className="nosort">Type</th>
                      <th className="nosort">Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr
                        key={item.id}
                        className={item.id === detail?.id ? 'selected' : ''}
                        onClick={() => void openItem(item.id)}
                      >
                        <td className="num dim">{item.id}</td>
                        <td className="mono">{item.method}</td>
                        <td className="mono" title={item.url ?? ''}>
                          {(item.url ?? '').slice(selected.origin.length) || '/'}
                        </td>
                        <td className={`num ${statusClass(item.status)}`}>{item.status ?? ''}</td>
                        <td className="num dim">{fmtBytes(item.resp_len)}</td>
                        <td className="num dim">
                          {item.duration_ms ? Math.round(item.duration_ms) : ''}
                        </td>
                        <td className="dim">{item.mime ?? ''}</td>
                        <td className="dim">{item.source}</td>
                      </tr>
                    ))}
                    {items.length === 0 && (
                      <tr>
                        <td colSpan={8} style={{ padding: 16, textAlign: 'center', color: 'var(--text-faint)' }}>
                          No logged items at this path.
                          {!recursive && ' Tick "include sub-paths" to see items below it.'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {detail ? (
              <div className="pane">
                <div className="toolbar tight">
                  <b className="mono" style={{ fontSize: 12 }}>
                    #{detail.id} {detail.method} {detail.url}
                  </b>
                  <span className="spacer" />
                  {handoff && (
                    <>
                      <button className="sm" onClick={() => sendToRepeater(handoff)}>
                        → Repeater
                      </button>
                      <button className="sm" onClick={() => sendToIntruder(handoff)}>
                        → Intruder
                      </button>
                    </>
                  )}
                </div>
                <Split initial={0.5} storageKey="sitemap-msg">
                  <MessageViewer title="Request" raw={b64ToRaw(detail.raw_request_b64)} />
                  <MessageViewer
                    title="Response"
                    raw={b64ToRaw(detail.raw_response_b64)}
                    decodedBody={
                      detail.decoded_body_b64 ? b64ToRaw(detail.decoded_body_b64) : null
                    }
                    status={detail.error ? <span className="err">{detail.error}</span> : null}
                  />
                </Split>
              </div>
            ) : (
              <div className="empty">
                <p>Select an item to see its request and response.</p>
              </div>
            )}
          </Split>
        ) : (
          <div className="empty">
            <h4>Select a host or path</h4>
            <p>
              The tree is built from HTTP history, so it covers everything the proxy
              has seen. Pick a node to list its requests, add it to scope, or send
              one on to Repeater or Intruder.
            </p>
          </div>
        )}
      </Split>
    </div>
  )
}
