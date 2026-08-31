import React, {
  createContext, useCallback, useContext, useEffect, useMemo, useRef, useState,
} from 'react'
import {
  api, defaultPayloadSet, FlowRow, PendingItem, Project, RepeaterTabRecord,
  Settings, SettingsInfo, Status, VpnStatus, type AttackType, type PayloadSet,
} from './api'
import { b64ToRaw, rawToB64 } from './raw'

/** A request handed off to Repeater or Intruder from elsewhere in the app. */
export interface Handoff {
  host: string
  port: number
  tls: boolean
  raw: string
  label: string
}

export interface RepeaterTab {
  id: string
  name: string
  host: string
  port: number
  tls: boolean
  raw: string
  history: { raw: string; at: number }[]
}

export interface IntruderState {
  host: string
  port: number
  tls: boolean
  template: string
  attackType: AttackType
  payloadSets: PayloadSet[]
  concurrency: number
  delayMs: number
  maxRequests: number
  updateContentLength: boolean
  urlEncode: boolean
  grepMatch: string
  activeAttackId: string | null
}

type WsListener = (type: string, data: unknown) => void

interface AppContextValue {
  status: Status | null
  /** Effective settings: system defaults with the active project's overrides. */
  settings: Settings | null
  settingsInfo: SettingsInfo | null
  /** Live VPN state, shared by the top bar and the VPN card. */
  vpnStatus: VpnStatus | null
  connected: boolean
  pending: PendingItem[]
  toast: { text: string; kind: 'ok' | 'error' } | null
  showToast: (text: string, kind?: 'ok' | 'error') => void
  refreshStatus: () => Promise<void>
  refreshSettings: () => Promise<void>
  saveProjectSettings: (patch: Record<string, unknown>) => Promise<void>
  saveSystemSettings: (patch: Partial<Settings>) => Promise<void>
  subscribe: (listener: WsListener) => () => void

  projects: Project[]
  activeProjectId: string | null
  activeProject: Project | null
  /** Bumps whenever the active project changes, so views can refetch. */
  projectEpoch: number
  refreshProjects: () => Promise<void>
  selectProject: (id: string) => Promise<void>
  createProject: (name: string, copyFrom?: string, temporary?: boolean) => Promise<void>
  keepProject: (id: string) => Promise<void>
  renameProject: (id: string, name: string) => Promise<void>
  deleteProject: (id: string) => Promise<void>

  repeaterTabs: RepeaterTab[]
  setRepeaterTabs: React.Dispatch<React.SetStateAction<RepeaterTab[]>>
  repeaterLoaded: boolean
  activeRepeaterTab: string | null
  setActiveRepeaterTab: (id: string) => void

  intruder: IntruderState
  setIntruder: React.Dispatch<React.SetStateAction<IntruderState>>
  sendToRepeater: (handoff: Handoff) => void
  sendToIntruder: (handoff: Handoff) => void
  navigate: (tab: string) => void
  activeTab: string
  subTab: string
  setSubTab: (sub: string) => void
}

const AppContext = createContext<AppContextValue | null>(null)

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useApp must be used inside AppProvider')
  return ctx
}

const BLANK_REQUEST = 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'

function blankTab(seq: number, handoff?: Handoff): RepeaterTab {
  return {
    id: `r${seq}-${Date.now().toString(36)}`,
    name: handoff?.label ?? `Tab ${seq}`,
    host: handoff?.host ?? '',
    port: handoff?.port ?? 80,
    tls: handoff?.tls ?? false,
    raw: handoff?.raw ?? BLANK_REQUEST,
    history: [],
  }
}

const initialIntruder: IntruderState = {
  host: '',
  port: 80,
  tls: false,
  template: '',
  attackType: 'sniper',
  payloadSets: [defaultPayloadSet()],
  concurrency: 8,
  delayMs: 0,
  maxRequests: 20000,
  updateContentLength: true,
  urlEncode: true,
  grepMatch: '',
  activeAttackId: null,
}

/** Tabs live in the URL hash so a view survives a reload and can be linked. */
function readHash(): [string, string] {
  const raw = window.location.hash.replace(/^#\/?/, '')
  const [main, sub] = raw.split('/')
  return [main || 'proxy', sub || '']
}

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<Status | null>(null)
  const [settingsInfo, setSettingsInfo] = useState<SettingsInfo | null>(null)
  const [connected, setConnected] = useState(false)
  const [pending, setPending] = useState<PendingItem[]>([])
  const [toast, setToast] = useState<{ text: string; kind: 'ok' | 'error' } | null>(null)
  const [route, setRoute] = useState<[string, string]>(readHash)

  const [projects, setProjects] = useState<Project[]>([])
  const [activeProjectId, setActiveProjectId] = useState<string | null>(null)
  const [projectEpoch, setProjectEpoch] = useState(0)

  const [repeaterTabs, setRepeaterTabs] = useState<RepeaterTab[]>([])
  const [repeaterLoaded, setRepeaterLoaded] = useState(false)
  const [activeRepeaterTab, setActiveRepeaterTab] = useState<string | null>(null)
  const [intruder, setIntruder] = useState<IntruderState>(initialIntruder)
  const tabSeq = useRef(0)

  const listeners = useRef(new Set<WsListener>())

  const showToast = useCallback((text: string, kind: 'ok' | 'error' = 'ok') => {
    setToast({ text, kind })
    window.setTimeout(() => setToast(null), kind === 'error' ? 6000 : 2800)
  }, [])

  const subscribe = useCallback((listener: WsListener) => {
    listeners.current.add(listener)
    return () => listeners.current.delete(listener)
  }, [])

  // ---------------------------------------------------------------- routing
  useEffect(() => {
    const onHashChange = () => setRoute(readHash())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  const setActiveTab = useCallback((tab: string) => {
    window.location.hash = `#${tab}`
  }, [])

  const setSubTab = useCallback((sub: string) => {
    setRoute(([main]) => {
      window.location.hash = `#${main}/${sub}`
      return [main, sub]
    })
  }, [])

  // --------------------------------------------------------------- fetching
  const refreshStatus = useCallback(async () => {
    try {
      const next = await api.status()
      setStatus(next)
      setActiveProjectId(next.project.id)
    } catch {
      /* the status poll is advisory; the WebSocket carries live state */
    }
  }, [])

  const refreshSettings = useCallback(async () => {
    try {
      setSettingsInfo(await api.getSettings())
    } catch {
      showToast('Could not load settings', 'error')
    }
  }, [showToast])

  const refreshProjects = useCallback(async () => {
    try {
      const listing = await api.projects()
      setProjects(listing.items)
      setActiveProjectId(listing.active_id)
    } catch {
      showToast('Could not load projects', 'error')
    }
  }, [showToast])

  // ------------------------------------------------------- repeater tabs I/O
  const loadRepeaterTabs = useCallback(async () => {
    setRepeaterLoaded(false)
    try {
      const stored = (await api.repeaterTabs()).items
      const tabs: RepeaterTab[] = stored.map((tab) => ({
        id: tab.id,
        name: tab.name,
        host: tab.host,
        port: tab.port,
        tls: tab.tls,
        raw: b64ToRaw(tab.raw_b64) || BLANK_REQUEST,
        history: tab.trail.map((raw) => ({ raw: b64ToRaw(raw), at: 0 })),
      }))
      if (tabs.length === 0) {
        tabSeq.current = 1
        tabs.push(blankTab(1))
      }
      setRepeaterTabs(tabs)
      setActiveRepeaterTab(tabs[0].id)
    } catch {
      setRepeaterTabs([blankTab(1)])
    } finally {
      setRepeaterLoaded(true)
    }
  }, [])

  // Persist tabs shortly after they settle, so typing is not a write per key.
  const saveTimer = useRef<number | undefined>(undefined)
  useEffect(() => {
    if (!repeaterLoaded) return
    if (saveTimer.current) window.clearTimeout(saveTimer.current)
    saveTimer.current = window.setTimeout(() => {
      const payload: RepeaterTabRecord[] = repeaterTabs.map((tab) => ({
        id: tab.id,
        name: tab.name,
        host: tab.host,
        port: tab.port,
        tls: tab.tls,
        raw_b64: rawToB64(tab.raw),
        trail: tab.history.slice(-25).map((entry) => rawToB64(entry.raw)),
      }))
      void api.saveRepeaterTabs(payload).catch(() => undefined)
    }, 900)
    return () => {
      if (saveTimer.current) window.clearTimeout(saveTimer.current)
    }
  }, [repeaterTabs, repeaterLoaded])

  // ------------------------------------------------------- project switching
  const adoptProject = useCallback(async () => {
    // Held messages are deliberately NOT cleared: interception belongs to the
    // shared listener, and dropping them from view would leave a browser
    // connection hanging with no way to forward it.
    setIntruder((prev) => ({ ...prev, activeAttackId: null }))
    await Promise.all([refreshSettings(), refreshProjects(), refreshStatus()])
    await loadRepeaterTabs()
    setProjectEpoch((n) => n + 1)
  }, [refreshSettings, refreshProjects, refreshStatus, loadRepeaterTabs])

  const selectProject = useCallback(async (id: string) => {
    if (id === activeProjectId) return
    try {
      const result = await api.activateProject(id)
      setActiveProjectId(result.active_id)
      await adoptProject()
      showToast(`Opened project "${result.project.name}"`)
    } catch (error) {
      showToast(`Could not open project: ${String(error)}`, 'error')
    }
  }, [activeProjectId, adoptProject, showToast])

  const createProject = useCallback(async (
    name: string, copyFrom?: string, temporary = false,
  ) => {
    try {
      const result = await api.createProject(name, copyFrom, temporary)
      setActiveProjectId(result.active_id)
      await adoptProject()
      showToast(`Created project "${result.project.name}"`)
    } catch (error) {
      showToast(`Could not create project: ${String(error)}`, 'error')
    }
  }, [adoptProject, showToast])

  const keepProject = useCallback(async (id: string) => {
    try {
      await api.keepProject(id)
      await refreshProjects()
      showToast('Project kept — it will survive a restart')
    } catch (error) {
      showToast(`Could not keep project: ${String(error)}`, 'error')
    }
  }, [refreshProjects, showToast])

  const renameProject = useCallback(async (id: string, name: string) => {
    try {
      await api.patchProject(id, { name })
      await refreshProjects()
      await refreshStatus()
    } catch (error) {
      showToast(`Could not rename: ${String(error)}`, 'error')
    }
  }, [refreshProjects, refreshStatus, showToast])

  const deleteProject = useCallback(async (id: string) => {
    try {
      const result = await api.deleteProject(id)
      if (result.active_id !== activeProjectId) {
        setActiveProjectId(result.active_id)
        await adoptProject()
      } else {
        await refreshProjects()
      }
      showToast('Project deleted')
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      showToast(message, 'error')
    }
  }, [activeProjectId, adoptProject, refreshProjects, showToast])

  // ----------------------------------------------------------- settings I/O
  const saveProjectSettings = useCallback(async (patch: Record<string, unknown>) => {
    const info = await api.putProjectSettings(patch)
    setSettingsInfo(info)
    void refreshProjects()
  }, [refreshProjects])

  const saveSystemSettings = useCallback(async (patch: Partial<Settings>) => {
    const result = await api.putSystemSettings(patch)
    setSettingsInfo(result)
    if (result.restarted) showToast('Proxy listener restarted')
  }, [showToast])

  // -------------------------------------------------------------- bootstrap
  useEffect(() => {
    void (async () => {
      await Promise.all([refreshStatus(), refreshSettings(), refreshProjects()])
      await loadRepeaterTabs()
      api.intercepts().then((r) => setPending(r.items)).catch(() => undefined)
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Live event feed, with automatic reconnect.
  useEffect(() => {
    let socket: WebSocket | null = null
    let retry: number | undefined
    let closed = false

    const connect = () => {
      const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws'
      socket = new WebSocket(`${scheme}://${window.location.host}/ws`)

      socket.onopen = () => {
        setConnected(true)
        void refreshStatus()
        api.intercepts().then((r) => setPending(r.items)).catch(() => undefined)
      }
      socket.onclose = () => {
        setConnected(false)
        if (!closed) retry = window.setTimeout(connect, 1500)
      }
      socket.onerror = () => socket?.close()
      socket.onmessage = (event) => {
        let parsed: { type: string; data: unknown }
        try {
          parsed = JSON.parse(event.data as string)
        } catch {
          return
        }
        const { type, data } = parsed

        if (type === 'intercept_request' || type === 'intercept_response') {
          setPending((prev) => [...prev, data as PendingItem])
        } else if (type === 'intercept_resolved') {
          const { id } = data as { id: string }
          setPending((prev) => prev.filter((item) => item.id !== id))
        } else if (type === 'settings_changed') {
          void refreshSettings()
        } else if (type === 'projects_changed') {
          void refreshProjects()
        } else if (type === 'project_changed') {
          // Another client switched project; follow it so views stay truthful.
          const payload = data as { active_id: string }
          setActiveProjectId((current) => {
            if (current !== null && current !== payload.active_id) void adoptProject()
            return payload.active_id
          })
        } else if (type === 'vpn_state') {
          setStatus((prev) => (prev ? { ...prev, vpn: data as VpnStatus } : prev))
        } else if (type === 'proxy_state' || type === 'hello') {
          setStatus((prev) => (prev ? { ...prev, proxy: data as Status['proxy'] } : prev))
        }

        for (const listener of listeners.current) listener(type, data)
      }
    }

    connect()
    return () => {
      closed = true
      if (retry) window.clearTimeout(retry)
      socket?.close()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshStatus, refreshSettings, refreshProjects])

  // Keep the aggregate counters fresh without leaning on the event stream.
  useEffect(() => {
    const timer = window.setInterval(() => void refreshStatus(), 5000)
    return () => window.clearInterval(timer)
  }, [refreshStatus])

  const sendToRepeater = useCallback((handoff: Handoff) => {
    tabSeq.current += 1
    const tab = blankTab(tabSeq.current, handoff)
    setRepeaterTabs((prev) => [...prev, tab])
    setActiveRepeaterTab(tab.id)
    setActiveTab('repeater')
    showToast(`Sent to Repeater: ${handoff.label}`)
  }, [setActiveTab, showToast])

  const sendToIntruder = useCallback((handoff: Handoff) => {
    setIntruder((prev) => ({
      ...prev,
      host: handoff.host,
      port: handoff.port,
      tls: handoff.tls,
      template: handoff.raw,
      activeAttackId: null,
    }))
    setActiveTab('intruder')
    showToast(`Sent to Intruder: ${handoff.label}`)
  }, [setActiveTab, showToast])

  const activeProject = useMemo(
    () => projects.find((p) => p.id === activeProjectId) ?? null,
    [projects, activeProjectId],
  )

  const value = useMemo<AppContextValue>(() => ({
    status,
    settings: settingsInfo?.effective ?? null,
    settingsInfo,
    vpnStatus: status?.vpn ?? null,
    connected, pending, toast, showToast,
    refreshStatus, refreshSettings, saveProjectSettings, saveSystemSettings, subscribe,
    projects, activeProjectId, activeProject, projectEpoch,
    refreshProjects, selectProject, createProject, keepProject, renameProject,
    deleteProject,
    repeaterTabs, setRepeaterTabs, repeaterLoaded,
    activeRepeaterTab: activeRepeaterTab ?? repeaterTabs[0]?.id ?? null,
    setActiveRepeaterTab,
    intruder, setIntruder, sendToRepeater, sendToIntruder,
    navigate: setActiveTab, activeTab: route[0], subTab: route[1], setSubTab,
  }), [
    status, settingsInfo, connected, pending, toast, showToast, refreshStatus,
    refreshSettings, saveProjectSettings, saveSystemSettings, subscribe,
    projects, activeProjectId, activeProject, projectEpoch, refreshProjects,
    selectProject, createProject, keepProject, renameProject, deleteProject,
    repeaterTabs, repeaterLoaded, activeRepeaterTab, intruder,
    sendToRepeater, sendToIntruder, setActiveTab, route, setSubTab,
  ])

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>
}

/** Convenience hook for views that append live flow rows. */
export function useFlowStream(onFlow: (type: string, row: Partial<FlowRow>) => void) {
  const { subscribe } = useApp()
  const handler = useRef(onFlow)
  handler.current = onFlow
  useEffect(() => subscribe((type, data) => {
    if (type === 'flow_new' || type === 'flow_update' || type === 'history_cleared') {
      handler.current(type, (data ?? {}) as Partial<FlowRow>)
    }
  }), [subscribe])
}
