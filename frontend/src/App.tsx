import { History } from './views/History'
import { Intercept } from './views/Intercept'
import { Intruder } from './views/Intruder'
import { Repeater } from './views/Repeater'
import { Sitemap } from './views/Sitemap'
import { ProjectSettings, SystemSettings } from './views/Settings'
import { Sidebar } from './components/Sidebar'
import { VpnBadge } from './components/VpnBadge'
import { useApp } from './store'

type ProxyTab = 'intercept' | 'history' | 'options'

const MAIN_TABS = [
  { id: 'proxy', label: 'Proxy' },
  { id: 'sitemap', label: 'Sitemap' },
  { id: 'repeater', label: 'Repeater' },
  { id: 'intruder', label: 'Intruder' },
]

export default function App() {
  const {
    activeTab, navigate, status, pending, toast, settings, subTab, setSubTab,
    activeProject, vpnStatus,
  } = useApp()

  const proxyTab = (['intercept', 'history', 'options'].includes(subTab)
    ? subTab
    : 'intercept') as ProxyTab

  const proxy = status?.proxy
  const interceptOn = settings?.intercept_enabled ?? false
  const onSettings = activeTab === 'settings'

  return (
    <div className="app">
      <Sidebar />

      <div className="main">
        <header className="topbar">
          <nav className="maintabs">
            {MAIN_TABS.map((tab) => (
              <button
                key={tab.id}
                className={`maintab${activeTab === tab.id ? ' active' : ''}`}
                onClick={() => navigate(tab.id)}
              >
                {tab.label}
                {tab.id === 'proxy' && pending.length > 0 && (
                  <span className="badge">{pending.length}</span>
                )}
              </button>
            ))}
            {onSettings && (
              <button className="maintab active">System settings</button>
            )}
          </nav>

          <div className="topbar-right">
            <span
              className={`project-chip${activeProject?.temporary ? ' temp' : ''}`}
              title={activeProject?.temporary
                ? 'Temporary project — its history, sitemap, Repeater tabs and '
                  + 'Intruder results are discarded when BRUP restarts. '
                  + 'Press "keep" beside it in the sidebar to make it permanent.'
                : 'Active project'}
            >
              {activeProject?.temporary && '⏱ '}
              {activeProject?.name ?? '…'}
            </span>
            {proxy && (
              <div className="counters">
                <span><b>{proxy.requests.toLocaleString()}</b> req</span>
                <span><b>{proxy.responses.toLocaleString()}</b> resp</span>
                {proxy.dropped > 0 && <span><b>{proxy.dropped}</b> dropped</span>}
                {proxy.errors > 0 && <span className="err"><b>{proxy.errors}</b> errors</span>}
              </div>
            )}
            <VpnBadge status={vpnStatus} onClick={() => navigate('settings')} />
            <span
              className="tag"
              style={{
                background: interceptOn ? 'var(--accent)' : undefined,
                color: interceptOn ? '#fff' : undefined,
              }}
              title="Toggle on the Proxy → Intercept tab"
            >
              intercept {interceptOn ? 'on' : 'off'}
            </span>
          </div>
        </header>

        <div className="content">
          {activeTab === 'proxy' && (
            <>
              <div className="subtabs">
                {([
                  ['intercept', pending.length ? `Intercept (${pending.length})` : 'Intercept'],
                  ['history', 'HTTP history'],
                  ['options', 'Project settings'],
                ] as [ProxyTab, string][]).map(([id, label]) => (
                  <button
                    key={id}
                    className={`subtab${proxyTab === id ? ' active' : ''}`}
                    onClick={() => setSubTab(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>
              {proxyTab === 'intercept' && <Intercept />}
              {proxyTab === 'history' && <History />}
              {proxyTab === 'options' && <ProjectSettings />}
            </>
          )}

          {activeTab === 'sitemap' && <Sitemap />}
          {activeTab === 'repeater' && <Repeater />}
          {activeTab === 'intruder' && <Intruder />}
          {onSettings && <SystemSettings />}
        </div>
      </div>

      {toast && <div className={`toast${toast.kind === 'error' ? ' error' : ''}`}>{toast.text}</div>}
    </div>
  )
}
