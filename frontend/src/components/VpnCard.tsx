import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, VpnConfigInfo, VpnProfile, VpnStatus } from '../api'
import { useApp } from '../store'

const STATE_COLOUR: Record<VpnStatus['state'], string> = {
  disconnected: 'var(--text-faint)',
  connecting: 'var(--yellow)',
  connected: 'var(--green)',
  failed: 'var(--red)',
}

export function VpnCard() {
  const {
    showToast, settingsInfo, saveSystemSettings, subscribe, vpnStatus, refreshStatus,
  } = useApp()

  // The status lives in the store so the top bar and this card cannot disagree.
  const status = vpnStatus
  const [profiles, setProfiles] = useState<VpnProfile[]>([])
  const [log, setLog] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const [showLog, setShowLog] = useState(false)

  const [importing, setImporting] = useState(false)
  const [name, setName] = useState('')
  const [config, setConfig] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [inspected, setInspected] = useState<VpnConfigInfo | null>(null)
  const [inspectError, setInspectError] = useState<string | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  const refresh = useCallback(async () => {
    try {
      const data = await api.vpn()
      setProfiles(data.profiles)
      setLog(data.log)
    } catch {
      /* the card is informational; a failed poll is not worth a toast */
    }
    await refreshStatus()
  }, [refreshStatus])

  useEffect(() => { void refresh() }, [refresh])

  useEffect(() => subscribe((type) => {
    if (type === 'vpn_profiles_changed') void refresh()
  }), [subscribe, refresh])

  // Poll while a tunnel is coming up, so the log fills in.
  useEffect(() => {
    if (status?.state !== 'connecting') return
    const timer = window.setInterval(() => void refresh(), 1200)
    return () => window.clearInterval(timer)
  }, [status?.state, refresh])

  // Debounced inspection of whatever has been pasted.
  useEffect(() => {
    if (!config.trim()) {
      setInspected(null)
      setInspectError(null)
      return
    }
    const timer = window.setTimeout(() => {
      api.vpnInspect(config)
        .then((info) => {
          setInspected(info)
          setInspectError(null)
        })
        .catch((error) => {
          setInspected(null)
          setInspectError(error instanceof ApiError ? error.message : String(error))
        })
    }, 400)
    return () => window.clearTimeout(timer)
  }, [config])

  const act = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(true)
    try {
      await fn()
      await refresh()
    } catch (error) {
      showToast(
        `${label}: ${error instanceof ApiError ? error.message : String(error)}`,
        'error',
      )
      const tail = await api.vpnLog(80).catch(() => null)
      if (tail) {
        setLog(tail.lines)
        setShowLog(true)
      }
    } finally {
      setBusy(false)
    }
  }

  const importFile = async (file: File) => {
    setConfig(await file.text())
    if (!name.trim()) setName(file.name.replace(/\.(ovpn|conf)$/i, ''))
  }

  const save = async () => {
    await act('Could not save the profile', async () => {
      await api.vpnSaveProfile({ name, config, username, password })
      setImporting(false)
      setName('')
      setConfig('')
      setUsername('')
      setPassword('')
      setInspected(null)
      showToast('VPN profile saved')
    })
  }

  const required = settingsInfo?.system.vpn_required ?? false
  const autoconnect = settingsInfo?.system.vpn_autoconnect ?? ''
  const autoCheck = settingsInfo?.system.vpn_auto_check_exit_ip ?? true
  const checkUrl = settingsInfo?.system.vpn_exit_ip_url ?? ''
  const state = status?.state ?? 'disconnected'
  const activeProfile = profiles.find((p) => p.id === status?.active_profile_id)
  // Only a profile that is actually up (or coming up) counts as live. Keying
  // this off active_profile_id alone would hide Connect after a disconnect.
  const liveProfileId = state === 'connected' || state === 'connecting'
    ? status?.active_profile_id ?? null
    : null
  const canConnect = state === 'disconnected' || state === 'failed'

  return (
    <div className="card">
      <h3>
        VPN <span className="tag">system wide</span>
        <span className="spacer" />
        <span style={{ color: STATE_COLOUR[state], fontWeight: 600 }}>
          ● {state}
          {activeProfile && state !== 'disconnected' ? ` — ${activeProfile.name}` : ''}
        </span>
      </h3>
      <div className="card-body">
        <p className="hint">
          Brings a tunnel up inside BRUP's own network namespace, so every upstream
          connection the proxy makes goes through it. There is one namespace, so one
          tunnel at a time — this cannot differ per project. The web UI stays
          reachable because Docker's bridge keeps a more specific route.
        </p>

        {status?.tooling_missing && status.tooling_missing.length > 0 && (
          <p className="hint" style={{ color: 'var(--red)' }}>
            Missing in the container: <code>{status.tooling_missing.join(', ')}</code> —
            rebuild the image.
          </p>
        )}

        {/* -------------------------------------------------- kill switch */}
        <div className="setting">
          <div className="setting-head">
            <b>Require VPN (kill switch)</b>
            <select
              className="state"
              value={required ? 'on' : 'off'}
              onChange={(e) => void saveSystemSettings({
                vpn_required: e.target.value === 'on',
              })}
            >
              <option value="on">On</option>
              <option value="off">Off</option>
            </select>
            {required && state !== 'connected' && (
              <span className="tag" style={{ background: 'var(--red)', color: '#fff' }}>
                blocking all traffic
              </span>
            )}
          </div>
          <p className="hint">
            While this is on and the tunnel is not up, the proxy, Repeater and
            Intruder refuse to send anything rather than letting it out over your
            normal connection. Leave it on if traffic must never leak.
          </p>
        </div>

        <div className="setting">
          <div className="setting-head">
            <b>Check the exit address automatically</b>
            <select
              className="state"
              value={autoCheck ? 'on' : 'off'}
              onChange={(e) => void saveSystemSettings({
                vpn_auto_check_exit_ip: e.target.value === 'on',
              })}
            >
              <option value="on">On</option>
              <option value="off">Off</option>
            </select>
          </div>
          <p className="hint">
            Once a tunnel is up, asks{' '}
            <code>{checkUrl || '(no URL set)'}</code> which address your traffic
            appears to come from, and shows it in the top bar. It is one request to
            a third party, which is why it is a setting — clear the URL to disable
            the check entirely. The tunnel is unaffected either way.
          </p>
          <div className="row">
            <label className="field">
              Check URL
              <input
                type="text"
                className="w-lg mono"
                defaultValue={checkUrl}
                key={checkUrl}
                placeholder="https://api.ipify.org"
                onBlur={(e) => {
                  const next = e.target.value.trim()
                  if (next !== checkUrl) {
                    void saveSystemSettings({ vpn_exit_ip_url: next })
                  }
                }}
              />
            </label>
          </div>
        </div>

        {/* ----------------------------------------------------- profiles */}
        <div>
          <div className="row" style={{ marginBottom: 6 }}>
            <b style={{ fontSize: 12 }}>Profiles</b>
            <button className="sm" onClick={() => setImporting((prev) => !prev)}>
              {importing ? 'Cancel import' : '+ Import configuration'}
            </button>
            {state !== 'disconnected' && (
              <button
                className="sm danger"
                disabled={busy}
                onClick={() => void act('Disconnect failed', () => api.vpnDisconnect())}
                title={state === 'failed'
                  ? 'Clear the error and tidy up any half-built tunnel'
                  : 'Bring the tunnel down'}
              >
                {state === 'failed' ? 'Clear error' : 'Disconnect'}
              </button>
            )}
            {state === 'connected' && (
              <>
                <button
                  className="sm"
                  disabled={busy}
                  onClick={() => void act('Exit IP check failed', () => api.vpnCheck())}
                  title="Asks an external service which IP your traffic comes from"
                >
                  Check exit IP
                </button>
                {status?.exit_ip && (
                  <span className="mono dim">exit {status.exit_ip}</span>
                )}
              </>
            )}
            <span className="spacer" />
            <button className="sm ghost" onClick={() => setShowLog((prev) => !prev)}>
              {showLog ? 'Hide log' : 'Show log'}
            </button>
          </div>

          {status?.message && (
            <p className="hint" style={{ color: 'var(--red)' }}>{status.message}</p>
          )}

          {profiles.length === 0 ? (
            <p className="hint">
              No profiles yet. Import a <code>.ovpn</code> or WireGuard{' '}
              <code>.conf</code> file from your provider.
            </p>
          ) : (
            <table className="grid">
              <thead>
                <tr>
                  <th className="nosort">Name</th>
                  <th className="nosort">Type</th>
                  <th className="nosort">Endpoint</th>
                  <th className="nosort">Tunnel</th>
                  <th className="nosort">Auto</th>
                  <th className="nosort" style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {profiles.map((profile) => {
                  const live = profile.id === liveProfileId
                  return (
                    <tr key={profile.id} style={{ cursor: 'default' }}>
                      <td>
                        {profile.name}
                        {live && (
                          <span className="tag tls" style={{ marginLeft: 5 }}>
                            {state === 'connecting' ? 'connecting' : 'active'}
                          </span>
                        )}
                      </td>
                      <td className="dim">{profile.kind}</td>
                      <td className="mono dim">{profile.endpoints.join(', ') || '—'}</td>
                      <td className={profile.full_tunnel ? '' : 'dim'}>
                        {profile.full_tunnel
                          ? 'full'
                          : <span style={{ color: 'var(--yellow)' }}>split</span>}
                      </td>
                      <td>
                        <input
                          type="checkbox"
                          title="Connect this profile when BRUP starts"
                          checked={autoconnect === profile.id}
                          onChange={(e) => void saveSystemSettings({
                            vpn_autoconnect: e.target.checked ? profile.id : '',
                          })}
                        />
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {live ? (
                          <button
                            className="sm danger"
                            disabled={busy}
                            onClick={() => void act('Disconnect failed',
                              () => api.vpnDisconnect())}
                          >
                            Disconnect
                          </button>
                        ) : (
                          <button
                            className="sm"
                            disabled={busy || !canConnect}
                            title={canConnect
                              ? 'Bring this tunnel up'
                              : 'Another tunnel is up — disconnect it first'}
                            onClick={() => void act('Connect failed',
                              () => api.vpnConnect(profile.id))}
                          >
                            Connect
                          </button>
                        )}
                        <button
                          className="sm ghost"
                          disabled={busy || live}
                          onClick={async () => {
                            if (!window.confirm(`Delete VPN profile "${profile.name}"?`)) return
                            await act('Delete failed', () => api.vpnDeleteProfile(profile.id))
                          }}
                        >
                          ×
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* ------------------------------------------------------- import */}
        {importing && (
          <div className="card" style={{ margin: 0, background: 'var(--bg-3)' }}>
            <h3>Import an OpenVPN or WireGuard configuration</h3>
            <div className="card-body">
              <div className="row">
                <label className="field">
                  Name
                  <input
                    type="text" className="w-md" value={name}
                    placeholder="Provider — Netherlands"
                    onChange={(e) => setName(e.target.value)}
                  />
                </label>
                <button className="sm" onClick={() => fileInput.current?.click()}>
                  Load from file…
                </button>
                <input
                  ref={fileInput}
                  type="file"
                  accept=".ovpn,.conf,.txt,text/plain"
                  style={{ display: 'none' }}
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) void importFile(file)
                    e.target.value = ''
                  }}
                />
              </div>

              <textarea
                className="mono" rows={10} spellCheck={false}
                placeholder={'Paste the contents of a .ovpn or WireGuard .conf file'}
                value={config}
                onChange={(e) => setConfig(e.target.value)}
              />

              {inspectError && (
                <p className="hint" style={{ color: 'var(--red)' }}>{inspectError}</p>
              )}
              {inspected && (
                <dl className="kv">
                  <dt>Detected</dt><dd>{inspected.kind}</dd>
                  <dt>Endpoint</dt><dd>{inspected.endpoints.join(', ') || '—'}</dd>
                  <dt>Tunnel</dt>
                  <dd style={{ color: inspected.full_tunnel ? undefined : 'var(--yellow)' }}>
                    {inspected.full_tunnel
                      ? 'full — all traffic routed through the VPN'
                      : 'split — only some traffic routed through the VPN'}
                  </dd>
                  {inspected.address && <><dt>Address</dt><dd>{inspected.address}</dd></>}
                  {inspected.dns && <><dt>DNS</dt><dd>{inspected.dns}</dd></>}
                </dl>
              )}
              {inspected?.warnings.map((warning) => (
                <p className="hint" style={{ color: 'var(--yellow)' }} key={warning}>
                  ⚠ {warning}
                </p>
              ))}

              <div className="row">
                <label className="field">
                  Username
                  <input
                    type="text" className="w-md" value={username}
                    placeholder="(only if your provider needs it)"
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </label>
                <label className="field">
                  Password
                  <input
                    type="password" className="w-md" value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </label>
              </div>
              {inspected?.needs_credentials && !username && (
                <p className="hint" style={{ color: 'var(--yellow)' }}>
                  This configuration has <code>auth-user-pass</code>, so it will ask for
                  a username and password when connecting.
                </p>
              )}
              <p className="hint">
                Credentials are stored in the <code>/data</code> volume in plain text,
                like the CA key. Anyone with access to that volume can read them.
              </p>

              <div className="row">
                <button
                  className="primary"
                  disabled={busy || !name.trim() || !config.trim() || !!inspectError}
                  onClick={() => void save()}
                >
                  Save profile
                </button>
              </div>
            </div>
          </div>
        )}

        {showLog && (
          <>
            <b style={{ fontSize: 12 }}>Connection log</b>
            <textarea
              className="mono" readOnly rows={12}
              value={log.length ? log.join('\n') : '(nothing yet)'}
            />
          </>
        )}
      </div>
    </div>
  )
}
