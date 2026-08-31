/** Typed wrappers over the BRUP HTTP API. */

export interface ScopeRule { enabled: boolean; pattern: string }

export interface HeaderRule {
  enabled: boolean
  target: 'request' | 'response'
  action: 'set' | 'add' | 'remove'
  name: string
  value: string
}

export interface Settings {
  proxy_host: string
  proxy_port: number
  invisible_proxy: boolean
  invisible_tls_enabled: boolean
  invisible_tls_port: number
  invisible_default_host: string
  intercept_enabled: boolean
  intercept_requests: boolean
  intercept_responses: boolean
  intercept_skip_extensions: string[]
  scope_include: ScopeRule[]
  scope_exclude: ScopeRule[]
  header_rules: HeaderRule[]
  upstream_proxy: string
  upstream_verify_tls: boolean
  connect_timeout: number
  read_timeout: number
  tls_passthrough_hosts: string[]
  // VPN settings are system-only: one network namespace means one tunnel.
  vpn_required: boolean
  vpn_autoconnect: string
  vpn_override_dns: boolean
  vpn_exit_ip_url: string
  logging_enabled: boolean
  log_out_of_scope: boolean
  max_history: number
  max_stored_body: number
}

export interface Project {
  id: string
  name: string
  created: number
  updated: number
  notes: string
  overrides: Partial<Settings>
  flow_count: number
  attack_count: number
  /** Temporary projects are discarded when BRUP restarts. */
  temporary: boolean
}

/** Both settings tiers plus what the active project overrides. */
export interface SettingsInfo {
  effective: Settings
  system: Settings
  overrides: Partial<Settings>
  overridable_keys: (keyof Settings)[]
  project_id: string
}

export interface RepeaterTabRecord {
  id: string
  name: string
  host: string
  port: number
  tls: boolean
  raw_b64: string
  trail: string[]
}

export interface ProxyState {
  running: boolean
  listeners: string[]
  started_at: number | null
  requests: number
  responses: number
  dropped: number
  errors: number
  connections: number
  pending_intercepts: number
}

export interface VpnStatus {
  state: 'disconnected' | 'connecting' | 'connected' | 'failed'
  message: string
  kind: 'openvpn' | 'wireguard' | null
  active_profile_id: string | null
  connected_at: number | null
  interface: string
  exit_ip: string | null
  exit_ip_checked: number | null
  required: boolean
  tooling_missing: string[]
}

export interface Status {
  proxy: ProxyState
  project: Project
  vpn: VpnStatus
  ca: { fingerprint_sha256: string; not_valid_after: string }
  ui_clients: number
  server_time: number
}

export interface FlowRow {
  id: number
  ts: number
  source: string
  host: string
  port: number
  tls: number | boolean
  method: string | null
  target?: string | null
  url: string | null
  status: number | null
  reason?: string | null
  mime?: string | null
  req_len: number
  resp_len: number
  duration_ms: number | null
  was_edited?: number
  in_scope?: number
  notes?: string
  color?: string
  error?: string | null
}

export interface FlowDetail extends FlowRow {
  raw_request_b64: string | null
  raw_response_b64: string | null
  decoded_body_b64?: string | null
  decode_error?: string | null
}

export interface PendingItem {
  id: string
  kind: 'request' | 'response'
  project_id: string
  flow_id: number | null
  host: string
  port: number
  tls: boolean
  url: string
  method: string
  status: number | null
  created: number
  raw_b64: string
  length: number
}

export interface RepeaterResult {
  ok: boolean
  error: string | null
  duration_ms: number
  status: number | null
  reason: string | null
  length: number
  raw_response_b64: string | null
  decoded_body_b64?: string | null
  decode_error?: string | null
  flow_id: number | null
}

export type AttackType = 'sniper' | 'battering_ram' | 'pitchfork' | 'cluster_bomb'

export interface PayloadRule {
  kind: 'prefix' | 'suffix' | 'upper' | 'lower' | 'reverse' | 'strip'
    | 'url_encode' | 'url_encode_all' | 'base64' | 'hex' | 'md5' | 'sha1' | 'sha256'
  value: string
  enabled: boolean
}

export interface PayloadSet {
  kind: 'list' | 'numbers' | 'brute'
  payloads: string[]
  wordlist: string
  number_from: number
  number_to: number
  number_step: number
  charset: string
  min_length: number
  max_length: number
  rules: PayloadRule[]
}

export interface AttackConfig {
  host: string
  port: number
  tls: boolean
  template_b64: string
  attack_type: AttackType
  payload_sets: PayloadSet[]
  concurrency: number
  delay_ms: number
  update_content_length: boolean
  url_encode_payloads: boolean
  grep_match: string[]
  max_requests: number
  name: string
}

export interface AttackSummary {
  id: string
  name: string
  host: string
  port: number
  tls: boolean
  attack_type: AttackType
  positions: number
  total: number
  completed: number
  errors: number
  status: 'running' | 'paused' | 'finished' | 'stopped' | 'error'
  message: string
  created: number
}

export interface AttackPreview {
  positions: number
  position_bases: string[]
  set_sizes: number[]
  total: number
  capped_at: number
  will_send: number
  samples: { index: number; payloads: string[]; raw_b64: string }[]
}

export interface ResultRow {
  attack_id: string
  idx: number
  payloads: string[]
  position: number | null
  status: number | null
  reason: string | null
  resp_len: number | null
  words: number | null
  duration_ms: number | null
  error: string | null
  grep_hits: string[]
}

export interface ResultDetail extends ResultRow {
  raw_request_b64: string | null
  raw_response_b64: string | null
  decoded_body_b64?: string | null
}

export interface SiteNode {
  key: string
  name: string
  path: string
  origin: string
  host: string
  port: number
  tls: boolean
  kind: 'host' | 'path'
  count: number
  subtree_count: number
  methods: string[]
  statuses: number[]
  mime: string | null
  last_id: number | null
  in_scope: boolean
  url: string
  children: SiteNode[]
}

export interface Sitemap {
  hosts: SiteNode[]
  truncated: boolean
  rows_considered: number
}

export interface VpnConfigInfo {
  kind?: 'openvpn' | 'wireguard'
  endpoints: string[]
  full_tunnel: boolean
  needs_credentials: boolean
  warnings: string[]
  address?: string
  dns?: string
}

export interface VpnProfile extends VpnConfigInfo {
  id: string
  name: string
  kind: 'openvpn' | 'wireguard'
  notes: string
  created: number
  has_credentials: boolean
  username: string
}

export interface Wordlist { name: string; ts: number; lines: number }

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message)
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  })
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`
    try {
      const body = await response.json()
      if (typeof body.detail === 'string') detail = body.detail
      else if (body.detail) detail = JSON.stringify(body.detail)
    } catch {
      /* keep the status text */
    }
    throw new ApiError(detail, response.status)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

const post = <T>(path: string, body?: unknown) =>
  request<T>(path, { method: 'POST', body: body === undefined ? undefined : JSON.stringify(body) })

export const api = {
  status: () => request<Status>('/api/status'),

  getSettings: () => request<SettingsInfo>('/api/settings'),
  putSystemSettings: (patch: Partial<Settings>) =>
    request<SettingsInfo & { restarted: boolean; proxy: ProxyState }>(
      '/api/settings/system', { method: 'PUT', body: JSON.stringify(patch) },
    ),
  /** A null value clears that override, falling back to the system setting. */
  putProjectSettings: (patch: Record<string, unknown>) =>
    request<SettingsInfo & { project: Project }>(
      '/api/settings/project', { method: 'PUT', body: JSON.stringify(patch) },
    ),

  projects: () => request<{ active_id: string; items: Project[] }>('/api/projects'),
  createProject: (name: string, copy_settings_from?: string, temporary = false) =>
    post<{ project: Project; active_id: string }>('/api/projects', {
      name, copy_settings_from: copy_settings_from ?? null, temporary,
    }),
  keepProject: (id: string) => post<Project>(`/api/projects/${id}/keep`),
  activateProject: (id: string) =>
    post<{ project: Project; active_id: string }>(`/api/projects/${id}/activate`),
  patchProject: (id: string, body: { name?: string; notes?: string }) =>
    request<Project>(`/api/projects/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteProject: (id: string) =>
    request<{ deleted: string; active_id: string }>(`/api/projects/${id}`, {
      method: 'DELETE',
    }),

  repeaterTabs: () => request<{ items: RepeaterTabRecord[] }>('/api/repeater/tabs'),
  saveRepeaterTabs: (tabs: RepeaterTabRecord[]) =>
    request<{ ok: boolean; count: number }>('/api/repeater/tabs', {
      method: 'PUT', body: JSON.stringify(tabs),
    }),
  proxyControl: (action: 'start' | 'stop' | 'restart') =>
    post<ProxyState>(`/api/proxy/${action}`),

  history: (params: Record<string, string | number | boolean>) => {
    const qs = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (value !== '' && value !== undefined && value !== null) qs.set(key, String(value))
    }
    return request<{ total: number; items: FlowRow[] }>(`/api/history?${qs}`)
  },
  historyItem: (id: number) => request<FlowDetail>(`/api/history/${id}`),
  historyHosts: () => request<{ host: string; n: number }[]>('/api/history/hosts'),
  clearHistory: () => request<{ ok: boolean }>('/api/history', { method: 'DELETE' }),
  annotate: (id: number, body: { notes?: string; color?: string }) =>
    request(`/api/history/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),

  sitemap: (in_scope_only = false) =>
    request<Sitemap>(`/api/sitemap?in_scope_only=${in_scope_only}`),
  sitemapItems: (origin: string, path: string, recursive: boolean, limit = 300) => {
    const qs = new URLSearchParams({
      origin, path, recursive: String(recursive), limit: String(limit),
    })
    return request<{ total: number; items: FlowRow[] }>(`/api/sitemap/items?${qs}`)
  },
  addToScope: (body: {
    origin: string; path?: string; kind: 'include' | 'exclude'; whole_host: boolean
  }) => post<{ added: boolean; pattern: string; settings: Settings }>(
    '/api/sitemap/scope', body,
  ),

  intercepts: () => request<{ enabled: boolean; items: PendingItem[] }>('/api/intercept'),
  forward: (id: string, raw_b64?: string) => post(`/api/intercept/${id}/forward`, { raw_b64 }),
  drop: (id: string) => post(`/api/intercept/${id}/drop`),
  forwardAll: () => post<{ forwarded: number }>('/api/intercept/forward-all'),
  dropAll: () => post<{ dropped: number }>('/api/intercept/drop-all'),

  repeaterSend: (body: {
    host: string; port: number; tls: boolean; raw_b64: string
    update_content_length: boolean; log: boolean
  }) => post<RepeaterResult>('/api/repeater/send', body),

  intruderPreview: (config: AttackConfig) => post<AttackPreview>('/api/intruder/preview', config),
  intruderStart: (config: AttackConfig) => post<AttackSummary>('/api/intruder/start', config),
  intruderList: () => request<AttackSummary[]>('/api/intruder'),
  intruderGet: (id: string) => request<AttackSummary>(`/api/intruder/${id}`),
  intruderResults: (id: string, limit = 5000) =>
    request<{ items: ResultRow[] }>(`/api/intruder/${id}/results?limit=${limit}`),
  intruderResult: (id: string, idx: number) =>
    request<ResultDetail>(`/api/intruder/${id}/results/${idx}`),
  intruderControl: (id: string, action: 'pause' | 'resume' | 'stop') =>
    post<AttackSummary>(`/api/intruder/${id}/${action}`),
  intruderDelete: (id: string) => request(`/api/intruder/${id}`, { method: 'DELETE' }),
  markPositions: (raw_b64: string, mode: 'auto' | 'clear' = 'auto') =>
    post<{ raw_b64: string; positions: number }>('/api/intruder/mark', { raw_b64, mode }),

  vpn: () => request<{ status: VpnStatus; profiles: VpnProfile[]; log: string[] }>('/api/vpn'),
  vpnLog: (limit = 200) => request<{ lines: string[] }>(`/api/vpn/log?limit=${limit}`),
  vpnInspect: (config: string) => post<VpnConfigInfo>('/api/vpn/inspect', { config }),
  vpnSaveProfile: (body: {
    name: string; config: string; username?: string; password?: string; notes?: string
  }) => post<VpnProfile>('/api/vpn/profiles', body),
  vpnDeleteProfile: (id: string) =>
    request(`/api/vpn/profiles/${id}`, { method: 'DELETE' }),
  vpnConnect: (profile_id: string) => post<VpnStatus>('/api/vpn/connect', { profile_id }),
  vpnDisconnect: () => post<VpnStatus>('/api/vpn/disconnect'),
  vpnCheck: () => post<{ exit_ip: string; checked: number; url: string }>('/api/vpn/check'),

  wordlists: () => request<Wordlist[]>('/api/wordlists'),
  saveWordlist: (name: string, content: string) =>
    post<{ name: string; lines: number }>('/api/wordlists', { name, content }),
  getWordlist: (name: string) =>
    request<{ name: string; content: string }>(`/api/wordlists/${encodeURIComponent(name)}`),
  deleteWordlist: (name: string) =>
    request(`/api/wordlists/${encodeURIComponent(name)}`, { method: 'DELETE' }),
}

export function defaultPayloadSet(): PayloadSet {
  return {
    kind: 'list',
    payloads: [],
    wordlist: '',
    number_from: 1,
    number_to: 100,
    number_step: 1,
    charset: 'abcdefghijklmnopqrstuvwxyz',
    min_length: 1,
    max_length: 3,
    rules: [],
  }
}
