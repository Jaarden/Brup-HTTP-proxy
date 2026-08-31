import { VpnStatus } from '../api'

/**
 * Top-bar VPN indicator. Red covers two different problems: a failed tunnel,
 * and the kill switch actively blocking traffic because nothing is up.
 */
export function VpnBadge({
  status, onClick,
}: {
  status: VpnStatus | null
  onClick: () => void
}) {
  if (!status) return null

  const { state, exit_ip: exitIp, required } = status
  const blocking = required && state !== 'connected'

  let label: string
  let colour: string
  let title: string

  switch (state) {
    case 'connected':
      label = exitIp ? `VPN on · ${exitIp}` : 'VPN on'
      colour = 'var(--green)'
      title = exitIp
        ? `Tunnel up (${status.kind}); traffic exits from ${exitIp}`
        : `Tunnel up (${status.kind}). Use "Check exit IP" to confirm the exit address.`
      break
    case 'connecting':
      label = 'VPN connecting…'
      colour = 'var(--yellow)'
      title = 'Bringing the tunnel up'
      break
    case 'failed':
      label = blocking ? 'VPN failed · blocking' : 'VPN failed'
      colour = 'var(--red)'
      title = status.message || 'The tunnel failed to come up'
      break
    default:
      label = blocking ? 'VPN off · blocking' : 'VPN off'
      colour = blocking ? 'var(--red)' : 'var(--text-faint)'
      title = blocking
        ? 'The kill switch is on and no tunnel is up, so all traffic is refused'
        : 'No tunnel; traffic goes out over the normal connection'
  }

  return (
    <button
      className="vpn-badge"
      style={{ color: colour, borderColor: colour }}
      title={`${title}\nClick to open System settings`}
      onClick={onClick}
    >
      <span className="dot" style={{ background: colour }} />
      {label}
    </button>
  )
}
