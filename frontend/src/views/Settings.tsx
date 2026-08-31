import { SettingsForm } from '../components/SettingsForm'

/** System-wide defaults, the listener and the CA. Reached from the sidebar. */
export function SystemSettings() {
  return <SettingsForm mode="system" />
}

/** The active project's overrides. Reached from Proxy → Project settings. */
export function ProjectSettings() {
  return <SettingsForm mode="project" />
}
