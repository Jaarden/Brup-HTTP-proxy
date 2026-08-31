import { useState } from 'react'
import { useApp } from '../store'

/** "Temporary 14:23" — enough to tell two apart in one sitting. */
function temporaryName(): string {
  const now = new Date()
  const hh = String(now.getHours()).padStart(2, '0')
  const mm = String(now.getMinutes()).padStart(2, '0')
  return `Temporary ${hh}:${mm}`
}

export function Sidebar() {
  const {
    projects, activeProjectId, activeProject, selectProject, createProject,
    keepProject, renameProject, deleteProject, activeTab, navigate, status, connected,
  } = useApp()
  const [collapsed, setCollapsed] = useState(false)
  const [naming, setNaming] = useState(false)
  const [newName, setNewName] = useState('')
  const [copySettings, setCopySettings] = useState(true)

  const submitNew = async () => {
    const name = newName.trim()
    if (!name) return
    setNaming(false)
    setNewName('')
    await createProject(name, copySettings ? activeProjectId ?? undefined : undefined)
  }

  const newTemporary = async () => {
    await createProject(temporaryName(), activeProjectId ?? undefined, true)
  }

  const confirmDelete = async (id: string, name: string) => {
    const project = projects.find((p) => p.id === id)
    const detail = project
      ? `${project.flow_count.toLocaleString()} logged item(s) and ${project.attack_count} attack(s)`
      : 'its data'
    if (!window.confirm(
      `Delete project "${name}"?\n\nThis permanently removes ${detail}, including its `
      + 'history, sitemap, Repeater tabs and Intruder results. This cannot be undone.',
    )) return
    await deleteProject(id)
  }

  if (collapsed) {
    return (
      <aside className="sidebar collapsed">
        <button
          className="ghost sidebar-toggle"
          title="Show projects"
          onClick={() => setCollapsed(false)}
        >
          ›
        </button>
        <div className="sidebar-spine" title={activeProject?.name ?? ''}>
          {activeProject?.name ?? ''}
        </div>
      </aside>
    )
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-head">
        <span className="brand">BRUP</span>
        <button
          className="ghost sidebar-toggle"
          title="Hide projects"
          onClick={() => setCollapsed(true)}
        >
          ‹
        </button>
      </div>

      <div className="new-project-actions">
        {naming ? (
          <>
            <input
              type="text"
              autoFocus
              placeholder="Project name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') void submitNew()
                if (e.key === 'Escape') {
                  setNaming(false)
                  setNewName('')
                }
              }}
            />
            <label className="toggle" title="Start from the current project's setting overrides">
              <input
                type="checkbox"
                checked={copySettings}
                onChange={(e) => setCopySettings(e.target.checked)}
              />
              Copy settings
            </label>
            <div className="row">
              <button className="primary grow" onClick={() => void submitNew()}>Create</button>
              <button onClick={() => setNaming(false)}>Cancel</button>
            </div>
          </>
        ) : (
          <>
            <button className="btn-new primary" onClick={() => setNaming(true)}>
              + New project
            </button>
            <button
              className="btn-new"
              onClick={() => void newTemporary()}
              title="A scratch project, discarded when BRUP restarts"
            >
              ⏱ Temporary project
            </button>
          </>
        )}
      </div>

      <div className="sidebar-section"><span>Projects</span></div>

      <div className="project-list">
        {projects.map((project) => {
          const active = project.id === activeProjectId
          return (
            <div
              key={project.id}
              className={`project${active ? ' active' : ''}${project.temporary ? ' temp' : ''}`}
              onClick={() => void selectProject(project.id)}
              onDoubleClick={() => {
                const name = window.prompt('Rename project', project.name)
                if (name && name.trim()) void renameProject(project.id, name.trim())
              }}
              title={`${project.name}\n${project.flow_count.toLocaleString()} items`
                + (project.temporary ? '\nTemporary: discarded on restart' : '')
                + '\nDouble-click to rename'}
            >
              <div className="project-main">
                <span className="project-name">
                  {project.temporary && <span className="temp-dot" title="Temporary">⏱</span>}
                  {project.name}
                </span>
                <span className="project-meta">
                  {project.flow_count.toLocaleString()} items
                  {Object.keys(project.overrides).length > 0 && (
                    <span className="tag edited" style={{ marginLeft: 5 }}>
                      {Object.keys(project.overrides).length} override
                      {Object.keys(project.overrides).length === 1 ? '' : 's'}
                    </span>
                  )}
                </span>
              </div>
              {project.temporary && (
                <button
                  className="project-keep"
                  title="Keep this project (survives a restart)"
                  onClick={(event) => {
                    event.stopPropagation()
                    void keepProject(project.id)
                  }}
                >
                  keep
                </button>
              )}
              <button
                className="project-x"
                title="Delete project"
                onClick={(event) => {
                  event.stopPropagation()
                  void confirmDelete(project.id, project.name)
                }}
              >
                ×
              </button>
            </div>
          )
        })}
        {projects.length === 0 && (
          <p className="hint" style={{ padding: '6px 10px' }}>No projects</p>
        )}
      </div>

      <div className="sidebar-foot">
        <button
          className={`sidebar-link${activeTab === 'settings' ? ' active' : ''}`}
          onClick={() => navigate('settings')}
        >
          ⚙ System settings
        </button>
        <div className="conn" title={status?.proxy.listeners.join(', ') || 'no listener'}>
          <span className={`dot${connected && status?.proxy.running ? ' on' : ''}`} />
          {connected
            ? (status?.proxy.running
                ? status.proxy.listeners[0] ?? 'running'
                : 'proxy stopped')
            : 'disconnected'}
        </div>
      </div>
    </aside>
  )
}
