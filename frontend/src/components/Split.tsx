import { useCallback, useEffect, useRef, useState } from 'react'

/** Two panes with a draggable divider; ratio persists per `storageKey`. */
export function Split({
  children, vertical = false, initial = 0.5, storageKey,
}: {
  children: [React.ReactNode, React.ReactNode]
  vertical?: boolean
  initial?: number
  storageKey?: string
}) {
  const [ratio, setRatio] = useState(() => {
    if (!storageKey) return initial
    try {
      const saved = window.localStorage.getItem(`brup.split.${storageKey}`)
      const value = saved ? Number(saved) : NaN
      return Number.isFinite(value) && value > 0.08 && value < 0.92 ? value : initial
    } catch {
      return initial
    }
  })
  const container = useRef<HTMLDivElement>(null)
  const dragging = useRef(false)

  useEffect(() => {
    if (!storageKey) return
    try {
      window.localStorage.setItem(`brup.split.${storageKey}`, String(ratio))
    } catch {
      /* a private window without storage is fine */
    }
  }, [ratio, storageKey])

  const onMove = useCallback((event: MouseEvent) => {
    if (!dragging.current || !container.current) return
    const box = container.current.getBoundingClientRect()
    const next = vertical
      ? (event.clientY - box.top) / box.height
      : (event.clientX - box.left) / box.width
    setRatio(Math.min(0.92, Math.max(0.08, next)))
  }, [vertical])

  useEffect(() => {
    const stop = () => {
      dragging.current = false
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', stop)
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', stop)
    }
  }, [onMove])

  const startDrag = () => {
    dragging.current = true
    document.body.style.cursor = vertical ? 'row-resize' : 'col-resize'
    document.body.style.userSelect = 'none'
  }

  const grow = (fraction: number) => ({ flexGrow: fraction, flexBasis: 0 as const })

  return (
    <div className={`split${vertical ? ' vertical' : ''}`} ref={container}>
      <div className="half" style={grow(ratio)}>{children[0]}</div>
      <div className="divider" onMouseDown={startDrag} />
      <div className="half" style={grow(1 - ratio)}>{children[1]}</div>
    </div>
  )
}
