import { useMemo, useState } from 'react'
import { byteLength, extractContentType, hexDump, prettifyBody, splitMessage } from '../raw'
import { RawEditor } from './RawEditor'

type View = 'pretty' | 'raw' | 'headers' | 'hex'

interface Props {
  raw: string
  /** Content-decoded body (gzip/br/deflate), when the backend supplied one. */
  decodedBody?: string | null
  title?: string
  toolbar?: React.ReactNode
  status?: React.ReactNode
  search?: string
}

/** Read-only viewer for a raw HTTP message, with the usual view modes. */
export function MessageViewer({ raw, decodedBody, title, toolbar, status }: Props) {
  const [view, setView] = useState<View>('pretty')

  const { head, body } = useMemo(() => splitMessage(raw), [raw])
  const contentType = useMemo(() => extractContentType(raw), [raw])
  const effectiveBody = decodedBody ?? body

  const text = useMemo(() => {
    if (!raw) return ''
    switch (view) {
      case 'raw':
        return decodedBody ? `${head}\r\n\r\n${decodedBody}` : raw
      case 'hex':
        return hexDump(raw)
      case 'headers':
        return head
      case 'pretty':
      default:
        return `${head}\n\n${prettifyBody(effectiveBody, contentType)}`
    }
  }, [view, raw, head, effectiveBody, contentType, decodedBody])

  return (
    <RawEditor
      readOnly
      value={text}
      title={title}
      placeholder="No message"
      status={
        <>
          {status}
          {decodedBody != null && <span className="dim">decoded {byteLength(decodedBody)}B</span>}
        </>
      }
      toolbar={
        <>
          {toolbar}
          <div className="viewtabs">
            {(['pretty', 'raw', 'headers', 'hex'] as View[]).map((mode) => (
              <button
                key={mode}
                className={view === mode ? 'active' : ''}
                onClick={() => setView(mode)}
                title={mode === 'pretty' ? 'Formatted body, content-decoded' : mode}
              >
                {mode}
              </button>
            ))}
          </div>
        </>
      }
    />
  )
}
