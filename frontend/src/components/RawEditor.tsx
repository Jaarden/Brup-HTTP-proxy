import { forwardRef } from 'react'
import { byteLength, firstLine } from '../raw'

interface Props {
  value: string
  onChange?: (value: string) => void
  readOnly?: boolean
  title?: string
  toolbar?: React.ReactNode
  placeholder?: string
  onSubmit?: () => void
  status?: React.ReactNode
}

/**
 * A plain monospace textarea. Deliberately not a rich editor: the operator must
 * be able to type arbitrary bytes without anything reformatting them.
 */
export const RawEditor = forwardRef<HTMLTextAreaElement, Props>(function RawEditor(
  { value, onChange, readOnly, title, toolbar, placeholder, onSubmit, status }, ref,
) {
  return (
    <div className="editor-wrap">
      {(title || toolbar) && (
        <div className="panel-title">
          {title && <span>{title}</span>}
          {toolbar}
        </div>
      )}
      <textarea
        ref={ref}
        className="editor"
        spellCheck={false}
        autoComplete="off"
        wrap="off"
        readOnly={readOnly}
        placeholder={placeholder}
        value={value}
        onChange={(event) => onChange?.(event.target.value)}
        onKeyDown={(event) => {
          if (onSubmit && (event.ctrlKey || event.metaKey) && event.key === 'Enter') {
            event.preventDefault()
            onSubmit()
          }
        }}
      />
      <div className="editor-status">
        <span>{byteLength(value).toLocaleString()} bytes</span>
        <span>{value ? value.split('\n').length : 0} lines</span>
        {status}
        <span className="spacer" />
        <span className="dim">{firstLine(value).slice(0, 90)}</span>
      </div>
    </div>
  )
})
