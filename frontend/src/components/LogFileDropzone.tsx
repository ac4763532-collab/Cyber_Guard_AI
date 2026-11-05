/**
 * CyberGuard AI - Log File Dropzone
 *
 * Drag-and-drop + click-to-browse log file picker, mirroring
 * EmailDropzone.tsx's controlled structure. Generalized for the file
 * types POST /analysis/logs/upload actually parses (.log/.txt/.csv/
 * .json/.jsonl) instead of a single fixed extension. Purely controlled
 * file selection - no API calls happen here; the parent page owns the
 * actual upload/analyze submission.
 */

import { useRef, useState } from 'react'
import { clsx } from 'clsx'
import { UploadCloud, FileText, X, CheckCircle2, AlertCircle } from 'lucide-react'

// Keep in sync with settings.log_upload_max_file_size_bytes
// (backend/app/config.py) - 5MB, smaller than email's 10MB since these
// are newer, unoptimized text parsers.
export const MAX_LOG_FILE_SIZE_BYTES = 5 * 1024 * 1024 // 5 MB

const ALLOWED_EXTENSIONS = ['.log', '.txt', '.csv', '.json', '.jsonl']

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function hasAllowedExtension(filename: string): boolean {
  const lower = filename.toLowerCase()
  return ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext))
}

function validateFile(file: File): string | null {
  if (!hasAllowedExtension(file.name)) {
    return `Unsupported file type. Supported: ${ALLOWED_EXTENSIONS.join(', ')}`
  }
  if (file.size > MAX_LOG_FILE_SIZE_BYTES) {
    return `File exceeds the ${MAX_LOG_FILE_SIZE_BYTES / (1024 * 1024)}MB upload limit.`
  }
  if (file.size === 0) {
    return 'File is empty.'
  }
  return null
}

interface LogFileDropzoneProps {
  selectedFile: File | null
  error: string | null
  disabled?: boolean
  /** Accepted today but not yet wired to multi-file selection - the
   * backend only supports a single file per request (v1). Kept so this
   * component can be extended later without a redesign. */
  multiple?: boolean
  onFileSelected: (file: File) => void
  onError: (message: string) => void
  onClear: () => void
}

export function LogFileDropzone({
  selectedFile,
  error,
  disabled = false,
  multiple = false,
  onFileSelected,
  onError,
  onClear,
}: LogFileDropzoneProps) {
  const [isDragActive, setIsDragActive] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFile = (file: File) => {
    const validationError = validateFile(file)
    if (validationError) {
      onError(validationError)
      return
    }
    onFileSelected(file)
  }

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragActive(false)
    if (disabled) return

    const file = e.dataTransfer.files?.[0]
    if (file) handleFile(file)
  }

  const handleDragEnter = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    if (!disabled) setIsDragActive(true)
  }

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
  }

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault()
    setIsDragActive(false)
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
    // Allow re-selecting the same filename after a clear.
    e.target.value = ''
  }

  const handleClick = () => {
    if (!disabled) inputRef.current?.click()
  }

  if (selectedFile) {
    return (
      <div className="border border-slate-700 rounded-xl p-6 bg-slate-800/50">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 min-w-0">
            <div className="flex-shrink-0 w-10 h-10 bg-cyan-500/20 rounded-lg flex items-center justify-center">
              <FileText className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="min-w-0">
              <p className="text-white font-medium truncate">{selectedFile.name}</p>
              <p className="text-sm text-slate-400">{formatFileSize(selectedFile.size)}</p>
              <div className="flex items-center gap-1 mt-1 text-emerald-400 text-xs">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Valid log file
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={onClear}
            disabled={disabled}
            className="flex-shrink-0 p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors disabled:opacity-50"
            aria-label="Remove file"
            title="Remove file"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    )
  }

  return (
    <div>
      <div
        onClick={handleClick}
        onDrop={handleDrop}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        role="button"
        tabIndex={0}
        aria-label="Drag and drop a log file here, or click to browse"
        className={clsx(
          'border-2 border-dashed rounded-xl px-6 py-12 text-center cursor-pointer transition-colors',
          disabled && 'opacity-50 cursor-not-allowed',
          isDragActive
            ? 'border-cyan-400 bg-cyan-500/10'
            : 'border-slate-700 hover:border-cyan-600 hover:bg-slate-800/30'
        )}
      >
        <input
          ref={inputRef}
          type="file"
          accept={ALLOWED_EXTENSIONS.join(',')}
          multiple={multiple}
          onChange={handleInputChange}
          disabled={disabled}
          className="hidden"
        />
        <UploadCloud
          className={clsx('w-12 h-12 mx-auto mb-4', isDragActive ? 'text-cyan-400' : 'text-slate-600')}
        />
        <p className="text-white font-medium mb-1">
          Drag and drop a log file here
        </p>
        <p className="text-slate-400 text-sm">
          or <span className="text-cyan-400">click to browse</span>
        </p>
        <p className="text-slate-500 text-xs mt-3">
          {ALLOWED_EXTENSIONS.join(' · ')} · up to {MAX_LOG_FILE_SIZE_BYTES / (1024 * 1024)}MB
        </p>
      </div>

      {error && (
        <div className="flex items-center gap-2 mt-3 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}
    </div>
  )
}
