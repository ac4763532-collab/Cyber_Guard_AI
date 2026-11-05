/**
 * Tests for LogFileDropzone: drag-drop and browse-select both fire
 * onFileSelected for a valid file; invalid extension / oversized files
 * fire onError (never onFileSelected); the selected-file view's remove
 * button fires onClear.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { LogFileDropzone, MAX_LOG_FILE_SIZE_BYTES } from './LogFileDropzone'

function makeFile(name: string, size: number, type = 'text/plain') {
  const file = new File(['x'.repeat(Math.min(size, 1024))], name, { type })
  // File.size reflects actual blob content length; override to simulate
  // large files without allocating real memory for them.
  Object.defineProperty(file, 'size', { value: size })
  return file
}

function renderDropzone(overrides: Partial<React.ComponentProps<typeof LogFileDropzone>> = {}) {
  const onFileSelected = vi.fn()
  const onError = vi.fn()
  const onClear = vi.fn()
  const utils = render(
    <LogFileDropzone
      selectedFile={null}
      error={null}
      onFileSelected={onFileSelected}
      onError={onError}
      onClear={onClear}
      {...overrides}
    />
  )
  return { ...utils, onFileSelected, onError, onClear }
}

describe('LogFileDropzone - browse-select', () => {
  it('fires onFileSelected for a valid .log file within the size limit', async () => {
    const { onFileSelected, onError } = renderDropzone()
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    const file = makeFile('auth.log', 1024)

    await userEvent.upload(input, file)

    expect(onFileSelected).toHaveBeenCalledWith(file)
    expect(onError).not.toHaveBeenCalled()
  })

  it('fires onError (not onFileSelected) for an unsupported extension', async () => {
    // Browse-select can't exercise this: the input's accept attribute
    // (set to ALLOWED_EXTENSIONS) makes userEvent.upload v14 skip firing
    // change entirely for a non-matching file, same as a real browser's
    // file picker would already filter it out before the user could even
    // pick it. Drag-and-drop has no such filter in either a real browser
    // or jsdom, so it's the real path a mismatched file reaches
    // validateFile() through - see the drag-and-drop describe block below
    // for that exact scenario; this covers the component's error copy.
    const { onFileSelected, onError } = renderDropzone()
    const dropzone = screen.getByRole('button', {
      name: /Drag and drop a log file here, or click to browse/i,
    })
    const file = makeFile('malware.exe', 1024)
    const { fireEvent } = await import('@testing-library/react')
    fireEvent.drop(dropzone, {
      dataTransfer: {
        files: [file],
        items: [{ kind: 'file', type: file.type, getAsFile: () => file }],
        types: ['Files'],
      },
    })

    expect(onFileSelected).not.toHaveBeenCalled()
    expect(onError).toHaveBeenCalledWith(expect.stringMatching(/unsupported file type/i))
  })

  it('fires onError (not onFileSelected) for a file over the size limit', async () => {
    const { onFileSelected, onError } = renderDropzone()
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    const file = makeFile('huge.log', MAX_LOG_FILE_SIZE_BYTES + 1)

    await userEvent.upload(input, file)

    expect(onFileSelected).not.toHaveBeenCalled()
    expect(onError).toHaveBeenCalledWith(expect.stringMatching(/exceeds the 5MB upload limit/i))
  })

  it('fires onError for an empty file', async () => {
    const { onFileSelected, onError } = renderDropzone()
    const input = document.querySelector('input[type="file"]') as HTMLInputElement
    const file = makeFile('empty.log', 0)

    await userEvent.upload(input, file)

    expect(onFileSelected).not.toHaveBeenCalled()
    expect(onError).toHaveBeenCalledWith(expect.stringMatching(/file is empty/i))
  })
})

describe('LogFileDropzone - drag and drop', () => {
  it('fires onFileSelected for a valid file dropped on the zone', async () => {
    const { onFileSelected } = renderDropzone()
    const dropzone = screen.getByRole('button', {
      name: /Drag and drop a log file here, or click to browse/i,
    })
    const file = makeFile('syslog.txt', 2048)

    const dataTransfer = {
      files: [file],
      items: [{ kind: 'file', type: file.type, getAsFile: () => file }],
      types: ['Files'],
    }

    // fireEvent is used here instead of userEvent because userEvent has
    // no built-in drag-and-drop file API; this constructs a real React
    // DragEvent with the file payload, matching LogFileDropzone's own
    // handleDrop(e: React.DragEvent).
    const { fireEvent } = await import('@testing-library/react')
    fireEvent.drop(dropzone, { dataTransfer })

    expect(onFileSelected).toHaveBeenCalledWith(file)
  })

  it('rejects an invalid dropped file via onError, not onFileSelected', async () => {
    const { onFileSelected, onError } = renderDropzone()
    const dropzone = screen.getByRole('button', {
      name: /Drag and drop a log file here, or click to browse/i,
    })
    const file = makeFile('binary.exe', 2048)
    const dataTransfer = {
      files: [file],
      items: [{ kind: 'file', type: file.type, getAsFile: () => file }],
      types: ['Files'],
    }

    const { fireEvent } = await import('@testing-library/react')
    fireEvent.drop(dropzone, { dataTransfer })

    expect(onFileSelected).not.toHaveBeenCalled()
    expect(onError).toHaveBeenCalled()
  })
})

describe('LogFileDropzone - selected file view', () => {
  it('shows the file name/size and fires onClear on remove', async () => {
    const file = makeFile('auth.log', 2048)
    const { onClear } = renderDropzone({ selectedFile: file })

    expect(screen.getByText('auth.log')).toBeInTheDocument()
    expect(screen.getByText('2.0 KB')).toBeInTheDocument()

    await userEvent.click(screen.getByLabelText('Remove file'))
    expect(onClear).toHaveBeenCalled()
  })

  it('disables the remove button when disabled is true', () => {
    const file = makeFile('auth.log', 2048)
    renderDropzone({ selectedFile: file, disabled: true })

    expect(screen.getByLabelText('Remove file')).toBeDisabled()
  })
})

describe('LogFileDropzone - error display', () => {
  it('renders a passed-in error message', () => {
    renderDropzone({ error: 'The file could not be parsed.' })
    expect(screen.getByText('The file could not be parsed.')).toBeInTheDocument()
  })
})
