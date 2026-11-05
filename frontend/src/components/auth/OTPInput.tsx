/**
 * CyberGuard AI - OTP Input Component
 *
 * 6-digit verification code input with auto-advance.
 */

import { useRef, useState, useEffect, KeyboardEvent, ClipboardEvent } from 'react'
import { clsx } from 'clsx'

interface OTPInputProps {
  length?: number
  value: string
  onChange: (value: string) => void
  onComplete?: (value: string) => void
  disabled?: boolean
  error?: boolean
  autoFocus?: boolean
}

export function OTPInput({
  length = 6,
  value,
  onChange,
  onComplete,
  disabled = false,
  error = false,
  autoFocus = true,
}: OTPInputProps) {
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])
  const [focusedIndex, setFocusedIndex] = useState(-1)

  // Initialize refs array
  useEffect(() => {
    inputRefs.current = inputRefs.current.slice(0, length)
  }, [length])

  // Auto-focus first input
  useEffect(() => {
    if (autoFocus && inputRefs.current[0]) {
      inputRefs.current[0].focus()
    }
  }, [autoFocus])

  // Handle input change
  const handleChange = (index: number, inputValue: string) => {
    if (disabled) return

    // Only allow numbers
    const digit = inputValue.replace(/\D/g, '').slice(-1)

    // Build new value
    const valueArray = value.split('')
    valueArray[index] = digit
    const newValue = valueArray.join('').slice(0, length)

    onChange(newValue)

    // Move to next input if digit entered
    if (digit && index < length - 1) {
      inputRefs.current[index + 1]?.focus()
    }

    // Check for completion
    if (newValue.length === length && onComplete) {
      onComplete(newValue)
    }
  }

  // Handle key down
  const handleKeyDown = (index: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (disabled) return

    if (e.key === 'Backspace') {
      e.preventDefault()
      const valueArray = value.split('')

      if (valueArray[index]) {
        // Clear current digit
        valueArray[index] = ''
        onChange(valueArray.join(''))
      } else if (index > 0) {
        // Move to previous and clear
        valueArray[index - 1] = ''
        onChange(valueArray.join(''))
        inputRefs.current[index - 1]?.focus()
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      e.preventDefault()
      inputRefs.current[index - 1]?.focus()
    } else if (e.key === 'ArrowRight' && index < length - 1) {
      e.preventDefault()
      inputRefs.current[index + 1]?.focus()
    }
  }

  // Handle paste
  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    if (disabled) return

    e.preventDefault()
    const pastedText = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, length)

    if (pastedText) {
      onChange(pastedText)

      // Focus last filled input or first empty
      const focusIndex = Math.min(pastedText.length, length - 1)
      inputRefs.current[focusIndex]?.focus()

      // Check for completion
      if (pastedText.length === length && onComplete) {
        onComplete(pastedText)
      }
    }
  }

  // Handle focus
  const handleFocus = (index: number) => {
    setFocusedIndex(index)
    inputRefs.current[index]?.select()
  }

  return (
    <div className="flex items-center justify-center gap-2 sm:gap-3">
      {Array.from({ length }).map((_, index) => {
        const digit = value[index] || ''
        const isFocused = focusedIndex === index
        const hasValue = digit !== ''

        return (
          <input
            key={index}
            ref={(el) => { inputRefs.current[index] = el }}
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={1}
            value={digit}
            onChange={(e) => handleChange(index, e.target.value)}
            onKeyDown={(e) => handleKeyDown(index, e)}
            onPaste={handlePaste}
            onFocus={() => handleFocus(index)}
            onBlur={() => setFocusedIndex(-1)}
            disabled={disabled}
            autoComplete="one-time-code"
            aria-label={`Digit ${index + 1} of ${length}`}
            className={clsx(
              'w-10 h-12 sm:w-12 sm:h-14 text-center text-xl font-semibold rounded-lg border-2 transition-all duration-200',
              'focus:outline-none',
              disabled && 'opacity-50 cursor-not-allowed bg-slate-800',
              error
                ? 'border-red-500 bg-red-500/10 text-red-400'
                : isFocused
                ? 'border-cyan-500 bg-slate-800 text-white ring-2 ring-cyan-500/20'
                : hasValue
                ? 'border-slate-600 bg-slate-800 text-white'
                : 'border-slate-700 bg-slate-800/50 text-white'
            )}
          />
        )
      })}
    </div>
  )
}
