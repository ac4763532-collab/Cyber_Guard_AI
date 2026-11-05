/**
 * Vitest global test setup.
 *
 * Extends expect() with jest-dom matchers and ensures each test gets a
 * clean DOM (prevents leakage between tests when components aren't
 * explicitly unmounted).
 */
import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

afterEach(() => {
  cleanup()
})
