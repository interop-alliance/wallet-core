import { defineConfig } from 'vitest/config'

/**
 * The integration tier: suites that run wallet-core's ceremonies against the
 * real `was-teaching-server`, booted in process through
 * `was-teaching-server/testing`. Kept out of the default unit run
 * (`vite.config.ts`), so `pnpm run test:node` stays fast and server-free.
 */
export default defineConfig({
  test: {
    include: ['test/integration/**/*.test.ts'],
    // Each suite boots its own server on an ephemeral port over its own
    // temp dir, so files may run in parallel. A ceremony run against a real
    // server takes seconds rather than milliseconds.
    testTimeout: 60_000,
    hookTimeout: 60_000
  }
})
