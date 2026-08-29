/**
 * Unit tests for the logging seam (`src/log.ts`): the type-only
 * assignability check against `@interop/logger`'s own `Logger` type, the
 * unwired console fallback, the wired path through `setLogger`, and the
 * stage-notifier adapter the long ceremonies report their boundaries
 * through.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { captureLogger } from '@interop/logger'
import type { Logger as PortLogger } from '@interop/logger'
import { log, setLogger, stageNotifier } from '../../src/log.js'
import type { Logger } from '../../src/log.js'

// The compile-time half of the "library port" contract (decision 0004 in
// the @interop/logger repo, section 5.6 of the FW-306 design): the locally
// declared `Logger` in src/log.ts and the package's own `Logger` type must
// stay mutually assignable, even though src/log.ts itself takes no
// reference to the package. A drift in either shape fails `tsc`, not this
// assertion at runtime.
function assertMutuallyAssignable(): void {
  const asPortLogger: PortLogger = log
  const asLocalLogger: Logger = asPortLogger
  void asLocalLogger
}
assertMutuallyAssignable()

describe('the console fallback', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('logs through the prefixed console when no logger is installed', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    log.warn('x', { a: 1 })

    expect(warn).toHaveBeenCalledWith('[wallet-core]', 'x', { a: 1 })
  })

  it('passes no trailing argument when called with no data', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    log.warn('x')

    expect(warn).toHaveBeenCalledWith('[wallet-core]', 'x')
  })
})

describe('setLogger', () => {
  afterEach(() => {
    // vitest isolates modules per FILE, not per test: an injected logger
    // left standing here would leak into every other test in this file.
    setLogger({
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {}
    })
  })

  it('routes calls to the installed logger and reports structured events', () => {
    const capture = captureLogger('wc')
    const previous = setLogger(capture.logger)

    const err = new Error('boom')
    log.warn('msg', { err, spaceId: 'urn:uuid:space' })

    expect(capture.events).toHaveLength(1)
    const event = capture.events[0]!
    expect(event.ns).toBe('wc')
    expect(event.level).toBe('warn')
    expect(event.msg).toBe('msg')
    expect(event.err).toBe(err)
    expect(event.data).toEqual({ spaceId: 'urn:uuid:space' })

    const restored = setLogger(previous)
    expect(restored).toBe(capture.logger)
  })
})

describe('stageNotifier', () => {
  afterEach(() => {
    setLogger({
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {}
    })
  })

  it('forwards each stage name to the caller notifier', () => {
    const seen: string[] = []

    const stage = stageNotifier(name => seen.push(name))
    stage('space-provisioning')
    stage('webvh-genesis')

    expect(seen).toEqual(['space-provisioning', 'webvh-genesis'])
  })

  it('is a no-op when the caller supplied no notifier', () => {
    expect(() => stageNotifier()('space-provisioning')).not.toThrow()
  })

  it('swallows a throwing notifier so telemetry cannot tear a ceremony', () => {
    const capture = captureLogger('wc')
    setLogger(capture.logger)

    const stage = stageNotifier(() => {
      throw new Error('telemetry blew up')
    })

    expect(() => stage('record-rebind')).not.toThrow()
    expect(capture.events).toHaveLength(1)
    expect(capture.events[0]!.level).toBe('warn')
    expect(capture.events[0]!.data).toEqual({ stage: 'record-rebind' })
  })
})
