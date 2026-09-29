/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Unit tests for the ceremony event channel (`src/ceremonyEvents.ts`): the
 * outcome level map, the reserved-key shape, the run id, the `run()`
 * boundary combinator's classification, the mender event, the served
 * identifier sanitizer, and the never-throw guarantee.
 */
import { captureLogger } from '@interop/logger'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ceremonyEvents,
  menderEvent,
  servedIdentifier,
  type CeremonyDetail,
  type CeremonyOutcome
} from '../../src/ceremonyEvents.js'
import { log, setLogger, type Logger } from '../../src/log.js'
import type { MendReportEntry } from '../../src/menders/index.js'
import type { CeremonyId } from '../../src/space/index.js'

type Stage = 'first' | 'second'

let capture: ReturnType<typeof captureLogger>

beforeEach(() => {
  capture = captureLogger('wc')
})

/**
 * A fresh emitter over the capture logger, refusing `KnownRefusalError`.
 */
function emitter() {
  return ceremonyEvents<Stage>({
    ceremony: 'client-revocation',
    log: capture.logger,
    refusals: ['KnownRefusalError']
  })
}

class KnownRefusalError extends Error {
  constructor() {
    super('refused')
    this.name = 'KnownRefusalError'
  }
}

describe('ceremonyEvents', () => {
  it('maps each outcome to its level', () => {
    const expected: Record<CeremonyOutcome, string> = {
      clean: 'info',
      noop: 'debug',
      partial: 'warn',
      refused: 'warn',
      failed: 'error'
    }
    for (const [outcome, level] of Object.entries(expected)) {
      capture = captureLogger('wc')
      emitter().outcome(outcome as CeremonyOutcome)
      expect(capture.events).toHaveLength(1)
      expect(capture.events[0]!.level).toBe(level)
      expect(capture.events[0]!.msg).toBe('ceremony outcome')
      expect(capture.events[0]!.data).toMatchObject({
        ceremony: 'client-revocation',
        outcome
      })
    }
  })

  it('stamps one run id on every event of a run, and a fresh one per run', () => {
    const first = emitter()
    first.stage('first')
    first.stage('second', { prior: true })
    first.outcome('clean', { failedCollections: 0 })
    const second = emitter()
    second.stage('first')

    const [stageOne, stageTwo, outcome, other] = capture.events
    expect(stageOne!.level).toBe('debug')
    expect(stageOne!.msg).toBe('ceremony stage')
    expect(stageOne!.data).toEqual({
      ceremony: 'client-revocation',
      run: first.runId,
      stage: 'first'
    })
    expect(stageTwo!.data).toEqual({
      ceremony: 'client-revocation',
      run: first.runId,
      stage: 'second',
      prior: true
    })
    expect(outcome!.data).toEqual({
      ceremony: 'client-revocation',
      run: first.runId,
      outcome: 'clean',
      failedCollections: 0
    })
    expect(typeof first.runId).toBe('string')
    expect(first.runId.length).toBeGreaterThan(0)
    expect(other!.data?.run).toBe(second.runId)
    expect(second.runId).not.toBe(first.runId)
  })

  it('emits a stage once per run and an outcome at most once', () => {
    const events = emitter()
    events.stage('first')
    events.stage('first')
    events.outcome('clean')
    events.outcome('failed')

    expect(capture.events.map(event => event.msg)).toEqual([
      'ceremony stage',
      'ceremony outcome'
    ])
    expect(capture.events[1]!.data?.outcome).toBe('clean')
  })

  it('carries err as a named parameter at data.err, with its name', () => {
    const err = new KnownRefusalError()
    emitter().outcome('refused', undefined, err)

    const [event] = capture.events
    expect(event!.err).toBe(err)
    expect(event!.data).toMatchObject({
      outcome: 'refused',
      errorName: 'KnownRefusalError'
    })
  })

  it('rejects object-valued and reserved-key detail at compile time', () => {
    const events = emitter()
    // @ts-expect-error -- detail is scalar only
    events.stage('first', { nested: { a: 1 } })
    // @ts-expect-error -- a reserved key cannot be set through detail
    events.stage('first', { run: 'forged' })
    // @ts-expect-error -- err travels as a named parameter, not a detail key
    events.outcome('failed', { err: 'x' })
    // @ts-expect-error -- stages are the ceremony's own union
    events.stage('third')
  })

  it('drops a reserved key and a non-scalar value smuggled past the type', () => {
    const events = emitter()
    const smuggled = {
      ceremony: 'forged',
      run: 'forged',
      stage: 'forged',
      outcome: 'forged',
      invariant: 'forged',
      errorName: 'forged',
      err: 'forged',
      nested: { secret: 'x' },
      count: 2
    } as unknown as CeremonyDetail
    events.stage('first', smuggled)
    events.outcome('clean', smuggled)

    expect(capture.events[0]!.data).toEqual({
      ceremony: 'client-revocation',
      run: events.runId,
      stage: 'first',
      count: 2
    })
    expect(capture.events[1]!.data).toEqual({
      ceremony: 'client-revocation',
      run: events.runId,
      outcome: 'clean',
      count: 2
    })
    expect(capture.events[1]!.err).toBeUndefined()
  })

  it('never throws: a throwing detail getter or logger leaves the stream going', () => {
    const detail = {
      count: 1,
      get broken(): number {
        throw new Error('getter')
      }
    } as unknown as CeremonyDetail
    const events = emitter()
    expect(() => events.stage('first', detail)).not.toThrow()
    expect(capture.events[0]!.data).toMatchObject({ stage: 'first', count: 1 })
    expect(capture.events[0]!.data).not.toHaveProperty('broken')

    const throwing: Logger = {
      debug: () => {
        throw new Error('sink')
      },
      info: () => {
        throw new Error('sink')
      },
      warn: () => {
        throw new Error('sink')
      },
      error: () => {
        throw new Error('sink')
      }
    }
    const quiet = ceremonyEvents<Stage>({
      ceremony: 'client-revocation',
      log: throwing,
      refusals: []
    })
    expect(() => quiet.stage('first')).not.toThrow()
    expect(() =>
      quiet.outcome('failed', undefined, new Error('x'))
    ).not.toThrow()
    expect(() =>
      menderEvent({
        log: throwing,
        entry: {
          invariant: 'standard-collections-are-provisioned',
          outcome: 'clean'
        }
      })
    ).not.toThrow()

    events.stage('second')
    expect(capture.events).toHaveLength(2)
  })
})

describe('ceremonyEvents run()', () => {
  it('emits the classified outcome once on return', async () => {
    const events = emitter()
    const result = await events.run(
      async () => {
        events.stage('first')
        return { failed: [1] }
      },
      value => ({
        outcome: value.failed.length > 0 ? 'partial' : 'clean',
        detail: { failedCollections: value.failed.length }
      })
    )

    expect(result).toEqual({ failed: [1] })
    const outcomes = capture.events.filter(
      event => event.msg === 'ceremony outcome'
    )
    expect(outcomes).toHaveLength(1)
    expect(outcomes[0]!.level).toBe('warn')
    expect(outcomes[0]!.data).toMatchObject({
      outcome: 'partial',
      failedCollections: 1
    })
  })

  it('emits exactly one outcome on an early return', async () => {
    const events = emitter()
    await events.run(
      async () => {
        const skip = true
        if (skip) {
          return 'early'
        }
        events.stage('second')
        return 'late'
      },
      () => ({ outcome: 'noop' })
    )
    expect(capture.events).toHaveLength(1)
    expect(capture.events[0]!.data?.outcome).toBe('noop')
    expect(capture.events[0]!.level).toBe('debug')
  })

  it('classifies a pending-named throw as noop at debug, and rethrows', async () => {
    const thrown = new Error('not yet')
    thrown.name = 'KnownPendingError'
    const events = ceremonyEvents<Stage>({
      ceremony: 'client-enrollment',
      log: capture.logger,
      refusals: ['KnownPendingError'],
      pending: ['KnownPendingError']
    })
    await expect(
      events.run(
        async () => {
          throw thrown
        },
        () => ({ outcome: 'clean' })
      )
    ).rejects.toBe(thrown)
    expect(capture.events).toHaveLength(1)
    expect(capture.events[0]!.level).toBe('debug')
    expect(capture.events[0]!.data).toMatchObject({
      outcome: 'noop',
      errorName: 'KnownPendingError'
    })
  })

  it('classifies a refusal-named throw as refused, by name, and rethrows', async () => {
    // A second class carrying the same name: the match is by `err.name`, so
    // a duplicated install's copy of the class still classifies.
    class KnownRefusalErrorCopy extends Error {
      constructor() {
        super('refused')
        this.name = 'KnownRefusalError'
      }
    }
    for (const thrown of [
      new KnownRefusalError(),
      new KnownRefusalErrorCopy()
    ]) {
      capture = captureLogger('wc')
      const events = emitter()
      await expect(
        events.run(
          async () => {
            events.stage('first')
            throw thrown
          },
          () => ({ outcome: 'clean' })
        )
      ).rejects.toBe(thrown)
      const [stage, outcome] = capture.events
      expect(stage!.msg).toBe('ceremony stage')
      expect(outcome!.level).toBe('warn')
      expect(outcome!.data).toMatchObject({
        outcome: 'refused',
        errorName: 'KnownRefusalError'
      })
      expect(outcome!.err).toBe(thrown)
    }
  })

  it('classifies any other throw as failed, with err, and rethrows', async () => {
    const thrown = new TypeError('boom')
    const events = emitter()
    await expect(
      events.run(
        async () => {
          throw thrown
        },
        () => ({ outcome: 'clean' })
      )
    ).rejects.toBe(thrown)
    expect(capture.events).toHaveLength(1)
    expect(capture.events[0]!.level).toBe('error')
    expect(capture.events[0]!.data).toMatchObject({
      outcome: 'failed',
      errorName: 'TypeError'
    })
    expect(capture.events[0]!.err).toBe(thrown)
  })

  it('emits no outcome from a throwing classifier, and still returns', async () => {
    const events = emitter()
    const result = await events.run(
      async () => 7,
      () => {
        throw new Error('classifier')
      }
    )
    expect(result).toBe(7)
    expect(capture.events).toHaveLength(0)
  })

  it('emits each stage once when a lost CAS attempt re-walks it', async () => {
    const events = emitter()
    let attempts = 0
    await events.run(
      async () => {
        // A retry loop inside the run: the first attempt loses its
        // compare-and-swap after the first stage and emits nothing more.
        for (;;) {
          attempts += 1
          events.stage('first')
          if (attempts === 1) {
            continue
          }
          events.stage('second')
          return attempts
        }
      },
      () => ({ outcome: 'clean' })
    )
    expect(attempts).toBe(2)
    expect(capture.events.map(event => event.data?.stage ?? 'outcome')).toEqual(
      ['first', 'second', 'outcome']
    )
  })
})

describe('menderEvent', () => {
  it('maps an entry to one event, without its ceremonies array', () => {
    const entry: MendReportEntry<CeremonyId> = {
      invariant: 'roster-wraps-exactly-the-document-key-set',
      outcome: 'failed',
      errorName: 'TypeError',
      detail: { reason: 'bridge-reseal', failedCollections: 2 },
      ceremonies: ['client-revocation']
    }
    menderEvent({ log: capture.logger, entry })

    expect(capture.events).toHaveLength(1)
    const [event] = capture.events
    expect(event!.msg).toBe('ceremony mender')
    expect(event!.level).toBe('error')
    expect(event!.data).toEqual({
      invariant: 'roster-wraps-exactly-the-document-key-set',
      outcome: 'failed',
      errorName: 'TypeError',
      reason: 'bridge-reseal',
      failedCollections: 2
    })
    expect(event!.err).toBeUndefined()
  })

  it('carries ceremony, run, and err on a tail-site call', () => {
    const events = emitter()
    const err = new Error('tail')
    menderEvent({
      log: capture.logger,
      entry: {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'partial'
      },
      ceremony: 'client-revocation',
      run: events.runId,
      err
    })
    const [event] = capture.events
    expect(event!.level).toBe('warn')
    expect(event!.data).toEqual({
      invariant: 'collection-epochs-name-the-current-user-key',
      outcome: 'partial',
      ceremony: 'client-revocation',
      run: events.runId
    })
    expect(event!.err).toBe(err)
  })

  it('carries ceremony alone when the site holds no emitter', () => {
    menderEvent({
      log: capture.logger,
      entry: {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'clean'
      },
      ceremony: 'unlock-credential-rotation'
    })
    expect(capture.events[0]!.level).toBe('info')
    expect(capture.events[0]!.data).toEqual({
      invariant: 'collection-epochs-name-the-current-user-key',
      outcome: 'clean',
      ceremony: 'unlock-credential-rotation'
    })
  })

  it('drops a reserved key an entry detail carries', () => {
    menderEvent({
      log: capture.logger,
      entry: {
        invariant: 'collection-epochs-name-the-current-user-key',
        outcome: 'clean',
        detail: { invariant: 'forged', outcome: 'forged', count: 1 }
      }
    })
    expect(capture.events[0]!.data).toEqual({
      invariant: 'collection-epochs-name-the-current-user-key',
      outcome: 'clean',
      count: 1
    })
  })

  it('typechecks for a generic ceremony union and for CeremonyId', () => {
    const generic: MendReportEntry<'custom-ceremony'> = {
      invariant: 'collection-epochs-name-the-current-user-key',
      outcome: 'clean',
      ceremonies: ['custom-ceremony']
    }
    menderEvent<'custom-ceremony'>({
      log: capture.logger,
      entry: generic,
      ceremony: 'custom-ceremony'
    })
    const typed: MendReportEntry<CeremonyId> = {
      invariant: 'collection-epochs-name-the-current-user-key',
      outcome: 'clean'
    }
    menderEvent({ log: capture.logger, entry: typed, ceremony: 'wallet-wipe' })
    expect(capture.events).toHaveLength(2)
  })

  describe('a noop entry', () => {
    afterEach(() => {
      vi.restoreAllMocks()
    })

    it('emits at debug', () => {
      menderEvent({
        log: capture.logger,
        entry: {
          invariant: 'collection-epochs-name-the-current-user-key',
          outcome: 'noop'
        }
      })
      expect(capture.events[0]!.level).toBe('debug')
    })

    it('is dropped by the unwired console fallback', () => {
      const debug = vi.spyOn(console, 'debug').mockImplementation(() => {})
      const info = vi.spyOn(console, 'info').mockImplementation(() => {})
      menderEvent({
        log,
        entry: {
          invariant: 'collection-epochs-name-the-current-user-key',
          outcome: 'noop'
        }
      })
      expect(debug).not.toHaveBeenCalled()
      expect(info).not.toHaveBeenCalled()
    })
  })
})

describe('the wallet-core logger path', () => {
  afterEach(() => {
    setLogger({
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {}
    })
  })

  it('routes through setLogger when a ceremony passes the module log', () => {
    const previous = setLogger(capture.logger)
    const events = ceremonyEvents<Stage>({
      ceremony: 'account-genesis',
      log,
      refusals: []
    })
    events.stage('first')
    expect(capture.events).toHaveLength(1)
    expect(capture.events[0]!.ns).toBe('wc')
    setLogger(previous)
  })
})

describe('servedIdentifier', () => {
  it('strips control and bidi characters', () => {
    expect(servedIdentifier('gen-\u202eabc\u0007\u2066d')).toBe('gen-abcd')
  })

  it('keeps a value at the cap and truncates past it with a suffix', () => {
    const atCap = 'a'.repeat(64)
    expect(servedIdentifier(atCap)).toBe(atCap)
    expect(servedIdentifier('b'.repeat(70))).toBe(`${'b'.repeat(64)}...`)
  })

  it('measures in code points, after stripping', () => {
    const emoji = '\u{1F600}'.repeat(65)
    expect(servedIdentifier(emoji)).toBe(`${'\u{1F600}'.repeat(64)}...`)
    expect(servedIdentifier(`${'c'.repeat(64)}\u0000\u0001`)).toBe(
      'c'.repeat(64)
    )
  })
})
