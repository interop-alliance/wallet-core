/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
import { captureLogger } from '@interop/logger'
import { beforeEach, describe, expect, it } from 'vitest'
import {
  heldAuthorities,
  MEND_REPORT_SHAPE_ERROR,
  menderRegistry,
  mendReportAccumulator,
  runMenderBlock,
  type InvariantDeclaration,
  type InvariantId,
  type MendReportEntry,
  type Registration,
  type Trigger
} from '../../src/menders/index.js'
import { declaration } from './fixtures/menderDeclaration.js'

/**
 * The block's dependency object: one per registration block, the wallet's
 * own type, handed to every converger unread.
 */
interface Deps {
  ran: InvariantId[]
}

const SEED_ID: InvariantId = 'roster-wraps-exactly-the-document-key-set'
const FIRST_ID: InvariantId = 'unlock-registry-opens-under-the-current-user-key'
const SECOND_ID: InvariantId =
  'standing-delegations-verify-under-the-current-document'
const POPUP_ID: InvariantId = 'no-annex-generation-outlives-its-pointer'

const declarations: ReadonlyArray<InvariantDeclaration<Deps>> = [
  declaration({
    id: SEED_ID,
    authority: 'account',
    ceremonies: ['client-revocation']
  }),
  declaration({ id: FIRST_ID, authority: 'account' }),
  declaration({ id: SECOND_ID, authority: 'account' }),
  declaration({
    id: POPUP_ID,
    authority: 'enrolled',
    when: route => !route.popup
  })
]

/**
 * A registration whose converger records that it ran and reports one entry
 * per id, unless `throws` is given.
 */
function registration({
  reports,
  trigger = 'remembered-login-chain',
  outcome = 'clean',
  throws,
  entries
}: {
  reports: ReadonlyArray<InvariantId>
  trigger?: Exclude<Trigger, 'login-routing'>
  outcome?: 'clean' | 'noop'
  throws?: Error
  entries?: ReadonlyArray<MendReportEntry>
}): Registration<Deps> {
  return {
    trigger,
    reports,
    async converge(deps) {
      for (const id of reports) {
        deps.ran.push(id)
      }
      if (throws) {
        throw throws
      }
      return entries ?? reports.map(invariant => ({ invariant, outcome }))
    }
  }
}

let capture: ReturnType<typeof captureLogger>

beforeEach(() => {
  capture = captureLogger()
})

/**
 * Runs a block on the remembered chain as an enrolled client on the page
 * route, logging into `capture`; a test overrides what its case turns on.
 */
function runBlock(
  options: Partial<Parameters<typeof runMenderBlock<Deps>>[0]> &
    Pick<Parameters<typeof runMenderBlock<Deps>>[0], 'registry' | 'deps'>
): ReturnType<typeof runMenderBlock<Deps>> {
  return runMenderBlock<Deps>({
    trigger: 'remembered-login-chain',
    held: heldAuthorities({ kind: 'enrolled' }),
    route: { popup: false },
    logger: capture.logger,
    ...options
  })
}

function warnings(): ReadonlyArray<string> {
  return capture.events
    .filter(event => event.level === 'warn')
    .map(event => event.msg)
}

describe('runMenderBlock', () => {
  it('runs the registrations of one chain trigger in list order', async () => {
    const deps: Deps = { ran: [] }
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [
        registration({ reports: [SECOND_ID] }),
        registration({ reports: [FIRST_ID] }),
        registration({ reports: [FIRST_ID], trigger: 'ceremony-tail' })
      ]
    })
    const report = await runBlock({
      registry,
      deps
    })
    expect(deps.ran).toEqual([SECOND_ID, FIRST_ID])
    expect(report).toEqual([
      { invariant: SECOND_ID, outcome: 'clean' },
      { invariant: FIRST_ID, outcome: 'clean' }
    ])
    expect(warnings()).toEqual([])
  })

  it('skips a registration whose reported declaration refuses this route', async () => {
    const deps: Deps = { ran: [] }
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [
        registration({ reports: [FIRST_ID, POPUP_ID] }),
        registration({ reports: [SECOND_ID] })
      ]
    })
    const inPopup = await runBlock({
      registry,
      route: { popup: true },
      deps
    })
    expect(inPopup.map(entry => entry.invariant)).toEqual([SECOND_ID])
    expect(deps.ran).toEqual([SECOND_ID])

    const onPage = await runBlock({
      registry,
      deps: { ran: [] }
    })
    expect(onPage.map(entry => entry.invariant)).toEqual([
      FIRST_ID,
      POPUP_ID,
      SECOND_ID
    ])
  })

  it('aborts the block when the seed fails, and runs no registration', async () => {
    const deps: Deps = { ran: [] }
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [registration({ reports: [FIRST_ID] })]
    })
    const seen: MendReportEntry[] = []
    const report = await runBlock({
      registry,
      deps,
      seed: registration({
        reports: [SEED_ID],
        throws: new TypeError('the roster read named did:webvh:example')
      }),
      onOutcome: entry => seen.push(entry)
    })
    expect(deps.ran).toEqual([SEED_ID])
    expect(report).toEqual([
      {
        invariant: SEED_ID,
        outcome: 'failed',
        errorName: 'TypeError',
        ceremonies: ['client-revocation']
      }
    ])
    expect(seen).toEqual(report)
    expect(warnings()).toEqual([
      `Could not converge ${SEED_ID}; the next login retries`
    ])
  })

  it('runs the seed first and the block behind it when it succeeds', async () => {
    const deps: Deps = { ran: [] }
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [registration({ reports: [FIRST_ID] })]
    })
    const report = await runBlock({
      registry,
      deps,
      seed: registration({ reports: [SEED_ID], outcome: 'noop' })
    })
    expect(deps.ran).toEqual([SEED_ID, FIRST_ID])
    expect(report.map(entry => entry.outcome)).toEqual(['noop', 'clean'])
  })

  it('skips a seed the held set does not satisfy, and still runs the block', async () => {
    const deps: Deps = { ran: [] }
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [
        registration({ reports: [FIRST_ID], trigger: 'transient-login-chain' })
      ]
    })
    const report = await runBlock({
      registry,
      trigger: 'transient-login-chain',
      held: heldAuthorities({ kind: 'ladder' }),
      deps,
      seed: registration({
        reports: [POPUP_ID],
        trigger: 'transient-login-chain'
      })
    })
    expect(deps.ran).toEqual([FIRST_ID])
    expect(report.map(entry => entry.invariant)).toEqual([FIRST_ID])
    expect(warnings()).toEqual([])
  })

  it('warns with each declaration warn string, reports failed, and carries on', async () => {
    const deps: Deps = { ran: [] }
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [
        registration({
          reports: [FIRST_ID, SECOND_ID],
          throws: new RangeError('a message naming urn:uuid:space')
        }),
        registration({ reports: [POPUP_ID] })
      ]
    })
    const report = await runBlock({
      registry,
      deps
    })
    expect(warnings()).toEqual([
      `Could not converge ${FIRST_ID}; the next login retries`,
      `Could not converge ${SECOND_ID}; the next login retries`
    ])
    expect(report).toEqual([
      { invariant: FIRST_ID, outcome: 'failed', errorName: 'RangeError' },
      { invariant: SECOND_ID, outcome: 'failed', errorName: 'RangeError' },
      { invariant: POPUP_ID, outcome: 'clean' }
    ])
    // The error itself rides the logger; only its name rides the report.
    for (const entry of report) {
      expect(JSON.stringify(entry)).not.toContain('urn:uuid:space')
    }
    const warned = capture.events.find(event => event.level === 'warn')
    expect(warned?.err).toBeInstanceOf(RangeError)
    expect(deps.ran).toEqual([FIRST_ID, SECOND_ID, POPUP_ID])
  })

  it('normalizes a registration whose entries do not match its reports', async () => {
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [
        registration({
          reports: [FIRST_ID, SECOND_ID],
          entries: [{ invariant: SECOND_ID, outcome: 'clean' }]
        }),
        registration({ reports: [POPUP_ID] })
      ]
    })
    const report = await runBlock({
      registry,
      deps: { ran: [] }
    })
    expect(report).toEqual([
      {
        invariant: FIRST_ID,
        outcome: 'failed',
        errorName: MEND_REPORT_SHAPE_ERROR
      },
      {
        invariant: SECOND_ID,
        outcome: 'failed',
        errorName: MEND_REPORT_SHAPE_ERROR
      },
      { invariant: POPUP_ID, outcome: 'clean' }
    ])
    expect(warnings()).toEqual([
      'A mender registration returned entries that do not match the invariants it reports'
    ])
  })

  it('reports every entry through onOutcome once, in order', async () => {
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [
        registration({ reports: [FIRST_ID, SECOND_ID] }),
        registration({ reports: [POPUP_ID] })
      ]
    })
    const seen: MendReportEntry[] = []
    const report = await runBlock({
      registry,
      deps: { ran: [] },
      seed: registration({ reports: [SEED_ID] }),
      onOutcome: entry => seen.push(entry)
    })
    expect(seen.map(entry => entry.invariant)).toEqual([
      SEED_ID,
      FIRST_ID,
      SECOND_ID,
      POPUP_ID
    ])
    expect(seen).toEqual(report)
  })

  it('runs a supplied registration list in place of the registry lists', async () => {
    const first = registration({ reports: [FIRST_ID] })
    const second = registration({ reports: [SECOND_ID] })
    const popup = registration({ reports: [POPUP_ID] })
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [first, second, popup]
    })
    const deps: Deps = { ran: [] }
    const report = await runBlock({
      registry,
      route: { popup: true },
      deps,
      // The tail of the same trigger's list, and one entry this route
      // refuses: the override narrows the block, and the route test still
      // admits each one.
      registrations: [second, popup]
    })
    expect(deps.ran).toEqual([SECOND_ID])
    expect(report).toEqual([{ invariant: SECOND_ID, outcome: 'clean' }])
  })

  it('refuses a seed or override registration listed under another trigger', async () => {
    const first = registration({ reports: [FIRST_ID] })
    const transient = registration({
      reports: [SECOND_ID],
      trigger: 'transient-login-chain'
    })
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [first, transient]
    })
    const deps: Deps = { ran: [] }
    await expect(
      runBlock({ registry, deps, registrations: [first, transient] })
    ).rejects.toThrow(TypeError)
    await expect(runBlock({ registry, deps, seed: transient })).rejects.toThrow(
      TypeError
    )
    expect(deps.ran).toEqual([])
  })
})

describe('mendReportAccumulator', () => {
  it('assembles the routing entries and the block entries in report order', async () => {
    const accumulator = mendReportAccumulator()
    accumulator.report({
      invariant: 'client-key-record-matches-the-pointed-account',
      outcome: 'clean'
    })
    const registry = menderRegistry<Registration<Deps>, Deps>({
      declarations,
      sites: [registration({ reports: [FIRST_ID] })]
    })
    await runBlock({
      registry,
      deps: { ran: [] },
      onOutcome: accumulator.report
    })
    accumulator.report({ invariant: POPUP_ID, outcome: 'noop' })
    accumulator.settle()
    await expect(accumulator.settled).resolves.toEqual([
      {
        invariant: 'client-key-record-matches-the-pointed-account',
        outcome: 'clean'
      },
      { invariant: FIRST_ID, outcome: 'clean' },
      { invariant: POPUP_ID, outcome: 'noop' }
    ])
  })

  it('fixes the settled report at the first settle', async () => {
    const accumulator = mendReportAccumulator()
    accumulator.report({ invariant: FIRST_ID, outcome: 'clean' })
    const first = accumulator.settle()
    accumulator.report({ invariant: SECOND_ID, outcome: 'refused' })
    expect(accumulator.settle()).toBe(first)
    await expect(accumulator.settled).resolves.toEqual([
      { invariant: FIRST_ID, outcome: 'clean' }
    ])
    expect(accumulator.entries()).toHaveLength(2)
  })
})
