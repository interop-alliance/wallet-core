/**
 * Tests for the resource-log class dispatch (`src/resourceLog/logClass.ts`):
 * which admission rule a controller view carries for the log it is about to
 * verify or extend. The user key roster class keeps the adapter's view
 * untouched, so the ceremony-tail license stands; the collection-descriptor
 * class narrows the hook to `assertionMethod` membership at the anchored
 * version, so an append the license refuses -- a ladder-signed rotation
 * against an unchanged document -- verifies. What the narrowing does NOT
 * touch is membership itself, which the library settles before the hook runs:
 * an entry signed by a key the anchored version does not back is refused
 * under either class.
 */
import { describe, expect, it } from 'vitest'
import {
  buildResourceLogEntry,
  buildResourceLogGenesis,
  verifyResourceLog,
  ResourceLogIntegrityError,
  type ResourceLogSigner
} from '@interop/vh-resource-log'
import {
  controllerForLogClass,
  ResourceLogLicenseError,
  type WebvhResourceLogController
} from '../../src/resourceLog/index.js'
import { makeRosterClient } from './fixtures/rosterClient.js'
import { fakeController } from './fixtures/resourceLog.js'

const METHOD = 'resource-log:0.1'

/**
 * An account whose document backs one enrolled client (alice) and one ladder
 * VM across two versions, the second of which changed nothing: a
 * ladder-signed append anchored at it is exactly the silent-rekey shape the
 * ceremony-tail license refuses.
 */
async function makeAccount() {
  const alice = await makeRosterClient()
  const ladder = await makeRosterClient()
  const stranger = await makeRosterClient()
  const version = (versionId: string) => ({
    versionId,
    keys: [alice.signingKeyMultibase, ladder.signingKeyMultibase],
    ladderKeys: [ladder.signingKeyMultibase],
    inventoryKeys: ['credA']
  })
  const beforeEdit = fakeController({ versions: [version('1-v1')] })
  const unchangedEdit = fakeController({
    versions: [version('1-v1'), version('2-v2')]
  })
  return { alice, ladder, stranger, beforeEdit, unchangedEdit }
}

/**
 * Runs a call expected to refuse and hands back what it threw.
 *
 * @param run {function}   `() => Promise<unknown>`
 * @returns {Promise<unknown>}
 */
async function caughtFrom(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run()
  } catch (err) {
    return err
  }
  throw new Error('expected a refusal, but the call resolved')
}

describe('controllerForLogClass', () => {
  it('hands the roster class the adapter view unchanged', async () => {
    const { beforeEdit } = await makeAccount()
    expect(
      controllerForLogClass({
        controller: beforeEdit,
        logClass: 'user-key-roster'
      })
    ).toBe(beforeEdit)
  })

  it('keeps every member but the hook for the collection-descriptor class', async () => {
    const { beforeEdit } = await makeAccount()
    const narrowed = controllerForLogClass({
      controller: beforeEdit,
      logClass: 'collection-descriptor'
    })
    expect(narrowed).not.toBe(beforeEdit)
    expect(narrowed.did).toBe(beforeEdit.did)
    expect(narrowed.versionIds).toEqual(beforeEdit.versionIds)
    expect([...(await narrowed.assertionKeysAt('1-v1'))]).toEqual([
      ...(await beforeEdit.assertionKeysAt('1-v1'))
    ])
    expect((await narrowed.inventoryAt('1-v1')).inventoryKeys).toEqual(
      (await beforeEdit.inventoryAt('1-v1')).inventoryKeys
    )
    // The hook stays a real function; the type makes it mandatory.
    expect(typeof narrowed.admitAppend).toBe('function')
  })
})

describe('the class dispatch end to end (verifyResourceLog)', () => {
  /**
   * The silent-rekey shape: a ladder-signed genesis, then a ladder-signed
   * rotation anchored at a version that changed nothing.
   */
  async function ladderRotation({
    ladder,
    beforeEdit,
    unchangedEdit
  }: {
    ladder: { logSigner: ResourceLogSigner }
    beforeEdit: WebvhResourceLogController
    unchangedEdit: WebvhResourceLogController
  }) {
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: beforeEdit,
      signer: ladder.logSigner
    })
    const rotation = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 2 },
      controller: unchangedEdit,
      signer: ladder.logSigner
    })
    return [genesis, rotation]
  }

  it('refuses the ladder-signed rotation under the roster class', async () => {
    const { ladder, beforeEdit, unchangedEdit } = await makeAccount()
    const entries = await ladderRotation({ ladder, beforeEdit, unchangedEdit })
    const caught = await caughtFrom(() =>
      verifyResourceLog({
        entries,
        controller: controllerForLogClass({
          controller: unchangedEdit,
          logClass: 'user-key-roster'
        }),
        expectedMethod: METHOD
      })
    )
    expect(caught).toBeInstanceOf(ResourceLogLicenseError)
    expect((caught as Error).name).toBe('ResourceLogLicenseError')
  })

  it('admits the same rotation under the collection-descriptor class', async () => {
    const { ladder, beforeEdit, unchangedEdit } = await makeAccount()
    const entries = await ladderRotation({ ladder, beforeEdit, unchangedEdit })
    const verified = await verifyResourceLog({
      entries,
      controller: controllerForLogClass({
        controller: unchangedEdit,
        logClass: 'collection-descriptor'
      }),
      expectedMethod: METHOD
    })
    expect(verified.state).toEqual({ type: 'TestState', value: 2 })
    expect(verified.headControllerVersionIndex).toBe(1)
  })

  it('admits an ordinary client-signed append under both classes', async () => {
    const { alice, beforeEdit, unchangedEdit } = await makeAccount()
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: beforeEdit,
      signer: alice.logSigner
    })
    const append = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 2 },
      controller: unchangedEdit,
      signer: alice.logSigner
    })
    for (const logClass of [
      'user-key-roster',
      'collection-descriptor'
    ] as const) {
      const verified = await verifyResourceLog({
        entries: [genesis, append],
        controller: controllerForLogClass({
          controller: unchangedEdit,
          logClass
        }),
        expectedMethod: METHOD
      })
      expect(verified.state).toEqual({ type: 'TestState', value: 2 })
    }
  })

  it('still refuses a signer the anchored version does not back', async () => {
    // The narrowing is of the license alone: `assertionMethod` membership is
    // the library's check, and it runs before the hook.
    const { alice, stranger, beforeEdit, unchangedEdit } = await makeAccount()
    const genesis = await buildResourceLogGenesis({
      state: { type: 'TestState', value: 1 },
      method: METHOD,
      controller: beforeEdit,
      signer: alice.logSigner
    })
    const foreign = await buildResourceLogEntry({
      head: genesis,
      state: { type: 'TestState', value: 2 },
      controller: unchangedEdit,
      signer: stranger.logSigner
    })
    const caught = await caughtFrom(() =>
      verifyResourceLog({
        entries: [genesis, foreign],
        controller: controllerForLogClass({
          controller: unchangedEdit,
          logClass: 'collection-descriptor'
        }),
        expectedMethod: METHOD
      })
    )
    expect(caught).toBeInstanceOf(ResourceLogIntegrityError)
  })
})
