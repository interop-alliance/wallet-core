/**
 * Tests for the did:webvh controller view (`src/resourceLog/controller.ts`):
 * the per-version `assertionMethod` sets read off an already-verified log's
 * entry `state` (embedded methods and string references alike), the
 * current-document lookup, the refusal on a version the log does not carry,
 * and the ordered version list.
 */
import { describe, expect, it } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import { webvhResourceLogController } from '../../src/resourceLog/index.js'
import { relationKeyMultibases } from '@interop/vh-resource-log'

const DID = 'did:webvh:scid:example.com:space:abc:id'
const ALICE = 'z6MkAlice'
const BOB = 'z6MkBob'
const CAROL = 'z6MkCarol'

/**
 * A minimal already-verified log: each entry carries only the `versionId` and
 * the resolved document `state` the controller view reads. The adapter is
 * documented as trusting a verified log, so no parameters, hashes, or proofs
 * are needed here.
 */
function makeLog(): DIDLog {
  return [
    {
      versionId: '1-v1',
      state: {
        id: DID,
        verificationMethod: [
          { id: `${DID}#alice`, publicKeyMultibase: ALICE },
          { id: `${DID}#bob`, publicKeyMultibase: BOB }
        ],
        // String references, resolved through `verificationMethod`.
        assertionMethod: [`${DID}#alice`, `${DID}#bob`]
      }
    },
    {
      versionId: '2-v2',
      state: {
        id: DID,
        verificationMethod: [{ id: `${DID}#alice`, publicKeyMultibase: ALICE }],
        // An embedded method alongside a reference.
        assertionMethod: [
          `${DID}#alice`,
          { id: `${DID}#carol`, publicKeyMultibase: CAROL }
        ]
      }
    }
  ] as unknown as DIDLog
}

describe('webvhResourceLogController', () => {
  it('reports the log versions in order', () => {
    const controller = webvhResourceLogController({ did: DID, log: makeLog() })
    expect(controller.did).toEqual(DID)
    expect(controller.versionIds).toEqual(['1-v1', '2-v2'])
  })

  it('answers each version with that entry state, read for its assertion keys', async () => {
    const log = makeLog()
    const controller = webvhResourceLogController({ did: DID, log })
    const keysAt = async (versionId: string) =>
      [
        ...relationKeyMultibases({
          doc: await controller.documentAt(versionId),
          relation: 'assertionMethod'
        })
      ].sort()
    expect(await controller.documentAt('1-v1')).toBe(log[0]!.state)
    expect(await keysAt('1-v1')).toEqual([ALICE, BOB].sort())
    expect(await keysAt('2-v2')).toEqual([ALICE, CAROL].sort())
  })

  it('resolves the head entry for the current document', async () => {
    const log = makeLog()
    const controller = webvhResourceLogController({ did: DID, log })
    expect(await controller.documentAt()).toBe(log[1]!.state)
  })

  it('refuses a version the log does not carry', async () => {
    const controller = webvhResourceLogController({ did: DID, log: makeLog() })
    let caught: { name?: string; message?: string } | null = null
    try {
      await controller.documentAt('3-v3')
    } catch (err) {
      caught = err as { name?: string; message?: string }
    }
    expect(caught?.name).toEqual('ResourceLogIntegrityError')
    expect(caught?.message).toContain('3-v3')
  })

  it('refuses the current document on an empty log', async () => {
    const controller = webvhResourceLogController({
      did: DID,
      log: [] as unknown as DIDLog
    })
    expect(controller.versionIds).toEqual([])
    let caught: { name?: string } | null = null
    try {
      await controller.documentAt()
    } catch (err) {
      caught = err as { name?: string }
    }
    expect(caught?.name).toEqual('ResourceLogIntegrityError')
  })
})
