/**
 * Unit tests for the `did:web` projection writers
 * (`src/webvh/didWebProjection.ts`) over a real in-memory did:webvh log: the
 * freshness ensure's verdicts (absent, unparsable, different, equal), its
 * key-order insensitivity, the fact that an already-current projection costs
 * no write, and the two ordering guards -- the `refresh` re-compare that
 * keeps a caller's older snapshot from overwriting a newer writer's
 * projection, and the compare-and-swap that reports `conflict` when one lands
 * between the read and the PUT.
 */
import { describe, expect, it } from 'vitest'
import { generateParallelDidWeb, type DIDDoc } from '@interop/did-method-webvh'
import {
  ensureDidWebProjection,
  putDidWebProjection
} from '../../src/webvh/didWebProjection.js'
import {
  ensureDidWebvh,
  mintClientWebvhUpdateKeys,
  readPublishedLog,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import {
  DID_DOCUMENT_RESOURCE,
  DID_LOG_RESOURCE
} from '../../src/space/collections.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-did-web-projection'

/**
 * A provisioned account: its store, its DID, and the resolved document the
 * projection derives from.
 *
 * @returns {Promise<object>}
 */
async function projectionFixture() {
  const { idStore, didDocument, log } = memoryIdStore()
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
    updateKeys: await mintClientWebvhUpdateKeys()
  })
  const published = await readPublishedLog({ idStore })
  return { idStore, didDocument, log, did, doc: published!.doc }
}

/**
 * The store wrapped so every `putIdResource` is recorded.
 *
 * @param idStore {WebvhIdStore}
 * @returns {object}
 */
function recordingStore(idStore: WebvhIdStore): {
  store: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'>
  writes: string[]
} {
  const writes: string[] = []
  return {
    writes,
    store: {
      getIdResourceRaw: options => idStore.getIdResourceRaw(options),
      async putIdResource(options) {
        writes.push(options.resourceId)
        return idStore.putIdResource(options)
      }
    }
  }
}

describe('ensureDidWebProjection', () => {
  it('writes nothing when the served projection already matches', async () => {
    const fixture = await projectionFixture()
    const recorder = recordingStore(fixture.idStore)

    const outcome = await ensureDidWebProjection({
      store: recorder.store,
      did: fixture.did,
      doc: fixture.doc
    })

    expect(outcome).toEqual({ outcome: 'current' })
    expect(recorder.writes).toEqual([])
  })

  it('ignores object key order in the served document', async () => {
    const fixture = await projectionFixture()
    // The same document, every object's keys reversed -- what a host (or a
    // second serializer) can legitimately serve back.
    const reversed = reverseKeys(
      generateParallelDidWeb(fixture.did, fixture.doc)
    )
    await fixture.idStore.putIdResource({
      resourceId: DID_DOCUMENT_RESOURCE,
      content: reversed as object,
      contentType: 'application/did+json'
    })
    const recorder = recordingStore(fixture.idStore)

    const outcome = await ensureDidWebProjection({
      store: recorder.store,
      did: fixture.did,
      doc: fixture.doc
    })

    expect(outcome).toEqual({ outcome: 'current' })
    expect(recorder.writes).toEqual([])
  })

  it('republishes an absent projection', async () => {
    const fixture = await projectionFixture()
    // A Space holding the log and no `did.json` at all -- what the
    // ladder-anchored genesis path leaves, its entries publishing the log
    // alone.
    const logOnly = memoryIdStore()
    await logOnly.idStore.putIdResource({
      resourceId: DID_LOG_RESOURCE,
      content: fixture.log()!,
      contentType: 'text/jsonl'
    })

    const outcome = await ensureDidWebProjection({
      store: logOnly.idStore,
      did: fixture.did,
      doc: fixture.doc
    })

    expect(outcome).toEqual({ outcome: 'republished' })
    expect(logOnly.didDocument()).toEqual(
      generateParallelDidWeb(fixture.did, fixture.doc)
    )
  })

  it('republishes a projection that differs from the resolved log', async () => {
    const fixture = await projectionFixture()
    const stale = generateParallelDidWeb(fixture.did, fixture.doc) as DIDDoc & {
      assertionMethod?: unknown[]
    }
    await fixture.idStore.putIdResource({
      resourceId: DID_DOCUMENT_RESOURCE,
      content: {
        ...stale,
        assertionMethod: [
          ...(stale.assertionMethod ?? []),
          `${fixture.did}#zRetiredKeyThatIsNotInTheLog`
        ]
      },
      contentType: 'application/did+json'
    })

    const outcome = await ensureDidWebProjection({
      store: fixture.idStore,
      did: fixture.did,
      doc: fixture.doc
    })

    expect(outcome).toEqual({ outcome: 'republished' })
    expect(JSON.stringify(fixture.didDocument())).not.toContain(
      'zRetiredKeyThatIsNotInTheLog'
    )
    expect(fixture.didDocument()).toEqual(
      generateParallelDidWeb(fixture.did, fixture.doc)
    )
  })

  it('republishes an unparsable projection', async () => {
    const fixture = await projectionFixture()
    const garbled: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'> = {
      // The stored body replaced by a garbled one, its validator kept: the
      // ensure's PUT is a compare-and-swap on exactly that validator.
      getIdResourceRaw: async ({ resourceId }) => {
        const served = await fixture.idStore.getIdResourceRaw({ resourceId })
        return resourceId === DID_DOCUMENT_RESOURCE && served !== undefined
          ? { ...served, text: '{ not json' }
          : served
      },
      putIdResource: options => fixture.idStore.putIdResource(options)
    }

    const outcome = await ensureDidWebProjection({
      store: garbled,
      did: fixture.did,
      doc: fixture.doc
    })

    expect(outcome).toEqual({ outcome: 'republished' })
    expect(fixture.didDocument()).toEqual(
      generateParallelDidWeb(fixture.did, fixture.doc)
    )
  })

  it('leaves a newer served projection alone when refresh re-resolves it', async () => {
    // The ordering defect this closes: the caller's `doc` was resolved at the
    // start of a visit, and another client published an inventory-removing
    // entry plus its correct projection since. The plain compare sees only a
    // difference, and writing the caller's snapshot would restore the key the
    // account just struck.
    const fixture = await projectionFixture()
    const newerDoc = {
      ...fixture.doc,
      capabilityInvocation: []
    } as unknown as DIDDoc
    await fixture.idStore.putIdResource({
      resourceId: DID_DOCUMENT_RESOURCE,
      content: generateParallelDidWeb(fixture.did, newerDoc) as object,
      contentType: 'application/did+json'
    })
    const recorder = recordingStore(fixture.idStore)
    let refreshed = 0

    const outcome = await ensureDidWebProjection({
      store: recorder.store,
      did: fixture.did,
      doc: fixture.doc,
      refresh: async () => {
        refreshed++
        return { did: fixture.did, doc: newerDoc }
      }
    })

    expect(outcome).toEqual({ outcome: 'current' })
    expect(refreshed).toBe(1)
    expect(recorder.writes).toEqual([])
    expect(fixture.didDocument()).toEqual(
      generateParallelDidWeb(fixture.did, newerDoc)
    )
  })

  it('republishes when the refreshed derivation still differs', async () => {
    const fixture = await projectionFixture()
    await fixture.idStore.putIdResource({
      resourceId: DID_DOCUMENT_RESOURCE,
      content: { id: `did:web:stale`, verificationMethod: [] },
      contentType: 'application/did+json'
    })

    const outcome = await ensureDidWebProjection({
      store: fixture.idStore,
      did: fixture.did,
      doc: fixture.doc,
      refresh: async () => ({ did: fixture.did, doc: fixture.doc })
    })

    expect(outcome).toEqual({ outcome: 'republished' })
    expect(fixture.didDocument()).toEqual(
      generateParallelDidWeb(fixture.did, fixture.doc)
    )
  })

  it('reports a conflict when the PUT loses its precondition', async () => {
    const fixture = await projectionFixture()
    // A stale served projection, so the ensure reaches its write ...
    await fixture.idStore.putIdResource({
      resourceId: DID_DOCUMENT_RESOURCE,
      content: { id: `did:web:stale`, verificationMethod: [] },
      contentType: 'application/did+json'
    })
    const concurrent = generateParallelDidWeb(fixture.did, fixture.doc)
    const racing: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'> = {
      // ... and another writer lands between that read and the PUT, so the
      // validator the ensure carries is already spent.
      getIdResourceRaw: async options => {
        const served = await fixture.idStore.getIdResourceRaw(options)
        if (options.resourceId === DID_DOCUMENT_RESOURCE) {
          await fixture.idStore.putIdResource({
            resourceId: DID_DOCUMENT_RESOURCE,
            content: concurrent as object,
            contentType: 'application/did+json'
          })
        }
        return served
      },
      putIdResource: options => fixture.idStore.putIdResource(options)
    }

    const outcome = await ensureDidWebProjection({
      store: racing,
      did: fixture.did,
      doc: fixture.doc
    })

    // No throw, and the concurrent writer's projection stands.
    expect(outcome).toEqual({ outcome: 'conflict' })
    expect(fixture.didDocument()).toEqual(concurrent)
  })

  it('propagates a read failure rather than writing blind', async () => {
    const fixture = await projectionFixture()
    const recorder = recordingStore(fixture.idStore)
    const failing: Pick<WebvhIdStore, 'getIdResourceRaw' | 'putIdResource'> = {
      getIdResourceRaw: async () => {
        throw new Error('the host is down')
      },
      putIdResource: recorder.store.putIdResource
    }

    await expect(
      ensureDidWebProjection({
        store: failing,
        did: fixture.did,
        doc: fixture.doc
      })
    ).rejects.toThrow('the host is down')
    expect(recorder.writes).toEqual([])
  })
})

describe('putDidWebProjection', () => {
  it('writes did.json under the did+json content type', async () => {
    const fixture = await projectionFixture()
    const seen: Array<{ resourceId: string; contentType?: string }> = []
    const webDoc = generateParallelDidWeb(fixture.did, fixture.doc)

    await putDidWebProjection({
      store: {
        async putIdResource(options) {
          seen.push({
            resourceId: options.resourceId,
            ...(options.contentType !== undefined
              ? { contentType: options.contentType }
              : {})
          })
          return fixture.idStore.putIdResource(options)
        }
      },
      webDoc
    })

    expect(seen).toEqual([
      { resourceId: 'did.json', contentType: 'application/did+json' }
    ])
    expect(fixture.didDocument()).toEqual(webDoc)
  })
})

/**
 * The same JSON value with every object's key order reversed. Used to prove
 * the ensure's comparison is structural rather than serialized-string
 * equality.
 *
 * @param value {unknown}
 * @returns {unknown}
 */
function reverseKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(member => reverseKeys(member))
  }
  if (typeof value !== 'object' || value === null) {
    return value
  }
  const entries = Object.entries(value as Record<string, unknown>).reverse()
  return Object.fromEntries(
    entries.map(([key, member]) => [key, reverseKeys(member)])
  )
}
