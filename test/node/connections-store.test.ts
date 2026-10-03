/**
 * Unit tests for the WAS adapter of the `connections` store
 * (`src/connections/store.ts`), over a fake Collection handle whose
 * documents feed is was-client's own walk: the listing read one request per
 * feed page with each body's ETag, a read at an unknown epoch reported
 * rather than returned as absent, a new body sealed at its derived id, and
 * the create race (two creates at one id, the loser re-reading and merging).
 */
import { describe, expect, it } from 'vitest'
import {
  Collection,
  IntegrityError,
  PreconditionFailedError
} from '@interop/was-client'
import type {
  ChangeDocument,
  ChangesCheckpoint,
  Json
} from '@interop/was-client'
import { UnknownEpochError } from '@interop/was-client/edv/cipher'
import {
  connectionResourceId,
  readConnections,
  recordGrants,
  wasConnectionsStore
} from '../../src/connections/index.js'
import { HMAC_KEY, SPACE_URL, zcap } from './fixtures/memoryConnections.js'

const AGENT = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const SECOND = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
const THIRD = 'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf'
const CONTEXT = { marker: 'codec context' }

/**
 * A stand-in for an EDV envelope: the id it was sealed for, the epoch it was
 * sealed under, and the plaintext.
 */
interface FakeEnvelope {
  sealedFor: string
  epoch: string
  payload: unknown
}

/**
 * The fake cipher's open: refuses an envelope sealed under an epoch it does
 * not hold, or one sealed for another id.
 *
 * @param options {object}
 * @returns {unknown}
 */
function open({ id, envelope }: { id: string; envelope: unknown }): unknown {
  const sealed = envelope as FakeEnvelope
  if (sealed.epoch !== 'current') {
    throw new UnknownEpochError({
      collectionId: 'connections',
      kids: [sealed.epoch]
    })
  }
  if (sealed.sealedFor !== id) {
    throw new IntegrityError('The envelope was sealed for another resource.')
  }
  return structuredClone(sealed.payload)
}

/**
 * A fake `connections` Collection handle. Its feed serves at most two
 * documents per page, and its `documents()` is was-client's own walk over
 * that feed.
 *
 * @returns {object}
 */
function fakeCollection() {
  const resources = new Map<
    string,
    { envelope: FakeEnvelope; etag: string; updatedAt: string }
  >()
  let revision = 0
  const calls: string[] = []
  const puts: Array<{ id: string; options: Record<string, unknown> }> = []
  let getBarrier: Promise<void> | undefined
  let releaseGets = () => {}

  const fake = {
    id: 'connections',
    spaceId: 'SPACE',
    codecContext() {
      return CONTEXT
    },
    async changes({
      checkpoint
    }: {
      checkpoint?: ChangesCheckpoint
      limit?: number
    }) {
      calls.push('changes')
      const ordered = [...resources]
        .map(([id, row]): ChangeDocument => ({
          id,
          _deleted: false,
          updatedAt: row.updatedAt,
          checkpoint: `${row.updatedAt}|${id}`,
          updatedAtCounter: 0,
          originId: 'origin-test',
          etag: row.etag,
          data: row.envelope as unknown as Json
        }))
        .sort((left, right) =>
          left.updatedAt === right.updatedAt
            ? left.id < right.id
              ? -1
              : 1
            : left.updatedAt < right.updatedAt
              ? -1
              : 1
        )
        .filter(doc => checkpoint === undefined || doc.checkpoint > checkpoint)
      const documents = ordered.slice(0, 2)
      const last = documents.at(-1)
      return {
        documents,
        checkpoint:
          ordered.length > 2 && last !== undefined ? last.checkpoint : null
      }
    },
    documents(options?: { limit?: number }) {
      return Collection.prototype.documents.call(
        fake as unknown as Collection,
        options
      )
    },
    resource(id: string) {
      return {
        async getWithEtag() {
          calls.push(`get:${id}`)
          if (getBarrier !== undefined) {
            await getBarrier
          }
          const row = resources.get(id)
          if (row === undefined) {
            return null
          }
          return {
            data: open({ id, envelope: row.envelope }),
            etag: row.etag
          }
        }
      }
    },
    async put(
      id: string,
      data: unknown,
      options: { ifMatch?: string; ifNoneMatch?: boolean } = {}
    ) {
      puts.push({ id, options })
      const row = resources.get(id)
      if (options.ifNoneMatch === true && row !== undefined) {
        throw new PreconditionFailedError('exists')
      }
      if (options.ifMatch !== undefined && row?.etag !== options.ifMatch) {
        throw new PreconditionFailedError('stale')
      }
      revision++
      const etag = `"e${revision}"`
      resources.set(id, {
        envelope: { sealedFor: id, epoch: 'current', payload: data },
        etag,
        updatedAt: `2026-10-01T00:00:${String(revision).padStart(2, '0')}Z`
      })
      return { etag }
    }
  }
  return {
    collection: fake as unknown as Collection,
    resources,
    calls,
    puts,
    holdGets(count: number) {
      let seen = 0
      getBarrier = new Promise<void>(resolve => {
        releaseGets = resolve
      })
      const original = fake.resource
      fake.resource = (id: string) => {
        const handle = original(id)
        return {
          ...handle,
          async getWithEtag() {
            seen++
            if (seen === count) {
              releaseGets()
              getBarrier = undefined
            }
            return handle.getWithEtag()
          }
        }
      }
    }
  }
}

const cipher = {
  async decrypt({
    id,
    envelope,
    context
  }: {
    id: string
    envelope: Json
    context?: unknown
  }) {
    expect(context).toBe(CONTEXT)
    return open({ id, envelope }) as Json
  }
}

async function record(
  store: ReturnType<typeof wasConnectionsStore>,
  did: string,
  zcapId: string
) {
  return recordGrants({
    store,
    hmacKey: HMAC_KEY,
    spaceUrl: SPACE_URL,
    did,
    kind: 'agent',
    grants: [
      { zcap: zcap({ id: zcapId, controller: did }), grantKind: 'grant' }
    ]
  })
}

describe('wasConnectionsStore', () => {
  it('seals a new body at its derived id, as a guarded create', async () => {
    const { collection, resources, puts } = fakeCollection()
    const store = wasConnectionsStore({ collection, cipher })
    const result = await record(store, AGENT, 'urn:zcap:1')
    const derived = await connectionResourceId({
      hmacKey: HMAC_KEY,
      did: AGENT
    })
    expect(result).toEqual({ resourceId: derived, outcome: 'created' })
    expect(puts).toEqual([
      {
        id: derived,
        options: { contentType: 'application/json', ifNoneMatch: true }
      }
    ])
    expect(resources.get(derived)?.envelope.sealedFor).toBe(derived)
    expect(await store.get({ resourceId: derived })).toMatchObject({
      body: { id: AGENT, kind: 'agent' },
      etag: '"e1"'
    })
  })

  it('lists through the documents feed, one request per page, with ETags', async () => {
    const { collection, calls } = fakeCollection()
    const store = wasConnectionsStore({ collection, cipher })
    for (const [did, zcapId] of [
      [AGENT, 'urn:zcap:1'],
      [SECOND, 'urn:zcap:2'],
      [THIRD, 'urn:zcap:3']
    ] as const) {
      await record(store, did, zcapId)
    }
    calls.length = 0
    const listed = await store.list()
    // Three entries over two feed pages, and no per-entry GET.
    expect(calls).toEqual(['changes', 'changes'])
    expect(listed).toHaveLength(3)
    for (const item of listed ?? []) {
      expect(item.etag).toMatch(/^"e\d"$/)
      expect(item.body).toMatchObject({ kind: 'agent' })
    }
    const listing = await readConnections({ store, hmacKey: HMAC_KEY })
    expect(listing?.entries.map(item => item.entry.id).sort()).toEqual(
      [AGENT, SECOND, THIRD].sort()
    )
  })

  it('reports a read at an unknown epoch instead of returning it absent', async () => {
    const { collection, resources } = fakeCollection()
    const store = wasConnectionsStore({ collection, cipher })
    const { resourceId } = await record(store, AGENT, 'urn:zcap:1')
    const row = resources.get(resourceId)!
    resources.set(resourceId, {
      ...row,
      envelope: { ...row.envelope, epoch: 'rotated-elsewhere' }
    })
    await expect(store.get({ resourceId })).rejects.toMatchObject({
      name: 'UnknownEpochError'
    })
    const listed = await store.list()
    expect(listed?.[0]).toMatchObject({ resourceId, etag: row.etag })
    expect(listed?.[0]?.body).toBeUndefined()
    expect(listed?.[0]?.readError).toMatchObject({ name: 'UnknownEpochError' })
    const listing = await readConnections({ store, hmacKey: HMAC_KEY })
    expect(listing?.unreadable).toEqual([resourceId])
    // A write over it refuses rather than treating it as absent.
    await expect(record(store, AGENT, 'urn:zcap:2')).rejects.toMatchObject({
      name: 'UnknownEpochError'
    })
  })

  it('reports an envelope served under another id as unreadable', async () => {
    const { collection, resources } = fakeCollection()
    const store = wasConnectionsStore({ collection, cipher })
    const { resourceId } = await record(store, AGENT, 'urn:zcap:1')
    resources.set('zMoved', resources.get(resourceId)!)
    resources.delete(resourceId)
    const listing = await readConnections({ store, hmacKey: HMAC_KEY })
    expect(listing?.entries).toEqual([])
    expect(listing?.unreadable).toEqual(['zMoved'])
  })

  it('lets the loser of a create race re-read and merge', async () => {
    const { collection, resources, puts, holdGets } = fakeCollection()
    const store = wasConnectionsStore({ collection, cipher })
    // Both writers read the id absent before either writes.
    holdGets(2)
    const [first, second] = await Promise.all([
      record(store, AGENT, 'urn:zcap:1'),
      record(store, AGENT, 'urn:zcap:2')
    ])
    expect([first.outcome, second.outcome].sort()).toEqual([
      'created',
      'updated'
    ])
    expect(puts.filter(put => put.options.ifNoneMatch === true)).toHaveLength(2)
    expect(puts.filter(put => put.options.ifMatch !== undefined)).toHaveLength(
      1
    )
    const payload = resources.get(first.resourceId)?.envelope.payload as {
      grants: Array<{ zcap: { id: string } }>
    }
    expect(payload.grants.map(grant => grant.zcap.id).sort()).toEqual([
      'urn:zcap:1',
      'urn:zcap:2'
    ])
  })

  it('reads an absent collection as null', async () => {
    const { collection } = fakeCollection()
    const missing = Object.assign(Object.create(collection) as object, {
      async changes() {
        const err = new Error('missing') as Error & { status: number }
        err.status = 404
        throw err
      }
    }) as unknown as Collection
    // `documents()` resolves a first-page 404 to null.
    Object.assign(missing, {
      documents(options?: { limit?: number }) {
        return Collection.prototype.documents.call(missing, options)
      }
    })
    const store = wasConnectionsStore({ collection: missing, cipher })
    expect(await store.list()).toBeNull()
  })
})
