/**
 * Unit tests for the `connections` writer arm
 * (`src/connections/writers.ts`): lazy registration on the second session,
 * the throttled touch, the per-entry two-phase sweep with its cap of 8, a
 * sweep across two entries, concurrent sweepers, the un-retire rules, the
 * pull-path touch, and the join a history view resolves a writer through.
 */
import { describe, expect, it } from 'vitest'
import {
  connectionResourceId,
  readConnections,
  registerConnectionWriter,
  resolveWriter,
  sweepConnectionWriters,
  touchConnectionWriter
} from '../../src/connections/index.js'
import type {
  ConnectionEntry,
  ConnectionsListing,
  ConnectionsStore,
  ConnectionWriter,
  WriterFirstSeenRecord,
  WriterFirstSeenStore
} from '../../src/connections/index.js'
import {
  HMAC_KEY,
  memoryConnectionsStore,
  namedError
} from './fixtures/memoryConnections.js'

const ACCOUNT = 'did:webvh:SCID:example.com:space:SPACE:id'
const OTHER_ACCOUNT = 'did:webvh:OTHER:example.com:space:OTHER:id'
const CLIENT = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
const SECOND = 'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf'
const APP = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const DAY_MS = 24 * 60 * 60 * 1000

function memoryLocal(initial?: WriterFirstSeenRecord) {
  let firstSeen: WriterFirstSeenRecord | undefined = initial
  const local: WriterFirstSeenStore = {
    async get() {
      return firstSeen
    },
    async put(next) {
      firstSeen = next
    }
  }
  return { local, current: () => firstSeen }
}

function writer(
  writerId: string,
  lastSeen: Date,
  overrides: Partial<ConnectionWriter> = {}
): ConnectionWriter {
  return {
    writerId,
    label: `label ${writerId}`,
    lastSeen: lastSeen.toISOString(),
    active: true,
    ...overrides
  }
}

function clientEntry({
  did = CLIENT,
  writers,
  ...overrides
}: {
  did?: string
  writers: ConnectionWriter[]
} & Partial<ConnectionEntry>): Record<string, unknown> {
  return {
    version: 1,
    kind: 'wallet-client',
    id: did,
    name: 'Chrome on Linux',
    firstSeen: '2026-08-01T00:00:00.000Z',
    lastSeen: '2026-08-01T00:00:00.000Z',
    grants: [],
    writers,
    ...overrides
  }
}

async function seedEntry(
  seed: (resourceId: string, body: unknown) => void,
  body: Record<string, unknown>
): Promise<string> {
  const resourceId = await connectionResourceId({
    hmacKey: HMAC_KEY,
    did: body.id as string
  })
  seed(resourceId, body)
  return resourceId
}

async function listing(store: ConnectionsStore): Promise<ConnectionsListing> {
  const read = await readConnections({ store, hmacKey: HMAC_KEY })
  if (read === null) {
    throw new Error('missing')
  }
  return read
}

describe('registerConnectionWriter', () => {
  const firstSession = new Date('2026-09-01T10:00:00.000Z')
  const secondSession = new Date('2026-09-02T10:00:00.000Z')

  function options(
    store: ConnectionsStore,
    local: WriterFirstSeenStore,
    overrides: Record<string, unknown> = {}
  ) {
    return {
      store,
      hmacKey: HMAC_KEY,
      local,
      accountDid: ACCOUNT,
      did: CLIENT,
      writerId: 'w1',
      label: 'Chrome on Linux',
      listedInDocument: true,
      sessionStartedAt: secondSession,
      now: secondSession,
      ...overrides
    }
  }

  it('defers the first session and registers on the second, creating the entry', async () => {
    const { store, rows } = memoryConnectionsStore()
    const { local, current } = memoryLocal()
    expect(
      await registerConnectionWriter(
        options(store, local, {
          sessionStartedAt: firstSession,
          now: firstSession
        })
      )
    ).toBe('deferred')
    // A second call inside the same session still defers.
    expect(
      await registerConnectionWriter(
        options(store, local, {
          sessionStartedAt: firstSession,
          now: new Date(firstSession.getTime() + 60_000)
        })
      )
    ).toBe('deferred')
    expect(rows.size).toBe(0)

    expect(await registerConnectionWriter(options(store, local))).toBe(
      'registered'
    )
    const resourceId = await connectionResourceId({
      hmacKey: HMAC_KEY,
      did: CLIENT
    })
    expect(rows.get(resourceId)?.body).toEqual({
      version: 1,
      kind: 'wallet-client',
      id: CLIENT,
      name: 'Chrome on Linux',
      firstSeen: secondSession.toISOString(),
      lastSeen: secondSession.toISOString(),
      grants: [],
      grantsReceived: [],
      outbox: [],
      writers: [
        {
          writerId: 'w1',
          label: 'Chrome on Linux',
          lastSeen: secondSession.toISOString(),
          active: true
        }
      ]
    })
    expect(current()?.lastTouchedAt).toBe(secondSession.toISOString())
  })

  it('gives no second-session credit across accounts', async () => {
    const { store, rows } = memoryConnectionsStore()
    const { local, current } = memoryLocal({
      accountDid: OTHER_ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    expect(await registerConnectionWriter(options(store, local))).toBe(
      'deferred'
    )
    expect(rows.size).toBe(0)
    expect(current()).toEqual({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: secondSession.toISOString()
    })
  })

  it('throttles touches and keeps the stored labels', async () => {
    const { store, rows, writes, seed } = memoryConnectionsStore()
    const resourceId = await seedEntry(
      seed,
      clientEntry({
        label: 'Work laptop',
        writers: [writer('w1', firstSession, { label: 'Old platform' })]
      })
    )
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    expect(await registerConnectionWriter(options(store, local))).toBe(
      'touched'
    )
    const writeCount = writes.length
    const soon = new Date(secondSession.getTime() + DAY_MS / 2)
    expect(
      await registerConnectionWriter(options(store, local, { now: soon }))
    ).toBe('fresh')
    expect(writes).toHaveLength(writeCount)

    const later = new Date(secondSession.getTime() + DAY_MS + 1)
    expect(
      await registerConnectionWriter(options(store, local, { now: later }))
    ).toBe('touched')
    const body = rows.get(resourceId)?.body as Record<string, unknown>
    expect(body.label).toBe('Work laptop')
    expect(body.writers).toEqual([
      {
        writerId: 'w1',
        label: 'Old platform',
        lastSeen: later.toISOString(),
        active: true
      }
    ])
  })

  it('reactivates a writer a sweep marked inactive', async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const resourceId = await seedEntry(
      seed,
      clientEntry({ writers: [writer('w1', firstSession, { active: false })] })
    )
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    expect(await registerConnectionWriter(options(store, local))).toBe(
      'touched'
    )
    expect(
      (rows.get(resourceId)?.body as { writers: ConnectionWriter[] }).writers[0]
    ).toMatchObject({ label: 'label w1', active: true })
  })

  it('makes room under the per-entry cap before adding a writer', async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const resourceId = await seedEntry(
      seed,
      clientEntry({
        writers: Array.from({ length: 8 }, (_, index) =>
          writer(`old${index}`, new Date(Date.UTC(2026, 7, 1 + index)))
        )
      })
    )
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    expect(await registerConnectionWriter(options(store, local))).toBe(
      'registered'
    )
    const writers = (
      rows.get(resourceId)?.body as { writers: ConnectionWriter[] }
    ).writers.map(member => member.writerId)
    expect(writers).toHaveLength(8)
    expect(writers).not.toContain('old0')
    expect(writers).toContain('w1')
  })

  it('un-retires an entry the document still lists, and leaves one it does not', async () => {
    for (const listedInDocument of [true, false]) {
      const { store, rows, writes, seed } = memoryConnectionsStore()
      const resourceId = await seedEntry(
        seed,
        clientEntry({
          retired: '2026-09-01T12:00:00.000Z',
          writers: [writer('w1', firstSession)]
        })
      )
      const { local } = memoryLocal({
        accountDid: ACCOUNT,
        writerId: 'w1',
        firstSessionAt: firstSession.toISOString()
      })
      const outcome = await registerConnectionWriter(
        options(store, local, { listedInDocument })
      )
      const body = rows.get(resourceId)?.body as Record<string, unknown>
      if (listedInDocument) {
        expect(outcome).toBe('touched')
        expect(body).not.toHaveProperty('retired')
      } else {
        expect(outcome).toBe('retired')
        expect(body.retired).toBe('2026-09-01T12:00:00.000Z')
        expect(writes).toEqual([])
      }
    }
  })

  it('creates no entry for a client the document does not list', async () => {
    const { store, rows } = memoryConnectionsStore()
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    expect(
      await registerConnectionWriter(
        options(store, local, { listedInDocument: false })
      )
    ).toBe('unlisted')
    expect(rows.size).toBe(0)
  })

  it('throttles a settled non-write outcome like a touch', async () => {
    const { store, seed } = memoryConnectionsStore()
    await seedEntry(seed, {
      ...clientEntry({ writers: [writer('w1', firstSession)] }),
      version: 2
    })
    const { local, current } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    let reads = 0
    const counting: ConnectionsStore = {
      ...store,
      async get(args) {
        reads++
        return store.get(args)
      }
    }
    expect(await registerConnectionWriter(options(counting, local))).toBe(
      'refused'
    )
    expect(reads).toBe(1)
    expect(current()?.lastTouchedAt).toBe(secondSession.toISOString())
    const soon = new Date(secondSession.getTime() + 60_000)
    expect(
      await registerConnectionWriter(options(counting, local, { now: soon }))
    ).toBe('fresh')
    expect(reads).toBe(1)
  })

  it('refuses a platform label outside the display-name rule, and strips it otherwise', async () => {
    const { store, rows } = memoryConnectionsStore()
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    await expect(
      registerConnectionWriter(options(store, local, { label: 'a'.repeat(65) }))
    ).rejects.toThrow(TypeError)
    expect(rows.size).toBe(0)
    const RLO = String.fromCodePoint(0x202e)
    expect(
      await registerConnectionWriter(
        options(store, local, { label: ` Chrome${RLO} on Linux ` })
      )
    ).toBe('registered')
    const [body] = [...rows.values()].map(row => row.body as ConnectionEntry)
    expect(body?.name).toBe('Chrome on Linux')
    expect(body?.writers[0]?.label).toBe('Chrome on Linux')
  })

  it('writes nothing over another kind, a newer version, or an unparseable body', async () => {
    for (const [body, expected] of [
      [{ ...clientEntry({ writers: [] }), kind: 'agent' }, 'kind-mismatch'],
      [{ ...clientEntry({ writers: [] }), version: 2 }, 'refused'],
      [{ ...clientEntry({ writers: [] }), grants: 'none' }, 'refused']
    ] as const) {
      const { store, writes, seed } = memoryConnectionsStore()
      await seedEntry(seed, body)
      const { local } = memoryLocal({
        accountDid: ACCOUNT,
        writerId: 'w1',
        firstSessionAt: firstSession.toISOString()
      })
      expect(await registerConnectionWriter(options(store, local))).toBe(
        expected
      )
      expect(writes).toEqual([])
    }
  })

  it('reports raced after three lost writes, and propagates other errors', async () => {
    const { store } = memoryConnectionsStore()
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    expect(
      await registerConnectionWriter(
        options(
          {
            ...store,
            async put() {
              throw namedError('PreconditionFailedError')
            }
          },
          local
        )
      )
    ).toBe('raced')
    await expect(
      registerConnectionWriter(
        options(
          {
            ...store,
            async put() {
              throw namedError('NotFoundError')
            }
          },
          local
        )
      )
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })
})

describe('touchConnectionWriter', () => {
  const now = new Date('2026-09-28T00:00:00.000Z')

  it('touches a registered writer, and skips an unregistered or retired one', async () => {
    const { store, rows, writes, seed } = memoryConnectionsStore()
    const live = await seedEntry(
      seed,
      clientEntry({
        writers: [writer('w1', new Date(now.getTime() - 2 * DAY_MS))]
      })
    )
    await seedEntry(
      seed,
      clientEntry({
        did: SECOND,
        retired: '2026-09-01T00:00:00.000Z',
        writers: [writer('w2', new Date(now.getTime() - 2 * DAY_MS))]
      })
    )
    const read = await listing(store)
    const base = { store, hmacKey: HMAC_KEY, listing: read, now }
    expect(await touchConnectionWriter({ ...base, writerId: 'w1' })).toBe(
      'touched'
    )
    expect(
      (rows.get(live)?.body as { writers: ConnectionWriter[] }).writers[0]
        ?.lastSeen
    ).toBe(now.toISOString())
    const count = writes.length
    expect(await touchConnectionWriter({ ...base, writerId: 'w2' })).toBe(
      'retired'
    )
    expect(await touchConnectionWriter({ ...base, writerId: 'stranger' })).toBe(
      'unregistered'
    )
    // Within the touch interval the call costs no write.
    expect(
      await touchConnectionWriter({
        ...base,
        listing: await listing(store),
        writerId: 'w1'
      })
    ).toBe('fresh')
    expect(writes).toHaveLength(count)
  })
})

describe('sweepConnectionWriters', () => {
  const now = new Date('2026-09-28T00:00:00.000Z')

  it('marks writers past the window inactive and keeps the rest', async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const resourceId = await seedEntry(
      seed,
      clientEntry({
        writers: [
          writer('stale', new Date(now.getTime() - 91 * DAY_MS)),
          writer('recent', new Date(now.getTime() - 89 * DAY_MS))
        ]
      })
    )
    const sweep = await sweepConnectionWriters({
      store,
      listing: await listing(store),
      now
    })
    expect(sweep.markedInactive).toEqual(['stale'])
    expect(sweep.dropped).toEqual([])
    const stored = rows.get(resourceId)?.body as { writers: ConnectionWriter[] }
    expect(
      Object.fromEntries(
        stored.writers.map(member => [member.writerId, member.active])
      )
    ).toEqual({ stale: false, recent: true })
    expect(sweep.listing.entries[0]?.entry.writers[0]?.active).toBe(false)
  })

  it('drops the oldest writers past the per-entry cap of 8, across two entries', async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const first = await seedEntry(
      seed,
      clientEntry({
        writers: Array.from({ length: 10 }, (_, index) =>
          writer(`a${index}`, new Date(now.getTime() - (index + 1) * DAY_MS))
        )
      })
    )
    const second = await seedEntry(
      seed,
      clientEntry({
        did: SECOND,
        writers: [
          writer('b-stale', new Date(now.getTime() - 120 * DAY_MS)),
          writer('b-live', now)
        ]
      })
    )
    const sweep = await sweepConnectionWriters({
      store,
      listing: await listing(store),
      now
    })
    expect(sweep.dropped.sort()).toEqual(['a8', 'a9'])
    expect(sweep.markedInactive).toEqual(['b-stale'])
    expect(
      (rows.get(first)?.body as { writers: ConnectionWriter[] }).writers.map(
        member => member.writerId
      )
    ).toEqual(['a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7'])
    expect(
      (rows.get(second)?.body as { writers: ConnectionWriter[] }).writers
    ).toHaveLength(2)
  })

  it('converges under concurrent sweepers', async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const resourceId = await seedEntry(
      seed,
      clientEntry({
        writers: [
          writer('stale', new Date(now.getTime() - 100 * DAY_MS)),
          writer('w1', new Date(now.getTime() - DAY_MS)),
          writer('w2', new Date(now.getTime() - 2 * DAY_MS))
        ]
      })
    )
    const read = await listing(store)
    const policy = { maxWriters: 2 }
    const [first, second] = await Promise.all([
      sweepConnectionWriters({ store, listing: read, now, policy }),
      sweepConnectionWriters({ store, listing: read, now, policy })
    ])
    expect([...first.dropped, ...second.dropped]).toEqual(['stale'])
    expect(
      (rows.get(resourceId)?.body as { writers: ConnectionWriter[] }).writers
    ).toHaveLength(2)
  })

  it('skips an entry touched after the listing read it, and one read without an ETag', async () => {
    const { store, rows, writes, seed } = memoryConnectionsStore()
    const resourceId = await seedEntry(
      seed,
      clientEntry({
        writers: [writer('w1', new Date(now.getTime() - 100 * DAY_MS))]
      })
    )
    const read = await listing(store)
    // The writer touches between the sweep's read and its write.
    rows.set(resourceId, {
      body: clientEntry({ writers: [writer('w1', now)] }),
      etag: 'touched'
    })
    const sweep = await sweepConnectionWriters({ store, listing: read, now })
    expect(sweep.markedInactive).toEqual([])
    expect(
      (rows.get(resourceId)?.body as { writers: ConnectionWriter[] }).writers[0]
        ?.active
    ).toBe(true)

    const etagless: ConnectionsListing = {
      ...read,
      entries: read.entries.map(({ etag: _etag, ...item }) => item)
    }
    const count = writes.length
    await sweepConnectionWriters({ store, listing: etagless, now })
    expect(writes).toHaveLength(count)
  })

  it('skips an entry whose write fails, reports it, and sweeps the rest', async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const failing = await seedEntry(
      seed,
      clientEntry({
        writers: [writer('w1', new Date(now.getTime() - 100 * DAY_MS))]
      })
    )
    const other = await seedEntry(
      seed,
      clientEntry({
        did: SECOND,
        writers: [writer('w2', new Date(now.getTime() - 100 * DAY_MS))]
      })
    )
    const outage = new Error('socket hang up')
    const flaky: ConnectionsStore = {
      ...store,
      async put(args) {
        if (args.resourceId === failing) {
          throw outage
        }
        return store.put(args)
      }
    }
    const read = await listing(store)
    const sweep = await sweepConnectionWriters({
      store: flaky,
      listing: read,
      now
    })
    expect(sweep.failed).toEqual([{ resourceId: failing, err: outage }])
    expect(sweep.markedInactive).toEqual(['w2'])
    expect(
      (rows.get(failing)?.body as { writers: ConnectionWriter[] }).writers[0]
        ?.active
    ).toBe(true)
    expect(
      (rows.get(other)?.body as { writers: ConnectionWriter[] }).writers[0]
        ?.active
    ).toBe(false)
    // The failed entry is listed as read.
    expect(
      sweep.listing.entries.find(item => item.resourceId === failing)?.entry
        .writers[0]?.active
    ).toBe(true)
  })

  it('leaves a newer-version entry alone', async () => {
    const { store, writes, seed } = memoryConnectionsStore()
    await seedEntry(seed, {
      ...clientEntry({
        writers: [writer('stale', new Date(now.getTime() - 100 * DAY_MS))]
      }),
      version: 2
    })
    const sweep = await sweepConnectionWriters({
      store,
      listing: await listing(store),
      now
    })
    expect(sweep.markedInactive).toEqual([])
    expect(writes).toEqual([])
  })

  it('reads a future lastSeen as now when evicting', async () => {
    const { store, seed } = memoryConnectionsStore()
    await seedEntry(
      seed,
      clientEntry({
        writers: [
          writer('future', new Date(now.getTime() + 365 * DAY_MS)),
          writer('today', now)
        ]
      })
    )
    const sweep = await sweepConnectionWriters({
      store,
      listing: await listing(store),
      now,
      policy: { maxWriters: 1 }
    })
    // Both read as `now`; the writerId tie-break decides, the same on every
    // sweeper, instead of the fast clock winning outright.
    expect(sweep.dropped).toEqual(['today'])
  })
})

describe('resolveWriter', () => {
  const now = new Date('2026-09-28T00:00:00.000Z')
  const entries: ConnectionEntry[] = [
    {
      version: 1,
      kind: 'wallet-client',
      id: CLIENT,
      name: 'Chrome on Linux',
      label: 'Work laptop',
      firstSeen: now.toISOString(),
      lastSeen: now.toISOString(),
      grants: [],
      grantsReceived: [],
      outbox: [],
      writers: [writer('wallet', now)]
    },
    {
      version: 1,
      kind: 'wallet-client',
      id: SECOND,
      firstSeen: now.toISOString(),
      lastSeen: now.toISOString(),
      retired: now.toISOString(),
      grants: [],
      grantsReceived: [],
      outbox: [],
      writers: [writer('revoked', now, { active: false })]
    },
    {
      version: 1,
      kind: 'app',
      id: APP,
      name: 'Example App',
      firstSeen: now.toISOString(),
      lastSeen: now.toISOString(),
      grants: [],
      grantsReceived: [],
      outbox: [],
      writers: [writer('app', now)]
    }
  ]
  const enrolledSigningKeys = new Set([CLIENT.slice('did:key:'.length)])

  it('links a writer whose entry key the document lists', () => {
    expect(
      resolveWriter({ writerId: 'wallet', entries, enrolledSigningKeys })
    ).toEqual({
      label: 'Work laptop',
      active: true,
      retired: false,
      clientSigningKeyMultibase: CLIENT.slice('did:key:'.length)
    })
  })

  it('leaves an unlisted key unlinked, and falls back through the names', () => {
    expect(
      resolveWriter({ writerId: 'revoked', entries, enrolledSigningKeys })
    ).toEqual({ label: 'label revoked', active: false, retired: true })
    expect(
      resolveWriter({ writerId: 'app', entries, enrolledSigningKeys })
    ).toEqual({ label: 'Example App', active: true, retired: false })
  })

  it('resolves an unregistered writer to nothing', () => {
    expect(
      resolveWriter({ writerId: 'gone', entries, enrolledSigningKeys })
    ).toBeUndefined()
  })
})
