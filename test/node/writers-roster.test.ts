import { describe, expect, it } from 'vitest'
import {
  REGISTERED_WRITER_POLICY,
  parseRegisteredWriterEntry,
  registerWriterOnSecondSession,
  registeredWriterResourceId,
  renameRegisteredWriter,
  resolveRegisteredWriter,
  sweepRegisteredWriters
} from '../../src/writers/index.js'
import type {
  RegisteredWriterEntry,
  RegisteredWritersStore,
  WriterFirstSeenRecord,
  WriterFirstSeenStore
} from '../../src/writers/index.js'

const ACCOUNT = 'did:webvh:SCID:example.com:space:SPACE:id'
const OTHER_ACCOUNT = 'did:webvh:OTHER:example.com:space:OTHER:id'
const DAY_MS = 24 * 60 * 60 * 1000

function namedError(name: string): Error {
  const err = new Error(name)
  err.name = name
  return err
}

/**
 * An in-memory roster store with ETags, honoring `ifMatch` / `ifNoneMatch`
 * the way the WAS server does.
 */
function memoryStore() {
  const rows = new Map<string, { body: unknown; etag: string }>()
  let revision = 0
  const writes: string[] = []
  const store: RegisteredWritersStore = {
    async list() {
      return [...rows].map(([resourceId, row]) => ({ resourceId, ...row }))
    },
    async get({ resourceId }) {
      const row = rows.get(resourceId)
      return row === undefined ? undefined : { ...row }
    },
    async put({ resourceId, entry, ifMatch, ifNoneMatch }) {
      const row = rows.get(resourceId)
      if (ifNoneMatch && row !== undefined) {
        throw namedError('PreconditionFailedError')
      }
      if (ifMatch !== undefined && row?.etag !== ifMatch) {
        throw namedError('PreconditionFailedError')
      }
      writes.push(`put:${resourceId}`)
      rows.set(resourceId, {
        body: structuredClone(entry),
        etag: `e${++revision}`
      })
    },
    async delete({ resourceId, ifMatch }) {
      const row = rows.get(resourceId)
      if (row === undefined) {
        throw namedError('NotFoundError')
      }
      if (ifMatch !== undefined && row.etag !== ifMatch) {
        throw namedError('PreconditionFailedError')
      }
      writes.push(`delete:${resourceId}`)
      rows.delete(resourceId)
    }
  }
  return { store, rows, writes }
}

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

function entry(
  writerId: string,
  lastSeen: Date,
  overrides: Partial<RegisteredWriterEntry> = {}
): RegisteredWriterEntry {
  return {
    version: 1,
    writerId,
    label: `label ${writerId}`,
    lastSeen: lastSeen.toISOString(),
    active: true,
    ...overrides
  }
}

function seed(
  rows: Map<string, { body: unknown; etag: string }>,
  entries: RegisteredWriterEntry[]
) {
  for (const [index, item] of entries.entries()) {
    rows.set(
      registeredWriterResourceId({
        accountDid: ACCOUNT,
        writerId: item.writerId
      }),
      { body: item, etag: `seed${index}` }
    )
  }
}

describe('registeredWriterResourceId', () => {
  it('is a deterministic EDV id scoped to the account', () => {
    const id = registeredWriterResourceId({
      accountDid: ACCOUNT,
      writerId: 'w1'
    })
    expect(id).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/)
    expect(
      registeredWriterResourceId({ accountDid: ACCOUNT, writerId: 'w1' })
    ).toBe(id)
    expect(
      registeredWriterResourceId({ accountDid: OTHER_ACCOUNT, writerId: 'w1' })
    ).not.toBe(id)
    expect(id).not.toContain('w1')
  })
})

describe('parseRegisteredWriterEntry', () => {
  it('accepts a version-1 entry and drops unknown members', () => {
    const now = new Date('2026-09-28T00:00:00.000Z')
    expect(
      parseRegisteredWriterEntry({ ...entry('w1', now), extra: 1 })
    ).toEqual(entry('w1', now))
  })

  it('refuses malformed bodies', () => {
    const now = new Date('2026-09-28T00:00:00.000Z')
    for (const body of [
      null,
      'text',
      { ...entry('w1', now), version: 2 },
      { ...entry('w1', now), writerId: '' },
      { ...entry('w1', now), lastSeen: 'yesterday' },
      { ...entry('w1', now), active: 'yes' },
      { ...entry('w1', now), signingKeyMultibase: 7 }
    ]) {
      expect(parseRegisteredWriterEntry(body)).toBeUndefined()
    }
  })
})

describe('registerWriterOnSecondSession', () => {
  const firstSession = new Date('2026-09-01T10:00:00.000Z')
  const secondSession = new Date('2026-09-02T10:00:00.000Z')

  it('defers the first session and registers on the second', async () => {
    const { store, rows } = memoryStore()
    const { local, current } = memoryLocal()
    const options = {
      store,
      local,
      accountDid: ACCOUNT,
      writerId: 'w1',
      label: 'Chrome on Linux',
      signingKeyMultibase: 'z6MkClient'
    }

    expect(
      await registerWriterOnSecondSession({
        ...options,
        sessionStartedAt: firstSession,
        now: firstSession
      })
    ).toBe('deferred')
    // A second call inside the same session still defers.
    expect(
      await registerWriterOnSecondSession({
        ...options,
        sessionStartedAt: firstSession,
        now: new Date(firstSession.getTime() + 60_000)
      })
    ).toBe('deferred')
    expect(rows.size).toBe(0)

    expect(
      await registerWriterOnSecondSession({
        ...options,
        sessionStartedAt: secondSession,
        now: secondSession
      })
    ).toBe('registered')
    const resourceId = registeredWriterResourceId({
      accountDid: ACCOUNT,
      writerId: 'w1'
    })
    expect(rows.get(resourceId)?.body).toEqual({
      version: 1,
      writerId: 'w1',
      signingKeyMultibase: 'z6MkClient',
      label: 'Chrome on Linux',
      lastSeen: secondSession.toISOString(),
      active: true
    })
    expect(current()?.lastTouchedAt).toBe(secondSession.toISOString())
  })

  it('gives no second-session credit across accounts', async () => {
    const { store, rows } = memoryStore()
    const { local, current } = memoryLocal({
      accountDid: OTHER_ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    expect(
      await registerWriterOnSecondSession({
        store,
        local,
        accountDid: ACCOUNT,
        writerId: 'w1',
        label: 'Chrome on Linux',
        sessionStartedAt: secondSession,
        now: secondSession
      })
    ).toBe('deferred')
    expect(rows.size).toBe(0)
    expect(current()).toEqual({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: secondSession.toISOString()
    })
  })

  it('throttles touches and keeps a renamed label', async () => {
    const { store, rows, writes } = memoryStore()
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    const options = {
      store,
      local,
      accountDid: ACCOUNT,
      writerId: 'w1',
      label: 'Chrome on Linux',
      sessionStartedAt: secondSession
    }
    expect(
      await registerWriterOnSecondSession({ ...options, now: secondSession })
    ).toBe('registered')
    expect(
      await renameRegisteredWriter({
        store,
        accountDid: ACCOUNT,
        writerId: 'w1',
        label: '  Work laptop  '
      })
    ).toBe(true)

    const writeCount = writes.length
    const soon = new Date(secondSession.getTime() + DAY_MS / 2)
    expect(await registerWriterOnSecondSession({ ...options, now: soon })).toBe(
      'fresh'
    )
    expect(writes).toHaveLength(writeCount)

    const later = new Date(secondSession.getTime() + DAY_MS + 1)
    expect(
      await registerWriterOnSecondSession({ ...options, now: later })
    ).toBe('touched')
    const resourceId = registeredWriterResourceId({
      accountDid: ACCOUNT,
      writerId: 'w1'
    })
    expect(rows.get(resourceId)?.body).toMatchObject({
      label: 'Work laptop',
      lastSeen: later.toISOString(),
      active: true
    })
  })

  it('reactivates an entry a sweep marked inactive', async () => {
    const { store, rows } = memoryStore()
    seed(rows, [entry('w1', firstSession, { active: false })])
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    expect(
      await registerWriterOnSecondSession({
        store,
        local,
        accountDid: ACCOUNT,
        writerId: 'w1',
        label: 'ignored',
        sessionStartedAt: secondSession,
        now: secondSession
      })
    ).toBe('touched')
    const resourceId = registeredWriterResourceId({
      accountDid: ACCOUNT,
      writerId: 'w1'
    })
    expect(rows.get(resourceId)?.body).toMatchObject({
      label: 'label w1',
      active: true
    })
  })

  it('makes room under the cap before registering', async () => {
    const { store, rows } = memoryStore()
    seed(rows, [
      entry('old', new Date('2026-08-01T00:00:00.000Z')),
      entry('mid', new Date('2026-08-15T00:00:00.000Z')),
      entry('new', new Date('2026-08-30T00:00:00.000Z'))
    ])
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    expect(
      await registerWriterOnSecondSession({
        store,
        local,
        accountDid: ACCOUNT,
        writerId: 'w1',
        label: 'Chrome on Linux',
        sessionStartedAt: secondSession,
        now: secondSession,
        policy: { maxEntries: 3 }
      })
    ).toBe('registered')
    const writers = [...rows.values()].map(
      row => (row.body as RegisteredWriterEntry).writerId
    )
    expect(writers.sort()).toEqual(['mid', 'new', 'w1'])
  })
})

describe('sweepRegisteredWriters', () => {
  const now = new Date('2026-09-28T00:00:00.000Z')

  it('marks entries past the TTL inactive and keeps the rest', async () => {
    const { store, rows } = memoryStore()
    seed(rows, [
      entry('stale', new Date(now.getTime() - 91 * DAY_MS)),
      entry('recent', new Date(now.getTime() - 89 * DAY_MS))
    ])
    const sweep = await sweepRegisteredWriters({
      store,
      accountDid: ACCOUNT,
      now
    })
    expect(sweep.markedInactive).toEqual(['stale'])
    expect(sweep.deleted).toEqual([])
    expect(
      Object.fromEntries(
        sweep.entries.map(item => [item.writerId, item.active])
      )
    ).toEqual({ stale: false, recent: true })
    const stored = rows.get(
      registeredWriterResourceId({ accountDid: ACCOUNT, writerId: 'stale' })
    )
    expect((stored?.body as RegisteredWriterEntry).active).toBe(false)
  })

  it('deletes the oldest entries past the cap', async () => {
    const { store, rows } = memoryStore()
    seed(
      rows,
      [1, 2, 3, 4, 5].map(day =>
        entry(`w${day}`, new Date(now.getTime() - day * DAY_MS))
      )
    )
    const sweep = await sweepRegisteredWriters({
      store,
      accountDid: ACCOUNT,
      now,
      policy: { maxEntries: 3 }
    })
    expect(sweep.deleted.sort()).toEqual(['w4', 'w5'])
    expect(sweep.entries.map(item => item.writerId)).toEqual(['w1', 'w2', 'w3'])
    expect(rows.size).toBe(3)
  })

  it('leaves unreadable and misplaced resources alone', async () => {
    const { store, rows } = memoryStore()
    rows.set('zUnreadable', { body: undefined, etag: 'x' })
    rows.set('zMisplaced', {
      body: entry('w1', new Date(now.getTime() - 200 * DAY_MS)),
      etag: 'y'
    })
    const sweep = await sweepRegisteredWriters({
      store,
      accountDid: ACCOUNT,
      now,
      policy: { maxEntries: 0 }
    })
    expect(sweep).toEqual({ entries: [], markedInactive: [], deleted: [] })
    expect(rows.size).toBe(2)
  })

  it('converges under concurrent sweepers', async () => {
    const { store, rows } = memoryStore()
    seed(rows, [
      entry('stale', new Date(now.getTime() - 100 * DAY_MS)),
      entry('w1', new Date(now.getTime() - DAY_MS)),
      entry('w2', new Date(now.getTime() - 2 * DAY_MS))
    ])
    const policy = { maxEntries: 2 }
    const [first, second] = await Promise.all([
      sweepRegisteredWriters({ store, accountDid: ACCOUNT, now, policy }),
      sweepRegisteredWriters({ store, accountDid: ACCOUNT, now, policy })
    ])
    expect([...first.deleted, ...second.deleted]).toEqual(['stale'])
    expect(rows.size).toBe(2)
  })

  it('skips an entry its writer touched after the sweep read it', async () => {
    const { store, rows } = memoryStore()
    seed(rows, [entry('w1', new Date(now.getTime() - 100 * DAY_MS))])
    const resourceId = registeredWriterResourceId({
      accountDid: ACCOUNT,
      writerId: 'w1'
    })
    const racing: RegisteredWritersStore = {
      ...store,
      async list() {
        const listed = await store.list()
        // The writer touches between the sweep's read and its write.
        rows.set(resourceId, {
          body: entry('w1', now),
          etag: 'touched'
        })
        return listed
      }
    }
    const sweep = await sweepRegisteredWriters({
      store: racing,
      accountDid: ACCOUNT,
      now
    })
    expect(sweep.markedInactive).toEqual([])
    expect((rows.get(resourceId)?.body as RegisteredWriterEntry).active).toBe(
      true
    )
  })

  it('uses the default policy', () => {
    expect(REGISTERED_WRITER_POLICY).toEqual({
      inactiveAfterMs: 90 * DAY_MS,
      maxEntries: 64,
      touchIntervalMs: DAY_MS
    })
  })
})

describe('resolveRegisteredWriter', () => {
  const now = new Date('2026-09-28T00:00:00.000Z')
  const entries = [
    entry('wallet', now, { signingKeyMultibase: 'z6MkEnrolled' }),
    entry('revoked', now, { signingKeyMultibase: 'z6MkGone', active: false }),
    entry('app', now)
  ]
  const enrolledSigningKeys = new Set(['z6MkEnrolled'])

  it('links a writer whose key the document lists', () => {
    expect(
      resolveRegisteredWriter({
        writerId: 'wallet',
        entries,
        enrolledSigningKeys
      })
    ).toEqual({
      label: 'label wallet',
      active: true,
      clientSigningKeyMultibase: 'z6MkEnrolled'
    })
  })

  it('leaves an unlisted key or a keyless writer unlinked', () => {
    expect(
      resolveRegisteredWriter({
        writerId: 'revoked',
        entries,
        enrolledSigningKeys
      })
    ).toEqual({ label: 'label revoked', active: false })
    expect(
      resolveRegisteredWriter({ writerId: 'app', entries, enrolledSigningKeys })
    ).toEqual({ label: 'label app', active: true })
  })

  it('resolves an unregistered writer to nothing', () => {
    expect(
      resolveRegisteredWriter({
        writerId: 'gone',
        entries,
        enrolledSigningKeys
      })
    ).toBeUndefined()
  })
})

describe('writer roster refusals', () => {
  const firstSession = new Date('2026-09-01T10:00:00.000Z')
  const secondSession = new Date('2026-09-02T10:00:00.000Z')
  const now = new Date('2026-09-28T00:00:00.000Z')

  function etagless(store: RegisteredWritersStore): RegisteredWritersStore {
    return {
      ...store,
      async list() {
        return (await store.list()).map(({ resourceId, body }) => ({
          resourceId,
          body
        }))
      },
      async get(options) {
        const stored = await store.get(options)
        return stored === undefined ? undefined : { body: stored.body }
      }
    }
  }

  it('refuses a touch or rename whose read carried no ETag', async () => {
    const { store, rows } = memoryStore()
    seed(rows, [entry('w1', firstSession)])
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    await expect(
      registerWriterOnSecondSession({
        store: etagless(store),
        local,
        accountDid: ACCOUNT,
        writerId: 'w1',
        label: 'x',
        sessionStartedAt: secondSession,
        now: secondSession
      })
    ).rejects.toMatchObject({ name: 'NotSupportedError' })
    await expect(
      renameRegisteredWriter({
        store: etagless(store),
        accountDid: ACCOUNT,
        writerId: 'w1',
        label: 'Renamed'
      })
    ).rejects.toMatchObject({ name: 'NotSupportedError' })
  })

  it('writes nothing in a sweep whose reads carried no ETag', async () => {
    const { store, rows, writes } = memoryStore()
    seed(rows, [
      entry('stale', new Date(now.getTime() - 100 * DAY_MS)),
      entry('w1', new Date(now.getTime() - DAY_MS))
    ])
    const sweep = await sweepRegisteredWriters({
      store: etagless(store),
      accountDid: ACCOUNT,
      now,
      policy: { maxEntries: 1 }
    })
    expect(sweep.markedInactive).toEqual([])
    expect(sweep.deleted).toEqual([])
    expect(writes).toEqual([])
  })

  it('propagates a NotFoundError from a put', async () => {
    const { store } = memoryStore()
    const refusing: RegisteredWritersStore = {
      ...store,
      async put() {
        throw namedError('NotFoundError')
      }
    }
    const { local } = memoryLocal({
      accountDid: ACCOUNT,
      writerId: 'w1',
      firstSessionAt: firstSession.toISOString()
    })
    await expect(
      registerWriterOnSecondSession({
        store: refusing,
        local,
        accountDid: ACCOUNT,
        writerId: 'w1',
        label: 'x',
        sessionStartedAt: secondSession,
        now: secondSession
      })
    ).rejects.toMatchObject({ name: 'NotFoundError' })
  })

  it('reads a future lastSeen as now when evicting', async () => {
    const { store, rows } = memoryStore()
    seed(rows, [
      entry('future', new Date(now.getTime() + 365 * DAY_MS)),
      entry('today', now)
    ])
    const sweep = await sweepRegisteredWriters({
      store,
      accountDid: ACCOUNT,
      now,
      policy: { maxEntries: 1 }
    })
    // Both read as `now`; the resource-id tie-break decides, the same on
    // every sweeper, instead of the fast clock winning outright.
    const ids = ['future', 'today'].map(writerId => ({
      writerId,
      resourceId: registeredWriterResourceId({ accountDid: ACCOUNT, writerId })
    }))
    ids.sort((left, right) => (left.resourceId < right.resourceId ? -1 : 1))
    expect(sweep.deleted).toEqual([ids[1]?.writerId])
  })
})
