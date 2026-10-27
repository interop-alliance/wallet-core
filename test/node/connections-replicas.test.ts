/**
 * Unit tests for the `replica-server` kind: the `replicas` item codec
 * (`src/connections/entry.ts`) and the replica-server upsert helpers
 * (`src/connections/replicas.ts`): the registration's entry write and its
 * adopting re-run, the pull grant recorded with a pending registration id,
 * the settled id, the intent markers, the item removal, the kind refusal of
 * every helper, and the retirement refusal while an item stands.
 */
import { describe, expect, it } from 'vitest'
import {
  ConnectionKindMismatchError,
  clearReplicaMarker,
  connectionKindOf,
  connectionSeedTag,
  markDeclined,
  parseConnectionEntry,
  recordGrants,
  recordReplicaGrant,
  recordReplicas,
  removeReplica,
  retireConnection,
  setReplicaMarker,
  settleReplicaRegistration
} from '../../src/connections/index.js'
import {
  HMAC_KEY,
  idOf,
  OTHER_SEED,
  SEED,
  SPACE_URL,
  memoryConnectionsStore,
  zcap
} from './fixtures/memoryConnections.js'

const SERVER = 'did:webvh:QmReplicaServerScid:replica.example:space:server:id'
const APP = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const SERVER_URL = 'https://replica.example/'
const ANNEX_URL = 'https://was.example/space/ANNEX/'
// 32 bytes of 0x01, 0x02, 0x03, and 0x04 as base64url with no padding.
const ACCOUNT_REPLICA = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE'
const ANNEX_REPLICA = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI'
const REGISTRATION = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM'
const OTHER_REGISTRATION = 'BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ'
const T1 = new Date('2026-10-01T00:00:00.000Z')
const T2 = new Date('2026-10-02T00:00:00.000Z')
const T3 = new Date('2026-10-03T00:00:00.000Z')

const BASE = { store: undefined as never, hmacKey: HMAC_KEY, did: SERVER }

function pullGrant(id: string, fromSpace = SPACE_URL) {
  return zcap({ id, controller: SERVER, target: fromSpace })
}

function item(overrides: Record<string, unknown> = {}) {
  return { fromSpace: SPACE_URL, spaceId: ACCOUNT_REPLICA, ...overrides }
}

function entry(overrides: Record<string, unknown> = {}) {
  return {
    version: 1,
    kind: 'replica-server',
    id: SERVER,
    url: SERVER_URL,
    firstSeen: T1.toISOString(),
    lastSeen: T1.toISOString(),
    grants: [],
    grantsReceived: [],
    outbox: [],
    writers: [],
    replicas: [item(), item({ fromSpace: ANNEX_URL, spaceId: ANNEX_REPLICA })],
    ...overrides
  }
}

async function registered() {
  const memory = memoryConnectionsStore()
  const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
  await recordReplicas({
    ...BASE,
    store: memory.store,
    url: SERVER_URL,
    name: 'replica.example',
    seed: SEED,
    seedTag,
    replicas: [
      { fromSpace: SPACE_URL, spaceId: ACCOUNT_REPLICA },
      { fromSpace: ANNEX_URL, spaceId: ANNEX_REPLICA }
    ],
    now: T1
  })
  const resourceId = await idOf(SERVER)
  return {
    ...memory,
    seedTag,
    resourceId,
    body: () => memory.rows.get(resourceId)?.body as Record<string, unknown>
  }
}

describe('the replicas item codec', () => {
  it('reads the kind and every item member, and keeps unknown item members', () => {
    const body = entry({
      replicas: [
        item({
          registrationId: REGISTRATION,
          collections: ['id', 'private-credentials'],
          stoppedAt: T1.toISOString(),
          restartedAt: T2.toISOString(),
          lostAt: T3.toISOString(),
          fromALaterBuild: { nested: true }
        }),
        item({
          fromSpace: ANNEX_URL,
          spaceId: ANNEX_REPLICA,
          pendingRegistrationId: REGISTRATION
        })
      ]
    })
    const parsed = parseConnectionEntry(body)
    expect(parsed?.replicas).toEqual(body.replicas)
    expect(connectionKindOf(parsed!)).toBe('replica-server')
  })

  it('reads an absent replicas list as empty', () => {
    const body = entry()
    delete (body as Record<string, unknown>).replicas
    expect(parseConnectionEntry(body)?.replicas).toEqual([])
  })

  it('makes the body unparseable on a malformed item', () => {
    const malformed: Array<Record<string, unknown>> = [
      item({ fromSpace: 'https://was.example/space/SPACE' }),
      item({ fromSpace: 'not a url/' }),
      item({ fromSpace: 7 }),
      item({ spaceId: 'short' }),
      item({ spaceId: `${ACCOUNT_REPLICA}=` }),
      item({ spaceId: undefined }),
      item({ registrationId: 'short' }),
      item({ pendingRegistrationId: 42 }),
      item({ collections: 'id' }),
      item({ collections: ['id', ''] }),
      item({ collections: [] }),
      item({ stoppedAt: 'yesterday' }),
      item({ restartedAt: 1 }),
      item({ lostAt: {} })
    ]
    for (const bad of malformed) {
      expect(
        parseConnectionEntry(entry({ replicas: [bad] })),
        JSON.stringify(bad)
      ).toBeUndefined()
    }
    expect(parseConnectionEntry(entry({ replicas: ['item'] }))).toBeUndefined()
    expect(parseConnectionEntry(entry({ replicas: {} }))).toBeUndefined()
  })

  it('refuses a non-empty replicas list on any other kind, and reads an empty one', () => {
    for (const kind of ['app', 'agent', 'wallet-client', 'contact', 'later']) {
      expect(
        parseConnectionEntry(entry({ kind, replicas: [item()] })),
        kind
      ).toBeUndefined()
      expect(
        parseConnectionEntry(entry({ kind, replicas: [] }))?.replicas
      ).toEqual([])
    }
  })
})

describe('recordReplicas', () => {
  it('creates the entry with its items, url, name, and seed', async () => {
    const { body, seedTag } = await registered()
    expect(body()).toEqual({
      ...entry(),
      name: 'replica.example',
      seed: SEED,
      seedTag
    })
  })

  it('adopts the ids of an item already recorded and clears retired and declined', async () => {
    const { store, body, seedTag } = await registered()
    store.put({
      resourceId: await idOf(SERVER),
      body: {
        ...body(),
        retired: T2.toISOString(),
        declined: T2.toISOString(),
        fromALaterBuild: 1
      }
    })
    const result = await recordReplicas({
      ...BASE,
      store,
      url: 'https://replica.example:8443/',
      seed: SEED,
      seedTag,
      replicas: [{ fromSpace: SPACE_URL, spaceId: OTHER_REGISTRATION }],
      now: T3
    })
    expect(result.outcome).toBe('updated')
    expect(body()).toEqual({
      ...entry(),
      name: 'replica.example',
      url: 'https://replica.example:8443/',
      lastSeen: T3.toISOString(),
      seed: SEED,
      seedTag,
      fromALaterBuild: 1
    })
  })

  it('stores a normalized source Space and matches the plain form to it', async () => {
    const { store, body } = await registered()
    const result = await recordReplicas({
      ...BASE,
      store,
      url: SERVER_URL,
      replicas: [
        {
          fromSpace: 'https://WAS.example:443/space/SPACE/',
          spaceId: OTHER_REGISTRATION
        }
      ],
      now: T2
    })
    expect(result.outcome).toBe('updated')
    // The same Space under another form of its URL adopts the stored item.
    expect(body().replicas).toEqual(entry().replicas)
    await setReplicaMarker({
      ...BASE,
      store,
      marker: 'stoppedAt',
      fromSpaces: ['https://WAS.example:443/space/SPACE/'],
      now: T3
    })
    expect((body().replicas as Array<Record<string, unknown>>)[0]).toEqual(
      item({ stoppedAt: T3.toISOString() })
    )
  })

  it('refuses to adopt an item marked lost', async () => {
    const { store, body } = await registered()
    await setReplicaMarker({
      ...BASE,
      store,
      marker: 'lostAt',
      fromSpaces: [ANNEX_URL],
      now: T2
    })
    const before = body()
    await expect(
      recordReplicas({
        ...BASE,
        store,
        url: SERVER_URL,
        replicas: [{ fromSpace: ANNEX_URL, spaceId: OTHER_REGISTRATION }]
      })
    ).rejects.toThrow(/marked lost/)
    expect(body()).toEqual(before)
    // Removing the item first lets the Space be registered again.
    await removeReplica({ ...BASE, store, fromSpace: ANNEX_URL })
    await recordReplicas({
      ...BASE,
      store,
      url: SERVER_URL,
      replicas: [{ fromSpace: ANNEX_URL, spaceId: OTHER_REGISTRATION }]
    })
    expect(body().replicas).toEqual([
      item(),
      item({ fromSpace: ANNEX_URL, spaceId: OTHER_REGISTRATION })
    ])
  })

  it('refuses a different seed, a seed without its tag, a bad id, and a repeated Space', async () => {
    const { store, seedTag } = await registered()
    const otherTag = await connectionSeedTag({
      hmacKey: HMAC_KEY,
      seed: OTHER_SEED
    })
    const one = [{ fromSpace: SPACE_URL, spaceId: ACCOUNT_REPLICA }]
    await expect(
      recordReplicas({
        ...BASE,
        store,
        url: SERVER_URL,
        seed: OTHER_SEED,
        seedTag: otherTag,
        replicas: one
      })
    ).rejects.toThrow(/different pairwise seed/)
    await expect(
      recordReplicas({
        ...BASE,
        store,
        url: SERVER_URL,
        seed: SEED,
        replicas: one
      })
    ).rejects.toThrow(TypeError)
    await expect(
      recordReplicas({
        ...BASE,
        store,
        url: SERVER_URL,
        replicas: [{ fromSpace: SPACE_URL, spaceId: 'nope' }]
      })
    ).rejects.toThrow(/32 random bytes/)
    await expect(
      recordReplicas({
        ...BASE,
        store,
        url: SERVER_URL,
        replicas: [
          { fromSpace: 'https://was.example/space/X', spaceId: ACCOUNT_REPLICA }
        ]
      })
    ).rejects.toThrow(/ending with a slash/)
    await expect(
      recordReplicas({
        ...BASE,
        store,
        url: SERVER_URL,
        replicas: [...one, ...one]
      })
    ).rejects.toThrow(/named twice/)
    expect(seedTag).toBeDefined()
  })
})

describe('recordReplicaGrant', () => {
  it('records the grant and the pending registration id in one write', async () => {
    const { store, body, writes } = await registered()
    const before = writes.length
    const result = await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: pullGrant('urn:zcap:pull'),
      pendingRegistrationId: REGISTRATION,
      now: T2
    })
    expect(result.outcome).toBe('updated')
    expect(writes.length - before).toBe(1)
    expect(body().grants).toEqual([
      {
        zcap: pullGrant('urn:zcap:pull'),
        grantKind: 'grant',
        grantedAt: T2.toISOString()
      }
    ])
    expect(body().replicas).toEqual([
      item({ pendingRegistrationId: REGISTRATION }),
      item({ fromSpace: ANNEX_URL, spaceId: ANNEX_REPLICA })
    ])
    // The re-run writes nothing.
    const again = await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: pullGrant('urn:zcap:pull'),
      pendingRegistrationId: REGISTRATION,
      now: T3
    })
    expect(again.outcome).toBe('unchanged')
  })

  it('appends a renewal keeping grantedAt, with renewedAt and no pending id, leaving declined as it stands', async () => {
    const { store, body } = await registered()
    await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: pullGrant('urn:zcap:pull'),
      pendingRegistrationId: REGISTRATION,
      now: T1
    })
    await settleReplicaRegistration({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      registrationId: REGISTRATION
    })
    await markDeclined({ ...BASE, store, now: T2 })
    const renewed = zcap({
      id: 'urn:zcap:pull-2',
      controller: SERVER,
      target: SPACE_URL,
      expires: '2028-01-01T00:00:00.000Z'
    })
    await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: renewed,
      renews: 'urn:zcap:pull',
      now: T3
    })
    expect(body().declined).toBe(T2.toISOString())
    expect(body().grants).toEqual([
      {
        zcap: pullGrant('urn:zcap:pull'),
        grantKind: 'grant',
        grantedAt: T1.toISOString()
      },
      {
        zcap: renewed,
        grantKind: 'grant',
        grantedAt: T1.toISOString(),
        renewedAt: T3.toISOString()
      }
    ])
    expect(body().replicas).toEqual([
      item({ registrationId: REGISTRATION }),
      item({ fromSpace: ANNEX_URL, spaceId: ANNEX_REPLICA })
    ])
  })

  it('refuses a renewal of a gone or superseded source, of another scope, or not expiring later', async () => {
    const { store } = await registered()
    const first = pullGrant('urn:zcap:pull')
    await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: first
    })
    const later = (id: string, overrides: Record<string, unknown> = {}) =>
      zcap({
        id,
        controller: SERVER,
        target: SPACE_URL,
        expires: '2028-01-01T00:00:00.000Z',
        ...overrides
      })
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: later('urn:zcap:x'),
        renews: 'urn:zcap:gone'
      })
    ).rejects.toThrow(/no longer on the connections entry/)
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: pullGrant('urn:zcap:x'),
        renews: 'urn:zcap:pull'
      })
    ).rejects.toThrow(/strictly later/)
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: later('urn:zcap:x', { target: `${SPACE_URL}id/` }),
        renews: 'urn:zcap:pull'
      })
    ).rejects.toThrow(/keep its controller, invocation target/)
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: later('urn:zcap:x'),
        renews: 'urn:zcap:pull',
        pendingRegistrationId: REGISTRATION
      })
    ).rejects.toThrow(/not both/)
    await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: later('urn:zcap:pull-2'),
      renews: 'urn:zcap:pull'
    })
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: later('urn:zcap:x', { expires: '2029-01-01T00:00:00.000Z' }),
        renews: 'urn:zcap:pull'
      })
    ).rejects.toThrow(/no longer the latest of its scope/)
  })

  it('refuses a second pending id while one stands, and a grant allowing more than GET', async () => {
    const { store, body } = await registered()
    await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: pullGrant('urn:zcap:pull'),
      pendingRegistrationId: REGISTRATION
    })
    const before = body()
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: pullGrant('urn:zcap:pull-2'),
        pendingRegistrationId: OTHER_REGISTRATION
      })
    ).rejects.toThrow(/registration pending under/)
    expect(body()).toEqual(before)
    const broad = (allowedAction?: string | string[]) => {
      const capability = zcap({
        id: 'urn:zcap:x',
        controller: SERVER,
        target: ANNEX_URL,
        allowedAction
      })
      if (allowedAction === undefined) {
        delete (capability as Record<string, unknown>).allowedAction
      }
      return capability
    }
    for (const allowedAction of [['GET', 'PUT'], 'PUT', undefined, ['get']]) {
      await expect(
        recordReplicaGrant({
          ...BASE,
          store,
          fromSpace: ANNEX_URL,
          zcap: broad(allowedAction)
        }),
        JSON.stringify(allowedAction)
      ).rejects.toThrow(/GET and nothing else/)
    }
    // The string form of the one action is admitted.
    const result = await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: ANNEX_URL,
      zcap: zcap({
        id: 'urn:zcap:annex',
        controller: SERVER,
        target: ANNEX_URL,
        allowedAction: 'GET'
      })
    })
    expect(result.outcome).toBe('updated')
  })

  it('refuses a registered item a new pending id, a foreign grant, a stray target, a retired entry, and an unknown Space', async () => {
    const { store, resourceId, rows } = await registered()
    await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: pullGrant('urn:zcap:pull'),
      pendingRegistrationId: REGISTRATION
    })
    await settleReplicaRegistration({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      registrationId: REGISTRATION
    })
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: pullGrant('urn:zcap:pull-2'),
        pendingRegistrationId: OTHER_REGISTRATION
      })
    ).rejects.toThrow(/registered already/)
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: zcap({ id: 'urn:zcap:x', controller: APP })
      })
    ).rejects.toThrow(/delegated to the party/)
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: pullGrant('urn:zcap:x', ANNEX_URL)
      })
    ).rejects.toThrow(/must target this Space/)
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: 'https://was.example/space/NONE/',
        zcap: pullGrant('urn:zcap:x', 'https://was.example/space/NONE/')
      })
    ).rejects.toThrow(/lists no replica/)
    const stored = rows.get(resourceId)!
    stored.body = { ...(stored.body as object), retired: T2.toISOString() }
    await expect(
      recordReplicaGrant({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        zcap: pullGrant('urn:zcap:x')
      })
    ).rejects.toThrow(/retired/)
    const { store: empty } = memoryConnectionsStore()
    expect(
      (
        await recordReplicaGrant({
          ...BASE,
          store: empty,
          fromSpace: SPACE_URL,
          zcap: pullGrant('urn:zcap:x')
        })
      ).outcome
    ).toBe('absent')
  })
})

describe('settleReplicaRegistration', () => {
  it('moves the landed id, is idempotent, and refuses another id', async () => {
    const { store, body } = await registered()
    await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: pullGrant('urn:zcap:pull'),
      pendingRegistrationId: REGISTRATION
    })
    await expect(
      settleReplicaRegistration({
        ...BASE,
        store,
        fromSpace: SPACE_URL,
        registrationId: OTHER_REGISTRATION
      })
    ).rejects.toThrow(/no pending registration/)
    const first = await settleReplicaRegistration({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      registrationId: REGISTRATION
    })
    expect(first.outcome).toBe('updated')
    expect((body().replicas as Array<Record<string, unknown>>)[0]).toEqual(
      item({ registrationId: REGISTRATION })
    )
    const again = await settleReplicaRegistration({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      registrationId: REGISTRATION
    })
    expect(again.outcome).toBe('unchanged')
    await expect(
      settleReplicaRegistration({
        ...BASE,
        store,
        fromSpace: ANNEX_URL,
        registrationId: REGISTRATION
      })
    ).rejects.toThrow(/no pending registration/)
  })
})

describe('the intent markers', () => {
  it('sets stoppedAt on every item in one write, keeps a held time, and clears it', async () => {
    const { store, body, writes } = await registered()
    const before = writes.length
    const stopped = await setReplicaMarker({
      ...BASE,
      store,
      marker: 'stoppedAt',
      now: T2
    })
    expect(stopped.outcome).toBe('updated')
    expect(writes.length - before).toBe(1)
    expect(body().replicas).toEqual([
      item({ stoppedAt: T2.toISOString() }),
      item({
        fromSpace: ANNEX_URL,
        spaceId: ANNEX_REPLICA,
        stoppedAt: T2.toISOString()
      })
    ])
    const again = await setReplicaMarker({
      ...BASE,
      store,
      marker: 'stoppedAt',
      now: T3
    })
    expect(again.outcome).toBe('unchanged')
    const cleared = await clearReplicaMarker({
      ...BASE,
      store,
      marker: 'stoppedAt',
      fromSpaces: [ANNEX_URL]
    })
    expect(cleared.outcome).toBe('updated')
    expect(body().replicas).toEqual([
      item({ stoppedAt: T2.toISOString() }),
      item({ fromSpace: ANNEX_URL, spaceId: ANNEX_REPLICA })
    ])
    expect(
      (await clearReplicaMarker({ ...BASE, store, marker: 'lostAt' })).outcome
    ).toBe('unchanged')
  })

  it('writes restartedAt and clears declined in the same write', async () => {
    const { store, body, writes } = await registered()
    await markDeclined({ ...BASE, store, now: T1 })
    expect(body().declined).toBe(T1.toISOString())
    const before = writes.length
    await setReplicaMarker({
      ...BASE,
      store,
      marker: 'restartedAt',
      fromSpaces: [SPACE_URL],
      now: T2
    })
    expect(writes.length - before).toBe(1)
    expect(body().declined).toBeUndefined()
    expect((body().replicas as Array<Record<string, unknown>>)[0]).toEqual(
      item({ restartedAt: T2.toISOString() })
    )
    // An empty list marks nothing, so it must not clear the decline either.
    await markDeclined({ ...BASE, store, now: T3 })
    await expect(
      setReplicaMarker({
        ...BASE,
        store,
        marker: 'restartedAt',
        fromSpaces: []
      })
    ).rejects.toThrow(TypeError)
    await expect(
      clearReplicaMarker({
        ...BASE,
        store,
        marker: 'restartedAt',
        fromSpaces: []
      })
    ).rejects.toThrow(TypeError)
    expect(body().declined).toBe(T3.toISOString())
    // A declined entry whose items all carry the marker still gets the decline cleared.
    const result = await setReplicaMarker({
      ...BASE,
      store,
      marker: 'restartedAt',
      fromSpaces: [SPACE_URL],
      now: T3
    })
    expect(result.outcome).toBe('updated')
    expect(body().declined).toBeUndefined()
  })

  it('marks lostAt on one item and refuses an unknown Space', async () => {
    const { store, body } = await registered()
    await setReplicaMarker({
      ...BASE,
      store,
      marker: 'lostAt',
      fromSpaces: [ANNEX_URL],
      now: T2
    })
    expect(body().replicas).toEqual([
      item(),
      item({
        fromSpace: ANNEX_URL,
        spaceId: ANNEX_REPLICA,
        lostAt: T2.toISOString()
      })
    ])
    await expect(
      setReplicaMarker({
        ...BASE,
        store,
        marker: 'lostAt',
        fromSpaces: ['https://was.example/space/NONE/']
      })
    ).rejects.toThrow(/lists no replica/)
    await expect(
      clearReplicaMarker({
        ...BASE,
        store,
        marker: 'lostAt',
        fromSpaces: ['https://was.example/space/NONE/']
      })
    ).rejects.toThrow(/lists no replica/)
  })
})

describe('removeReplica and retirement', () => {
  it('removes an item, refuses one with a standing grant, and retires once empty', async () => {
    const { store, body } = await registered()
    await recordReplicaGrant({
      ...BASE,
      store,
      fromSpace: SPACE_URL,
      zcap: pullGrant('urn:zcap:pull'),
      pendingRegistrationId: REGISTRATION
    })
    await expect(
      retireConnection({
        ...BASE,
        store,
        handledZcapIds: ['urn:zcap:pull'],
        spaceUrl: SPACE_URL,
        now: T2
      })
    ).rejects.toThrow(/retires once every item is removed/)
    await expect(
      removeReplica({ ...BASE, store, fromSpace: SPACE_URL })
    ).rejects.toThrow(/Stop removes them/)
    const annex = await removeReplica({ ...BASE, store, fromSpace: ANNEX_URL })
    expect(annex.outcome).toBe('updated')
    expect(
      (await removeReplica({ ...BASE, store, fromSpace: ANNEX_URL })).outcome
    ).toBe('unchanged')
    // Stop's last step removed the grant; then the account item goes.
    const stored = body()
    await store.put({
      resourceId: await idOf(SERVER),
      body: { ...stored, grants: [] }
    })
    await removeReplica({ ...BASE, store, fromSpace: SPACE_URL })
    expect(body().replicas).toEqual([])
    const retired = await retireConnection({
      ...BASE,
      store,
      handledZcapIds: [],
      spaceUrl: SPACE_URL,
      now: T3
    })
    expect(retired.outcome).toBe('updated')
    expect(body().retired).toBe(T3.toISOString())
    expect(body().seed).toBe(SEED)
  })
})

describe('the kind refusals', () => {
  it('refuses another kind in every replica helper, and the agent helpers accept the kind', async () => {
    const { store } = memoryConnectionsStore()
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      did: SERVER,
      kind: 'agent',
      grants: [],
      now: T1
    })
    const calls = [
      () =>
        recordReplicas({ ...BASE, store, url: SERVER_URL, replicas: [item()] }),
      () =>
        recordReplicaGrant({
          ...BASE,
          store,
          fromSpace: SPACE_URL,
          zcap: pullGrant('urn:zcap:x')
        }),
      () =>
        settleReplicaRegistration({
          ...BASE,
          store,
          fromSpace: SPACE_URL,
          registrationId: REGISTRATION
        }),
      () => setReplicaMarker({ ...BASE, store, marker: 'stoppedAt' }),
      () => clearReplicaMarker({ ...BASE, store, marker: 'stoppedAt' }),
      () => removeReplica({ ...BASE, store, fromSpace: SPACE_URL })
    ]
    for (const call of calls) {
      await expect(call()).rejects.toBeInstanceOf(ConnectionKindMismatchError)
    }
    const { store: replicaStore, body } = await registered()
    await expect(
      recordGrants({
        store: replicaStore,
        hmacKey: HMAC_KEY,
        did: SERVER,
        kind: 'app',
        grants: []
      })
    ).rejects.toBeInstanceOf(ConnectionKindMismatchError)
    const consent = await recordGrants({
      store: replicaStore,
      hmacKey: HMAC_KEY,
      did: SERVER,
      kind: 'replica-server',
      spaceUrl: SPACE_URL,
      grants: [{ zcap: pullGrant('urn:zcap:consent'), grantKind: 'grant' }],
      now: T2
    })
    expect(consent.outcome).toBe('updated')
    expect((body().grants as unknown[]).length).toBe(1)
    expect(
      (await markDeclined({ ...BASE, store: replicaStore, now: T3 })).outcome
    ).toBe('updated')
  })
})
