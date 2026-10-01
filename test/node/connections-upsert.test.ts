/**
 * Unit tests for the `connections` upsert helpers
 * (`src/connections/upsert.ts`): create, merge by capability id, un-retire,
 * removal by id, idempotent retirement, the label owned by one helper, the
 * kind refusal, the retirement's handled-set abort, the wallet-client
 * creation rule, a lost race re-read and re-applied, and the version-skew
 * round trips (unknown members kept verbatim, a newer or unparseable body
 * never written over).
 */
import { describe, expect, it } from 'vitest'
import {
  connectionResourceId,
  recordGrants,
  removeGrants,
  retireConnection,
  setConnectionLabel
} from '../../src/connections/index.js'
import type { ConnectionsStore } from '../../src/connections/index.js'
import {
  HMAC_KEY,
  SPACE_URL,
  memoryConnectionsStore,
  namedError,
  zcap
} from './fixtures/memoryConnections.js'

const APP = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const CLIENT = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
const OTHER = 'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf'
const CLIENT_KEY = CLIENT.slice('did:key:'.length)
// A bidi control, built from its code point so no literal one sits in source.
const RLO = String.fromCodePoint(0x202e)
const T1 = new Date('2026-10-01T00:00:00.000Z')
const T2 = new Date('2026-10-02T00:00:00.000Z')
const T3 = new Date('2026-10-03T00:00:00.000Z')

async function idOf(did: string): Promise<string> {
  return connectionResourceId({ hmacKey: HMAC_KEY, did })
}

function grant(
  id: string,
  controller = APP,
  grantKind: 'grant' | 'share' = 'grant'
) {
  return { zcap: zcap({ id, controller }), grantKind }
}

describe('recordGrants', () => {
  it('creates an entry with its grants, names, and timestamps', async () => {
    const { store, rows } = memoryConnectionsStore()
    const result = await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'app',
      grants: [grant('urn:zcap:1'), grant('urn:zcap:2', APP, 'share')],
      name: `  Example App${RLO} `,
      origin: 'https://app.example',
      url: 'https://app.example/',
      appKey: 'zAppKey',
      now: T1
    })
    expect(result).toEqual({ resourceId: await idOf(APP), outcome: 'created' })
    expect(rows.get(result.resourceId)?.body).toEqual({
      version: 1,
      kind: 'app',
      id: APP,
      name: 'Example App',
      origin: 'https://app.example',
      url: 'https://app.example/',
      appKey: 'zAppKey',
      firstSeen: T1.toISOString(),
      lastSeen: T1.toISOString(),
      grants: [
        {
          zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
          grantKind: 'grant',
          grantedAt: T1.toISOString()
        },
        {
          zcap: zcap({ id: 'urn:zcap:2', controller: APP }),
          grantKind: 'share',
          grantedAt: T1.toISOString()
        }
      ],
      writers: []
    })
  })

  it('writes a zero-grant consent, and stores no name outside the bound', async () => {
    const { store, rows } = memoryConnectionsStore()
    const { resourceId } = await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'app',
      grants: [],
      name: 'a'.repeat(65),
      origin: 'https://app.example',
      now: T1
    })
    expect(rows.get(resourceId)?.body).toMatchObject({
      grants: [],
      origin: 'https://app.example'
    })
    expect(rows.get(resourceId)?.body).not.toHaveProperty('name')
  })

  it('merges by capability id, un-retires, and leaves label and firstSeen alone', async () => {
    const { store, rows } = memoryConnectionsStore()
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'agent',
      grants: [grant('urn:zcap:1')],
      name: 'Agent',
      now: T1
    })
    const resourceId = await idOf(APP)
    rows.set(resourceId, {
      body: {
        ...(rows.get(resourceId)!.body as object),
        label: 'My agent',
        retired: T1.toISOString()
      },
      etag: 'retired'
    })
    const result = await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'agent',
      grants: [grant('urn:zcap:1'), grant('urn:zcap:2')],
      name: 'a'.repeat(65),
      now: T2
    })
    expect(result.outcome).toBe('updated')
    const body = rows.get(resourceId)?.body as Record<string, unknown>
    expect(body).not.toHaveProperty('retired')
    expect(body.label).toBe('My agent')
    expect(body.name).toBe('Agent')
    expect(body.firstSeen).toBe(T1.toISOString())
    expect(body.lastSeen).toBe(T2.toISOString())
    const grants = body.grants as Array<{
      zcap: { id: string }
      grantedAt: string
    }>
    expect(grants.map(item => [item.zcap.id, item.grantedAt])).toEqual([
      ['urn:zcap:1', T1.toISOString()],
      ['urn:zcap:2', T2.toISOString()]
    ])
  })

  it('refuses a grant delegated to another party, outside this Space, or of an unknown kind', async () => {
    const { store, writes } = memoryConnectionsStore()
    await expect(
      recordGrants({
        store,
        hmacKey: HMAC_KEY,
        spaceUrl: SPACE_URL,
        did: APP,
        kind: 'app',
        grants: [grant('urn:zcap:1', OTHER)]
      })
    ).rejects.toThrow(TypeError)
    // The same check every reader applies: a grant stored here is one the
    // revocation index sees.
    for (const target of [
      'https://was.example/space/OTHER/private-credentials/',
      'https://was.example:8443/space/SPACE/private-credentials/',
      'not a url'
    ]) {
      await expect(
        recordGrants({
          store,
          hmacKey: HMAC_KEY,
          spaceUrl: SPACE_URL,
          did: APP,
          kind: 'app',
          grants: [
            {
              zcap: zcap({ id: 'urn:zcap:1', controller: APP, target }),
              grantKind: 'grant'
            }
          ]
        })
      ).rejects.toThrow(/target this Space/)
    }
    await expect(
      recordGrants({
        store,
        hmacKey: HMAC_KEY,
        spaceUrl: SPACE_URL,
        did: APP,
        kind: 'app',
        grants: [
          {
            zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
            grantKind: 'lease'
          }
        ] as never
      })
    ).rejects.toThrow(TypeError)
    expect(writes).toEqual([])
  })

  it('without a Space, writes a zero-grant entry and refuses any grant', async () => {
    const { store, rows, writes } = memoryConnectionsStore()
    await expect(
      recordGrants({
        store,
        hmacKey: HMAC_KEY,
        did: APP,
        kind: 'app',
        grants: [grant('urn:zcap:1')]
      })
    ).rejects.toThrow(/container URL/)
    expect(writes).toEqual([])

    const result = await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      kind: 'app',
      grants: [],
      name: 'Example App',
      origin: 'https://app.example',
      url: 'https://app.example/',
      appKey: 'zAppKey',
      now: T1
    })
    expect(result).toEqual({ resourceId: await idOf(APP), outcome: 'created' })
    expect(rows.get(result.resourceId)?.body).toEqual({
      version: 1,
      kind: 'app',
      id: APP,
      name: 'Example App',
      origin: 'https://app.example',
      url: 'https://app.example/',
      appKey: 'zAppKey',
      firstSeen: T1.toISOString(),
      lastSeen: T1.toISOString(),
      grants: [],
      writers: []
    })
  })
})

describe('kind mismatch', () => {
  it('refuses recordGrants and the wallet-client writes over another kind', async () => {
    const { store, rows, writes } = memoryConnectionsStore()
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'app',
      grants: [grant('urn:zcap:1')],
      now: T1
    })
    const before = structuredClone(rows.get(await idOf(APP)))
    const count = writes.length
    await expect(
      recordGrants({
        store,
        hmacKey: HMAC_KEY,
        spaceUrl: SPACE_URL,
        did: APP,
        kind: 'agent',
        grants: [grant('urn:zcap:2')]
      })
    ).rejects.toMatchObject({
      name: 'ConnectionKindMismatchError',
      expectedKind: 'agent',
      foundKind: 'app'
    })
    await expect(
      setConnectionLabel({
        store,
        hmacKey: HMAC_KEY,
        did: APP,
        kind: 'wallet-client',
        label: 'Laptop'
      })
    ).rejects.toMatchObject({ name: 'ConnectionKindMismatchError' })
    expect(writes).toHaveLength(count)
    expect(rows.get(await idOf(APP))).toEqual(before)
  })

  it('retires an entry of any kind', async () => {
    for (const kind of ['app', 'agent', 'wallet-client', 'contact'] as const) {
      const { store, rows } = memoryConnectionsStore()
      await recordGrants({
        store,
        hmacKey: HMAC_KEY,
        spaceUrl: SPACE_URL,
        did: APP,
        kind,
        grants: [grant('urn:zcap:1')],
        now: T1
      })
      const result = await retireConnection({
        store,
        hmacKey: HMAC_KEY,
        did: APP,
        handledZcapIds: ['urn:zcap:1'],
        spaceUrl: SPACE_URL,
        now: T2
      })
      expect(result.outcome).toBe('updated')
      expect(rows.get(result.resourceId)?.body).toMatchObject({
        kind,
        retired: T2.toISOString(),
        grants: []
      })
    }
  })
})

describe('removeGrants', () => {
  it('removes by capability id and writes nothing when none match', async () => {
    const { store, rows, writes } = memoryConnectionsStore()
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'app',
      grants: [grant('urn:zcap:1'), grant('urn:zcap:2', APP, 'share')],
      now: T1
    })
    const result = await removeGrants({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      zcapIds: ['urn:zcap:2']
    })
    expect(result.outcome).toBe('updated')
    const body = rows.get(result.resourceId)?.body as {
      grants: Array<{ zcap: { id: string } }>
      lastSeen: string
    }
    expect(body.grants.map(item => item.zcap.id)).toEqual(['urn:zcap:1'])
    expect(body.lastSeen).toBe(T1.toISOString())

    const count = writes.length
    expect(
      (
        await removeGrants({
          store,
          hmacKey: HMAC_KEY,
          did: APP,
          zcapIds: ['urn:zcap:9']
        })
      ).outcome
    ).toBe('unchanged')
    expect(
      (
        await removeGrants({
          store,
          hmacKey: HMAC_KEY,
          did: OTHER,
          zcapIds: ['urn:zcap:1']
        })
      ).outcome
    ).toBe('absent')
    expect(writes).toHaveLength(count)
  })
})

describe('retireConnection', () => {
  it('empties grants, drops appKey, keeps the rest, and is idempotent', async () => {
    const { store, rows, writes } = memoryConnectionsStore()
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'app',
      grants: [grant('urn:zcap:1')],
      name: 'Example App',
      origin: 'https://app.example',
      appKey: 'zAppKey',
      now: T1
    })
    const options = {
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      handledZcapIds: ['urn:zcap:1'],
      spaceUrl: SPACE_URL
    }
    expect((await retireConnection({ ...options, now: T2 })).outcome).toBe(
      'updated'
    )
    const body = rows.get(await idOf(APP))?.body as Record<string, unknown>
    expect(body).toMatchObject({
      name: 'Example App',
      origin: 'https://app.example',
      firstSeen: T1.toISOString(),
      lastSeen: T1.toISOString(),
      retired: T2.toISOString(),
      grants: [],
      writers: []
    })
    expect(body).not.toHaveProperty('appKey')

    const count = writes.length
    expect((await retireConnection({ ...options, now: T3 })).outcome).toBe(
      'unchanged'
    )
    expect(writes).toHaveLength(count)
    expect(
      (await retireConnection({ ...options, did: OTHER, now: T3 })).outcome
    ).toBe('absent')
  })

  it('throws when it finds a grant outside the handled set', async () => {
    const { store, rows } = memoryConnectionsStore()
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'app',
      grants: [grant('urn:zcap:1')],
      now: T1
    })
    // A concurrent consent merges a grant between the disconnect's read and
    // its retirement: the first write loses the race, and the re-read finds
    // the new grant.
    let raced = false
    const racing: ConnectionsStore = {
      ...store,
      async put(options) {
        if (!raced) {
          raced = true
          await recordGrants({
            store,
            hmacKey: HMAC_KEY,
            spaceUrl: SPACE_URL,
            did: APP,
            kind: 'app',
            grants: [grant('urn:zcap:2')],
            now: T2
          })
        }
        return store.put(options)
      }
    }
    await expect(
      retireConnection({
        store: racing,
        hmacKey: HMAC_KEY,
        did: APP,
        handledZcapIds: ['urn:zcap:1'],
        spaceUrl: SPACE_URL,
        now: T3
      })
    ).rejects.toThrow(/did not handle/)
    const body = rows.get(await idOf(APP))?.body as Record<string, unknown>
    expect(body).not.toHaveProperty('retired')
    expect((body.grants as unknown[]).length).toBe(2)
  })

  it('empties a foreign grant without requiring it handled', async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const resourceId = await idOf(APP)
    seed(resourceId, {
      version: 1,
      kind: 'app',
      id: APP,
      firstSeen: T1.toISOString(),
      lastSeen: T1.toISOString(),
      grants: [
        {
          zcap: zcap({ id: 'urn:zcap:foreign', controller: OTHER }),
          grantKind: 'grant',
          grantedAt: T1.toISOString()
        },
        {
          zcap: zcap({
            id: 'urn:zcap:elsewhere',
            controller: APP,
            target: 'https://was.example/space/OTHER/private-credentials/'
          }),
          grantKind: 'grant',
          grantedAt: T1.toISOString()
        }
      ],
      writers: []
    })
    const result = await retireConnection({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      handledZcapIds: [],
      spaceUrl: SPACE_URL,
      now: T2
    })
    expect(result.outcome).toBe('updated')
    expect(rows.get(resourceId)?.body).toMatchObject({ grants: [] })
  })

  it("without spaceUrl counts no grant as the party's and empties them all", async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const resourceId = await idOf(APP)
    seed(resourceId, {
      version: 1,
      kind: 'app',
      id: APP,
      appKey: 'zAppKey',
      firstSeen: T1.toISOString(),
      lastSeen: T1.toISOString(),
      grants: [
        {
          zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
          grantKind: 'grant',
          grantedAt: T1.toISOString()
        }
      ],
      writers: []
    })
    const result = await retireConnection({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      handledZcapIds: [],
      now: T2
    })
    expect(result.outcome).toBe('updated')
    const body = rows.get(resourceId)?.body as Record<string, unknown>
    expect(body).toMatchObject({ grants: [], retired: T2.toISOString() })
    expect(body).not.toHaveProperty('appKey')
  })
})

describe('setConnectionLabel', () => {
  it('creates an absent entry for a listed wallet client only', async () => {
    const { store, rows, writes } = memoryConnectionsStore()
    const enrolledSigningKeys = new Set([CLIENT_KEY])
    const result = await setConnectionLabel({
      store,
      hmacKey: HMAC_KEY,
      did: CLIENT,
      kind: 'wallet-client',
      name: 'Pixel 9',
      enrolledSigningKeys,
      now: T1
    })
    expect(result.outcome).toBe('created')
    expect(rows.get(result.resourceId)?.body).toEqual({
      version: 1,
      kind: 'wallet-client',
      id: CLIENT,
      name: 'Pixel 9',
      firstSeen: T1.toISOString(),
      lastSeen: T1.toISOString(),
      grants: [],
      writers: []
    })

    const count = writes.length
    // A wallet client the document does not list.
    await expect(
      setConnectionLabel({
        store,
        hmacKey: HMAC_KEY,
        did: OTHER,
        kind: 'wallet-client',
        label: 'Gone',
        enrolledSigningKeys
      })
    ).rejects.toThrow(/verified account document/)
    // Any other party.
    await expect(
      setConnectionLabel({
        store,
        hmacKey: HMAC_KEY,
        did: APP,
        kind: 'app',
        label: 'Mine',
        enrolledSigningKeys: new Set([APP.slice('did:key:'.length)])
      })
    ).rejects.toThrow(/verified account document/)
    expect(writes).toHaveLength(count)
  })

  it('refuses a label outside the display-name rule, and strips it otherwise', async () => {
    const { store, rows, writes } = memoryConnectionsStore()
    const enrolledSigningKeys = new Set([CLIENT_KEY])
    for (const label of ['a'.repeat(65), RLO]) {
      await expect(
        setConnectionLabel({
          store,
          hmacKey: HMAC_KEY,
          did: CLIENT,
          kind: 'wallet-client',
          label,
          enrolledSigningKeys
        })
      ).rejects.toThrow(TypeError)
    }
    expect(writes).toEqual([])
    const { resourceId } = await setConnectionLabel({
      store,
      hmacKey: HMAC_KEY,
      did: CLIENT,
      kind: 'wallet-client',
      label: ` Work${RLO} phone `,
      enrolledSigningKeys
    })
    expect(rows.get(resourceId)?.body).toMatchObject({ label: 'Work phone' })
  })

  it('sets and clears label, and only it touches label', async () => {
    const { store, rows } = memoryConnectionsStore()
    const enrolledSigningKeys = new Set([CLIENT_KEY])
    await setConnectionLabel({
      store,
      hmacKey: HMAC_KEY,
      did: CLIENT,
      kind: 'wallet-client',
      name: 'Pixel 9',
      label: '  Work phone ',
      enrolledSigningKeys,
      now: T1
    })
    const resourceId = await idOf(CLIENT)
    expect(rows.get(resourceId)?.body).toMatchObject({
      label: 'Work phone',
      name: 'Pixel 9'
    })

    // recordGrants, removeGrants, and retireConnection leave label alone.
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: CLIENT,
      kind: 'wallet-client',
      grants: [grant('urn:zcap:1', CLIENT)],
      name: 'Renamed by itself',
      now: T2
    })
    await removeGrants({
      store,
      hmacKey: HMAC_KEY,
      did: CLIENT,
      zcapIds: ['urn:zcap:1']
    })
    await retireConnection({
      store,
      hmacKey: HMAC_KEY,
      did: CLIENT,
      handledZcapIds: [],
      spaceUrl: SPACE_URL,
      now: T3
    })
    expect(rows.get(resourceId)?.body).toMatchObject({
      label: 'Work phone',
      name: 'Renamed by itself'
    })

    // Leaving label out leaves it; a blank label removes it.
    expect(
      (
        await setConnectionLabel({
          store,
          hmacKey: HMAC_KEY,
          did: CLIENT,
          kind: 'wallet-client'
        })
      ).outcome
    ).toBe('unchanged')
    await setConnectionLabel({
      store,
      hmacKey: HMAC_KEY,
      did: CLIENT,
      kind: 'wallet-client',
      label: '   '
    })
    expect(rows.get(resourceId)?.body).not.toHaveProperty('label')
  })
})

describe('lost races', () => {
  it('re-reads and re-applies a 412 on each helper', async () => {
    const enrolledSigningKeys = new Set([CLIENT_KEY])
    const runs: Array<{
      name: string
      did: string
      prepare: (store: ConnectionsStore) => Promise<unknown>
      run: (store: ConnectionsStore) => Promise<unknown>
      expected: Record<string, unknown>
    }> = [
      {
        name: 'recordGrants',
        did: APP,
        prepare: async store =>
          recordGrants({
            store,
            hmacKey: HMAC_KEY,
            spaceUrl: SPACE_URL,
            did: APP,
            kind: 'app',
            grants: [grant('urn:zcap:1')],
            now: T1
          }),
        run: async store =>
          recordGrants({
            store,
            hmacKey: HMAC_KEY,
            spaceUrl: SPACE_URL,
            did: APP,
            kind: 'app',
            grants: [grant('urn:zcap:2')],
            now: T2
          }),
        expected: { lastSeen: T2.toISOString() }
      },
      {
        name: 'removeGrants',
        did: APP,
        prepare: async store =>
          recordGrants({
            store,
            hmacKey: HMAC_KEY,
            spaceUrl: SPACE_URL,
            did: APP,
            kind: 'app',
            grants: [grant('urn:zcap:1'), grant('urn:zcap:2')],
            now: T1
          }),
        run: async store =>
          removeGrants({
            store,
            hmacKey: HMAC_KEY,
            did: APP,
            zcapIds: ['urn:zcap:1', 'urn:zcap:2']
          }),
        expected: { grants: [] }
      },
      {
        name: 'retireConnection',
        did: APP,
        prepare: async store =>
          recordGrants({
            store,
            hmacKey: HMAC_KEY,
            spaceUrl: SPACE_URL,
            did: APP,
            kind: 'app',
            grants: [grant('urn:zcap:1')],
            now: T1
          }),
        run: async store =>
          retireConnection({
            store,
            hmacKey: HMAC_KEY,
            did: APP,
            handledZcapIds: ['urn:zcap:1'],
            spaceUrl: SPACE_URL,
            now: T3
          }),
        expected: { retired: T3.toISOString() }
      },
      {
        name: 'setConnectionLabel',
        did: CLIENT,
        prepare: async store =>
          setConnectionLabel({
            store,
            hmacKey: HMAC_KEY,
            did: CLIENT,
            kind: 'wallet-client',
            name: 'Pixel 9',
            enrolledSigningKeys,
            now: T1
          }),
        run: async store =>
          setConnectionLabel({
            store,
            hmacKey: HMAC_KEY,
            did: CLIENT,
            kind: 'wallet-client',
            label: 'Work phone'
          }),
        expected: { label: 'Work phone' }
      }
    ]
    for (const { name, did, prepare, run, expected } of runs) {
      const { store, rows } = memoryConnectionsStore()
      await prepare(store)
      const resourceId = await idOf(did)
      let raced = false
      let gets = 0
      const racing: ConnectionsStore = {
        ...store,
        async get(options) {
          gets++
          return store.get(options)
        },
        async put(options) {
          if (!raced) {
            raced = true
            // Another writer lands between this helper's read and its write.
            const row = rows.get(resourceId)!
            rows.set(resourceId, {
              body: { ...(row.body as object), extra: 'concurrent' },
              etag: 'concurrent'
            })
          }
          return store.put(options)
        }
      }
      await run(racing)
      expect(gets, name).toBe(2)
      expect(rows.get(resourceId)?.body, name).toMatchObject({
        ...expected,
        extra: 'concurrent'
      })
    }
  })

  it('throws the last lost race after three attempts', async () => {
    const { store } = memoryConnectionsStore()
    const losing: ConnectionsStore = {
      ...store,
      async put() {
        throw namedError('PreconditionFailedError')
      }
    }
    await expect(
      recordGrants({
        store: losing,
        hmacKey: HMAC_KEY,
        spaceUrl: SPACE_URL,
        did: APP,
        kind: 'app',
        grants: []
      })
    ).rejects.toMatchObject({ name: 'PreconditionFailedError' })
  })

  it('creates under ifNoneMatch, so a create race re-reads and merges', async () => {
    const { store, rows } = memoryConnectionsStore()
    let raced = false
    const racing: ConnectionsStore = {
      ...store,
      async put(options) {
        expect(options.ifNoneMatch ?? options.ifMatch).toBeDefined()
        if (!raced) {
          raced = true
          await recordGrants({
            store,
            hmacKey: HMAC_KEY,
            spaceUrl: SPACE_URL,
            did: APP,
            kind: 'app',
            grants: [grant('urn:zcap:1')],
            now: T1
          })
        }
        return store.put(options)
      }
    }
    const result = await recordGrants({
      store: racing,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'app',
      grants: [grant('urn:zcap:2')],
      now: T2
    })
    expect(result.outcome).toBe('updated')
    const body = rows.get(result.resourceId)?.body as {
      grants: Array<{ zcap: { id: string } }>
      firstSeen: string
    }
    expect(body.grants.map(item => item.zcap.id)).toEqual([
      'urn:zcap:1',
      'urn:zcap:2'
    ])
    expect(body.firstSeen).toBe(T1.toISOString())
  })

  it('refuses to write over an entry read without an ETag', async () => {
    const { store } = memoryConnectionsStore()
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'app',
      grants: [],
      now: T1
    })
    const etagless: ConnectionsStore = {
      ...store,
      async get(options) {
        const stored = await store.get(options)
        return stored === undefined ? undefined : { body: stored.body }
      }
    }
    await expect(
      recordGrants({
        store: etagless,
        hmacKey: HMAC_KEY,
        spaceUrl: SPACE_URL,
        did: APP,
        kind: 'app',
        grants: []
      })
    ).rejects.toMatchObject({ name: 'NotSupportedError' })
  })
})

describe('version skew', () => {
  const unknownGrant = {
    zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
    grantKind: 'grant',
    grantedAt: T1.toISOString(),
    note: { addedBy: 'a later build' }
  }

  function skewedEntry(overrides: Record<string, unknown> = {}) {
    return {
      version: 1,
      kind: 'app',
      id: APP,
      name: 'Example App',
      appKey: 'zAppKey',
      firstSeen: T1.toISOString(),
      lastSeen: T1.toISOString(),
      grants: [unknownGrant],
      writers: [],
      futureMember: { kept: [1, 2, 3] },
      ...overrides
    }
  }

  const helpers: Array<{
    name: string
    did: string
    run: (store: ConnectionsStore) => Promise<unknown>
  }> = [
    {
      name: 'recordGrants',
      did: APP,
      run: async store =>
        recordGrants({
          store,
          hmacKey: HMAC_KEY,
          spaceUrl: SPACE_URL,
          did: APP,
          kind: 'app',
          grants: [grant('urn:zcap:2')],
          now: T2
        })
    },
    {
      name: 'removeGrants',
      did: APP,
      run: async store =>
        removeGrants({
          store,
          hmacKey: HMAC_KEY,
          did: APP,
          zcapIds: ['urn:zcap:absent', 'urn:zcap:9']
        })
    },
    {
      name: 'setConnectionLabel',
      did: APP,
      run: async store =>
        setConnectionLabel({
          store,
          hmacKey: HMAC_KEY,
          did: APP,
          kind: 'app',
          label: 'Mine'
        })
    },
    {
      name: 'retireConnection',
      did: APP,
      run: async store =>
        retireConnection({
          store,
          hmacKey: HMAC_KEY,
          did: APP,
          handledZcapIds: ['urn:zcap:1'],
          spaceUrl: SPACE_URL,
          now: T2
        })
    }
  ]

  it('writes unknown top-level and grant-wrapper members back verbatim', async () => {
    for (const { name, run } of helpers) {
      if (name === 'retireConnection' || name === 'removeGrants') {
        continue
      }
      const { store, rows, seed } = memoryConnectionsStore()
      const resourceId = await idOf(APP)
      seed(resourceId, skewedEntry())
      await run(store)
      const body = rows.get(resourceId)?.body as Record<string, unknown>
      expect(body.futureMember, name).toEqual({ kept: [1, 2, 3] })
      expect((body.grants as unknown[])[0], name).toEqual(unknownGrant)
    }
    // The unknown top-level member also survives a removal and a retirement.
    const { store, rows, seed } = memoryConnectionsStore()
    const resourceId = await idOf(APP)
    seed(
      resourceId,
      skewedEntry({
        grants: [
          unknownGrant,
          { ...unknownGrant, zcap: zcap({ id: 'urn:zcap:9', controller: APP }) }
        ]
      })
    )
    await helpers.find(helper => helper.name === 'removeGrants')!.run(store)
    let body = rows.get(resourceId)?.body as Record<string, unknown>
    expect(body.futureMember).toEqual({ kept: [1, 2, 3] })
    expect(body.grants).toEqual([unknownGrant])
    await helpers.find(helper => helper.name === 'retireConnection')!.run(store)
    body = rows.get(resourceId)?.body as Record<string, unknown>
    expect(body.futureMember).toEqual({ kept: [1, 2, 3] })
    expect(body.retired).toBe(T2.toISOString())
  })

  it('refuses to write over a version 2 entry or an unparseable body', async () => {
    for (const stored of [
      skewedEntry({ version: 2 }),
      skewedEntry({ name: 7 }),
      skewedEntry({ grants: 'none' }),
      // A body for another party, sitting at this party's id.
      skewedEntry({ id: OTHER })
    ]) {
      for (const { name, run } of helpers) {
        const { store, rows, writes, seed } = memoryConnectionsStore()
        const resourceId = await idOf(APP)
        seed(resourceId, stored)
        await expect(run(store), name).rejects.toThrow(/refuses to write/)
        expect(writes, name).toEqual([])
        expect(rows.get(resourceId)?.body, name).toEqual(stored)
      }
    }
  })
})
