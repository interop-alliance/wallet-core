/**
 * Unit tests for the `connections` upsert helpers
 * (`src/connections/upsert.ts`): create, merge by capability id, un-retire,
 * removal by id, idempotent retirement, the consent-less un-retirement, the label owned by one helper, the
 * kind refusal, the retirement's handled-set abort, the wallet-client
 * creation rule, a lost race re-read and re-applied, and the version-skew
 * round trips (unknown members kept verbatim, a newer or unparseable body
 * never written over), and the agent-connection helpers over the pairwise
 * seed, `grantsReceived`, `outbox`, and `declined`.
 */
import { describe, expect, it } from 'vitest'
import {
  clearReceivedGrants,
  connectionResourceId,
  connectionSeedTag,
  markDeclined,
  pruneSupersededGrants,
  recordGrants,
  recordReceivedGrants,
  recordRenewedGrants,
  removeGrants,
  retireConnection,
  setConnectionLabel,
  settleOutboxItem,
  unretireConnection
} from '../../src/connections/index.js'
import type { ConnectionsStore } from '../../src/connections/index.js'
import {
  AGENT_INBOX,
  HMAC_KEY,
  OTHER_SEED,
  SEED,
  SPACE_URL,
  memoryConnectionsStore,
  namedError,
  zcap
} from './fixtures/memoryConnections.js'

const APP = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const CLIENT = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
const OTHER = 'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf'
const PAIRWISE_FOR_MESSAGE =
  'did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2'
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
      grantsReceived: [],
      outbox: [],
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
      grantsReceived: [],
      outbox: [],
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

describe('recordGrants with a message', () => {
  function envelope(ids: string[]) {
    return {
      type: 'Grant',
      actor: PAIRWISE_FOR_MESSAGE,
      object: { zcaps: ids.map(id => zcap({ id, controller: APP })) }
    }
  }

  it('queues the envelope on outbox in the same write, keeping pending items', async () => {
    const { store, rows, writes } = memoryConnectionsStore()
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'agent',
      grants: [grant('urn:zcap:1')],
      message: envelope(['urn:zcap:1']),
      now: T1
    })
    const result = await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'agent',
      grants: [grant('urn:zcap:2')],
      message: envelope(['urn:zcap:2']),
      now: T2
    })
    expect(result.outcome).toBe('updated')
    expect(writes).toHaveLength(2)
    const body = rows.get(result.resourceId)?.body as {
      grants: unknown[]
      outbox: unknown[]
    }
    expect(body.grants).toHaveLength(2)
    expect(body.outbox).toEqual([
      { message: envelope(['urn:zcap:1']), createdAt: T1.toISOString() },
      { message: envelope(['urn:zcap:2']), createdAt: T2.toISOString() }
    ])
  })

  it('refuses an envelope that does not carry exactly the grants of the call', async () => {
    const { store, rows } = memoryConnectionsStore()
    for (const ids of [['urn:zcap:9'], ['urn:zcap:1', 'urn:zcap:9'], []]) {
      await expect(
        recordGrants({
          store,
          hmacKey: HMAC_KEY,
          spaceUrl: SPACE_URL,
          did: APP,
          kind: 'agent',
          grants: [grant('urn:zcap:1')],
          message: envelope(ids),
          now: T1
        })
      ).rejects.toThrow(TypeError)
    }
    expect(rows.size).toBe(0)
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

describe('unretireConnection', () => {
  it('un-retires a retired wallet-client entry and moves lastSeen', async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const resourceId = await idOf(CLIENT)
    const writers = [
      {
        writerId: 'writer-1',
        label: 'Firefox on Linux',
        lastSeen: T1.toISOString(),
        active: true
      }
    ]
    seed(resourceId, {
      version: 1,
      kind: 'wallet-client',
      id: CLIENT,
      name: 'Laptop',
      label: 'My laptop',
      firstSeen: T1.toISOString(),
      lastSeen: T1.toISOString(),
      retired: T2.toISOString(),
      grants: [],
      writers
    })
    const result = await unretireConnection({
      store,
      hmacKey: HMAC_KEY,
      did: CLIENT,
      kind: 'wallet-client',
      now: T3
    })
    expect(result).toEqual({ resourceId, outcome: 'updated' })
    expect(rows.get(resourceId)?.body).toEqual({
      version: 1,
      kind: 'wallet-client',
      id: CLIENT,
      name: 'Laptop',
      label: 'My laptop',
      firstSeen: T1.toISOString(),
      lastSeen: T3.toISOString(),
      grants: [],
      writers
    })
  })

  it('writes nothing on an unretired entry or when none stands', async () => {
    const { store, writes } = memoryConnectionsStore()
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: CLIENT,
      kind: 'wallet-client',
      grants: [],
      now: T1
    })
    const count = writes.length
    const options = {
      store,
      hmacKey: HMAC_KEY,
      kind: 'wallet-client' as const,
      now: T2
    }
    expect(
      (await unretireConnection({ ...options, did: CLIENT })).outcome
    ).toBe('unchanged')
    expect((await unretireConnection({ ...options, did: OTHER })).outcome).toBe(
      'absent'
    )
    expect(writes).toHaveLength(count)
  })

  it('refuses an entry of another kind', async () => {
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
    await retireConnection({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      handledZcapIds: ['urn:zcap:1'],
      spaceUrl: SPACE_URL,
      now: T2
    })
    const before = structuredClone(rows.get(await idOf(APP)))
    const count = writes.length
    await expect(
      unretireConnection({
        store,
        hmacKey: HMAC_KEY,
        did: APP,
        kind: 'wallet-client',
        now: T3
      })
    ).rejects.toMatchObject({
      name: 'ConnectionKindMismatchError',
      expectedKind: 'wallet-client',
      foundKind: 'app'
    })
    expect(writes).toHaveLength(count)
    expect(rows.get(await idOf(APP))).toEqual(before)
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
      grantsReceived: [],
      outbox: [],
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

const PAIRWISE = OTHER
const T4 = new Date('2026-10-04T00:00:00.000Z')
const DAY_MS = 24 * 60 * 60 * 1000
const SKEW_MS = 10 * 60 * 1000

function inboxZcap(id: string, expires = '2027-01-01T00:00:00.000Z') {
  return zcap({
    id,
    controller: PAIRWISE,
    target: AGENT_INBOX,
    allowedAction: ['POST'],
    expires
  })
}

function receivedRecord(id: string, receivedAt = T1, expires?: string) {
  return {
    zcap: inboxZcap(id, expires),
    grantKind: 'inbox',
    receivedAt: receivedAt.toISOString()
  }
}

function grantRecord(id: string, expires: string, grantedAt = T1) {
  return {
    zcap: zcap({ id, controller: APP, collection: 'audience', expires }),
    grantKind: 'grant',
    grantedAt: grantedAt.toISOString()
  }
}

function agentEntry(overrides: Record<string, unknown> = {}) {
  return {
    version: 1,
    kind: 'agent',
    id: APP,
    firstSeen: T1.toISOString(),
    lastSeen: T1.toISOString(),
    grants: [],
    grantsReceived: [],
    outbox: [],
    writers: [],
    ...overrides
  }
}

function grantMessage(zcaps: object[]) {
  return { type: 'Grant', actor: PAIRWISE, object: { zcaps } }
}

async function seededAgent(overrides: Record<string, unknown> = {}) {
  const fixture = memoryConnectionsStore()
  const resourceId = await idOf(APP)
  fixture.seed(resourceId, agentEntry(overrides))
  const bodyOf = () =>
    fixture.rows.get(resourceId)?.body as Record<string, unknown>
  return { ...fixture, resourceId, bodyOf }
}

describe('recordGrants and the pairwise seed', () => {
  it('writes a seed and its tag, leaves an equal seed, and refuses a different one', async () => {
    const { store, rows, writes } = memoryConnectionsStore()
    const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    const options = {
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'agent' as const,
      grants: [grant('urn:zcap:1')]
    }
    const { resourceId } = await recordGrants({
      ...options,
      seed: SEED,
      seedTag,
      now: T1
    })
    expect(rows.get(resourceId)?.body).toMatchObject({ seed: SEED, seedTag })

    expect(
      (await recordGrants({ ...options, seed: SEED, seedTag, now: T2 })).outcome
    ).toBe('updated')
    expect(rows.get(resourceId)?.body).toMatchObject({
      seed: SEED,
      seedTag,
      lastSeen: T2.toISOString()
    })

    const otherTag = await connectionSeedTag({
      hmacKey: HMAC_KEY,
      seed: OTHER_SEED
    })
    const before = rows.get(resourceId)
    const count = writes.length
    await expect(
      recordGrants({ ...options, seed: OTHER_SEED, seedTag: otherTag, now: T3 })
    ).rejects.toThrow(/different pairwise seed/)
    expect(writes).toHaveLength(count)
    expect(rows.get(resourceId)).toEqual(before)
  })

  it('writes the seed onto an entry that has none', async () => {
    const { store, bodyOf } = await seededAgent()
    const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'agent',
      grants: [],
      seed: SEED,
      seedTag,
      now: T2
    })
    expect(bodyOf()).toMatchObject({ seed: SEED, seedTag })
  })

  it('refuses a seed with a bad tag or without one, before anything is read', async () => {
    const { store, writes } = memoryConnectionsStore()
    const otherTag = await connectionSeedTag({
      hmacKey: HMAC_KEY,
      seed: OTHER_SEED
    })
    const options = {
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'agent' as const,
      grants: []
    }
    await expect(
      recordGrants({ ...options, seed: SEED, seedTag: otherTag })
    ).rejects.toThrow(TypeError)
    await expect(recordGrants({ ...options, seed: SEED })).rejects.toThrow(
      TypeError
    )
    await expect(
      recordGrants({ ...options, seed: 'short', seedTag: otherTag })
    ).rejects.toThrow(TypeError)
    expect(writes).toEqual([])
  })

  it('clears declined on a fresh consent', async () => {
    const { store, bodyOf } = await seededAgent({
      declined: T1.toISOString()
    })
    await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'agent',
      grants: [grant('urn:zcap:1')],
      now: T2
    })
    expect(bodyOf()).not.toHaveProperty('declined')
  })

  it('stamps every grant of one call with the same grantedAt', async () => {
    const { store, rows } = memoryConnectionsStore()
    const { resourceId } = await recordGrants({
      store,
      hmacKey: HMAC_KEY,
      spaceUrl: SPACE_URL,
      did: APP,
      kind: 'agent',
      grants: [grant('urn:zcap:1'), grant('urn:zcap:2'), grant('urn:zcap:3')]
    })
    const { grants } = rows.get(resourceId)?.body as {
      grants: Array<{ grantedAt: string }>
    }
    expect(grants).toHaveLength(3)
    expect(new Set(grants.map(record => record.grantedAt)).size).toBe(1)
  })
})

describe('retireConnection and the agent-connection members', () => {
  it('empties grantsReceived and outbox, and keeps seed, seedTag, and declined', async () => {
    const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    const { store, bodyOf } = await seededAgent({
      seed: SEED,
      seedTag,
      declined: T1.toISOString(),
      grantsReceived: [receivedRecord('urn:zcap:inbox')],
      outbox: [{ message: grantMessage([]), createdAt: T1.toISOString() }]
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
    expect(bodyOf()).toMatchObject({
      seed: SEED,
      seedTag,
      declined: T1.toISOString(),
      retired: T2.toISOString(),
      grantsReceived: [],
      outbox: []
    })
  })

  it('writes a retired entry when only grantsReceived or only outbox is non-empty', async () => {
    for (const overrides of [
      { grantsReceived: [receivedRecord('urn:zcap:inbox')] },
      {
        outbox: [{ message: grantMessage([]), createdAt: T1.toISOString() }]
      }
    ]) {
      const { store, bodyOf } = await seededAgent({
        retired: T1.toISOString(),
        ...overrides
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
      expect(bodyOf()).toMatchObject({
        retired: T1.toISOString(),
        grantsReceived: [],
        outbox: []
      })
    }
  })

  it('keeps the new members through a helper that does not own them', async () => {
    const seedTag = await connectionSeedTag({ hmacKey: HMAC_KEY, seed: SEED })
    const members = {
      seed: SEED,
      seedTag,
      declined: T1.toISOString(),
      grantsReceived: [receivedRecord('urn:zcap:inbox')],
      outbox: [{ message: grantMessage([]), createdAt: T1.toISOString() }]
    }
    const { store, bodyOf } = await seededAgent(members)
    await setConnectionLabel({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      kind: 'agent',
      label: 'Feeds'
    })
    expect(bodyOf()).toMatchObject({ ...members, label: 'Feeds' })
  })
})

describe('recordReceivedGrants', () => {
  function receive(
    store: ConnectionsStore,
    zcaps: object[],
    now = T2,
    grantKind: 'inbox' = 'inbox'
  ) {
    return recordReceivedGrants({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      pairwiseDid: PAIRWISE,
      spaceUrl: SPACE_URL,
      grants: zcaps.map(value => ({ zcap: value, grantKind })),
      channelMaxLifetimeMs: 30 * DAY_MS,
      now
    })
  }

  it('replaces a lapsed held channel with a record of an earlier expires', async () => {
    const held = inboxZcap('urn:zcap:r1', '2099-01-01T00:00:00.000Z')
    const { store, bodyOf } = await seededAgent({
      grantsReceived: [
        { zcap: held, grantKind: 'inbox', receivedAt: T1.toISOString() }
      ]
    })
    const fresh = inboxZcap('urn:zcap:r2', '2026-12-01T00:00:00.000Z')
    const now = new Date(T1.getTime() + 31 * DAY_MS)
    expect((await receive(store, [fresh], now)).outcome).toBe('updated')
    expect(bodyOf().grantsReceived).toEqual([
      { zcap: fresh, grantKind: 'inbox', receivedAt: now.toISOString() }
    ])
  })

  it('refuses an expires outside strict ISO 8601, and an absent one', async () => {
    const { store, writes } = await seededAgent()
    for (const expires of [
      'January 1, 2027',
      '2027-01-01',
      '2027-01-01T00:00:00Z ',
      undefined
    ]) {
      await expect(
        receive(store, [{ ...inboxZcap('urn:zcap:r1'), expires }])
      ).rejects.toThrow(TypeError)
    }
    expect(writes).toEqual([])
  })

  it('admits an expires with any number of fractional second digits', async () => {
    const { store } = await seededAgent()
    const fresh = {
      ...inboxZcap('urn:zcap:r1'),
      expires: '2027-01-01T00:00:00.123456Z'
    }
    expect((await receive(store, [fresh])).outcome).toBe('updated')
  })

  it('keeps the later of two records for one target, and no-ops on a held id or an equal or earlier expires', async () => {
    const { store, bodyOf, writes } = await seededAgent()
    const first = inboxZcap('urn:zcap:r1', '2027-01-01T00:00:00.000Z')
    expect((await receive(store, [first])).outcome).toBe('updated')
    expect(bodyOf().grantsReceived).toEqual([
      { zcap: first, grantKind: 'inbox', receivedAt: T2.toISOString() }
    ])

    const later = inboxZcap('urn:zcap:r2', '2027-06-01T00:00:00.000Z')
    expect((await receive(store, [later], T3)).outcome).toBe('updated')
    expect(bodyOf().grantsReceived).toEqual([
      { zcap: later, grantKind: 'inbox', receivedAt: T3.toISOString() }
    ])

    const count = writes.length
    for (const value of [
      later,
      inboxZcap('urn:zcap:r3', '2027-06-01T00:00:00.000Z'),
      inboxZcap('urn:zcap:r4', '2027-02-01T00:00:00.000Z')
    ]) {
      expect((await receive(store, [value], T4)).outcome).toBe('unchanged')
    }
    expect(writes).toHaveLength(count)
  })

  it('drops a record past expires by more than the clock skew', async () => {
    const lapsed = new Date(T2.getTime() - SKEW_MS).toISOString()
    const inSkew = new Date(T2.getTime() - SKEW_MS + 1).toISOString()
    const { store, bodyOf } = await seededAgent({
      grantsReceived: [
        {
          zcap: zcap({
            id: 'urn:zcap:old',
            controller: PAIRWISE,
            target: 'https://old.example/inbox/',
            allowedAction: ['POST'],
            expires: lapsed
          }),
          grantKind: 'inbox',
          receivedAt: T1.toISOString()
        },
        {
          zcap: zcap({
            id: 'urn:zcap:band',
            controller: PAIRWISE,
            target: 'https://band.example/inbox/',
            allowedAction: ['POST'],
            expires: inSkew
          }),
          grantKind: 'inbox',
          receivedAt: T1.toISOString()
        }
      ]
    })
    await receive(store, [inboxZcap('urn:zcap:new')])
    expect(
      (bodyOf().grantsReceived as Array<{ zcap: { id: string } }>).map(
        record => record.zcap.id
      )
    ).toEqual(['urn:zcap:band', 'urn:zcap:new'])
  })

  it('refuses a retired entry, and writes nothing for an absent one', async () => {
    const { store, writes } = await seededAgent({ retired: T1.toISOString() })
    await expect(receive(store, [inboxZcap('urn:zcap:r1')])).rejects.toThrow(
      /retired/
    )
    expect(writes).toEqual([])
    const empty = memoryConnectionsStore()
    expect(
      (await receive(empty.store, [inboxZcap('urn:zcap:r1')])).outcome
    ).toBe('absent')
  })

  it('refuses a record controlled by another DID, targeting this Space, or an inbox without POST', async () => {
    const { store, writes } = await seededAgent()
    for (const value of [
      zcap({
        id: 'urn:zcap:x',
        controller: APP,
        target: AGENT_INBOX,
        allowedAction: ['POST']
      }),
      zcap({
        id: 'urn:zcap:x',
        controller: PAIRWISE,
        target: `${SPACE_URL}inbox/`,
        allowedAction: ['POST']
      }),
      zcap({
        id: 'urn:zcap:x',
        controller: PAIRWISE,
        target: AGENT_INBOX,
        allowedAction: ['GET']
      }),
      { id: 'urn:zcap:x' }
    ]) {
      await expect(receive(store, [value])).rejects.toThrow(TypeError)
    }
    await expect(
      receive(store, [inboxZcap('urn:zcap:x')], T2, 'outbox' as 'inbox')
    ).rejects.toThrow(TypeError)
    expect(writes).toEqual([])
  })
})

describe('recordRenewedGrants', () => {
  const AUDIENCE_EXPIRES = '2026-10-10T00:00:00.000Z'
  const INBOX_EXPIRES = '2026-10-11T00:00:00.000Z'

  function inboxGrantRecord(id: string, expires: string, grantedAt = T1) {
    return {
      zcap: zcap({
        id,
        controller: APP,
        collection: 'inbox',
        allowedAction: ['POST'],
        expires
      }),
      grantKind: 'grant',
      grantedAt: grantedAt.toISOString()
    }
  }

  function audienceZcap(id: string, expires: string) {
    return zcap({ id, controller: APP, collection: 'audience', expires })
  }

  function inboxGrantZcap(id: string, expires: string) {
    return zcap({
      id,
      controller: APP,
      collection: 'inbox',
      allowedAction: ['POST'],
      expires
    })
  }

  async function connectedAgent(overrides: Record<string, unknown> = {}) {
    return seededAgent({
      grants: [
        grantRecord('urn:zcap:audience', AUDIENCE_EXPIRES),
        inboxGrantRecord('urn:zcap:inbox', INBOX_EXPIRES)
      ],
      grantsReceived: [receivedRecord('urn:zcap:channel')],
      ...overrides
    })
  }

  function renew(
    store: ConnectionsStore,
    renewals: Array<{ zcap: object; sourceZcapId: string }>,
    now: Date,
    channelMaxLifetimeMs = 30 * DAY_MS,
    message: Record<string, unknown> = grantMessage(
      renewals.map(renewal => renewal.zcap)
    )
  ) {
    return recordRenewedGrants({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      pairwiseDid: PAIRWISE,
      spaceUrl: SPACE_URL,
      renewals,
      message,
      channelMaxLifetimeMs,
      now
    })
  }

  it('refuses a renewal that does not expire strictly later than its source', async () => {
    const { store, rows, resourceId, writes } = await connectedAgent()
    const before = rows.get(resourceId)
    await expect(
      renew(
        store,
        [
          {
            zcap: audienceZcap('urn:zcap:a2', AUDIENCE_EXPIRES),
            sourceZcapId: 'urn:zcap:audience'
          }
        ],
        T2
      )
    ).rejects.toThrow(/strictly later/)
    expect(writes).toEqual([])
    expect(rows.get(resourceId)).toEqual(before)
  })

  it('refuses a message whose zcaps are not exactly the renewed ones', async () => {
    const { store, writes } = await connectedAgent()
    const renewed = audienceZcap('urn:zcap:a2', '2026-11-10T00:00:00.000Z')
    const stray = audienceZcap('urn:zcap:stray', '2026-11-10T00:00:00.000Z')
    const renewals = [{ zcap: renewed, sourceZcapId: 'urn:zcap:audience' }]
    for (const zcaps of [[stray], [renewed, stray]]) {
      await expect(
        renew(store, renewals, T2, 30 * DAY_MS, grantMessage(zcaps))
      ).rejects.toThrow(TypeError)
    }
    expect(writes).toEqual([])
  })

  it('does not count a channel controlled by another DID than the pairwise one', async () => {
    const { store, writes } = await connectedAgent({
      grantsReceived: [
        {
          zcap: zcap({
            id: 'urn:zcap:channel',
            controller: CLIENT,
            target: AGENT_INBOX,
            allowedAction: ['POST']
          }),
          grantKind: 'inbox',
          receivedAt: T1.toISOString()
        }
      ]
    })
    await expect(
      renew(
        store,
        [
          {
            zcap: audienceZcap('urn:zcap:a2', '2026-11-10T00:00:00.000Z'),
            sourceZcapId: 'urn:zcap:audience'
          }
        ],
        T2
      )
    ).rejects.toThrow(/no live inbox/)
    expect(writes).toEqual([])
  })

  it('writes the renewed records and the pending envelope in one write', async () => {
    const { store, bodyOf, writes } = await connectedAgent()
    const renewed = audienceZcap(
      'urn:zcap:audience-2',
      '2026-11-10T00:00:00.000Z'
    )
    const result = await renew(
      store,
      [{ zcap: renewed, sourceZcapId: 'urn:zcap:audience' }],
      T2
    )
    expect(result.outcome).toBe('updated')
    expect(writes).toHaveLength(1)
    expect(bodyOf().grants).toEqual([
      grantRecord('urn:zcap:audience', AUDIENCE_EXPIRES),
      inboxGrantRecord('urn:zcap:inbox', INBOX_EXPIRES),
      {
        zcap: renewed,
        grantKind: 'grant',
        grantedAt: T1.toISOString(),
        renewedAt: T2.toISOString()
      }
    ])
    expect(bodyOf().outbox).toEqual([
      { message: grantMessage([renewed]), createdAt: T2.toISOString() }
    ])
  })

  it('replaces the pending envelope of a renewed scope, and drops an envelope left empty', async () => {
    const { store, bodyOf } = await connectedAgent()
    const audience2 = audienceZcap('urn:zcap:a2', '2026-11-10T00:00:00.000Z')
    const inbox2 = inboxGrantZcap('urn:zcap:i2', '2026-11-11T00:00:00.000Z')
    await renew(
      store,
      [
        { zcap: audience2, sourceZcapId: 'urn:zcap:audience' },
        { zcap: inbox2, sourceZcapId: 'urn:zcap:inbox' }
      ],
      T2
    )
    const audience3 = audienceZcap('urn:zcap:a3', '2026-12-10T00:00:00.000Z')
    await renew(store, [{ zcap: audience3, sourceZcapId: 'urn:zcap:a2' }], T3)
    expect(bodyOf().outbox).toEqual([
      { message: grantMessage([inbox2]), createdAt: T2.toISOString() },
      { message: grantMessage([audience3]), createdAt: T3.toISOString() }
    ])
    const inbox3 = inboxGrantZcap('urn:zcap:i3', '2026-12-11T00:00:00.000Z')
    await renew(store, [{ zcap: inbox3, sourceZcapId: 'urn:zcap:i2' }], T4)
    expect(bodyOf().outbox).toEqual([
      { message: grantMessage([audience3]), createdAt: T3.toISOString() },
      { message: grantMessage([inbox3]), createdAt: T4.toISOString() }
    ])
  })

  it('refuses a retired entry and leaves retired in place', async () => {
    const { store, rows, resourceId, writes } = await connectedAgent({
      retired: T1.toISOString()
    })
    const before = rows.get(resourceId)
    await expect(
      renew(
        store,
        [
          {
            zcap: audienceZcap('urn:zcap:a2', '2026-11-10T00:00:00.000Z'),
            sourceZcapId: 'urn:zcap:audience'
          }
        ],
        T2
      )
    ).rejects.toThrow(/retired/)
    expect(writes).toEqual([])
    expect(rows.get(resourceId)).toEqual(before)
  })

  it('refuses when the source is gone or no longer the latest of its scope', async () => {
    const { store, writes } = await connectedAgent()
    await expect(
      renew(
        store,
        [
          {
            zcap: audienceZcap('urn:zcap:a2', '2026-11-10T00:00:00.000Z'),
            sourceZcapId: 'urn:zcap:gone'
          }
        ],
        T2
      )
    ).rejects.toThrow(/no longer on/)
    await renew(
      store,
      [
        {
          zcap: audienceZcap('urn:zcap:a2', '2026-11-10T00:00:00.000Z'),
          sourceZcapId: 'urn:zcap:audience'
        }
      ],
      T2
    )
    const count = writes.length
    await expect(
      renew(
        store,
        [
          {
            zcap: audienceZcap('urn:zcap:a3', '2026-11-11T00:00:00.000Z'),
            sourceZcapId: 'urn:zcap:audience'
          }
        ],
        T3
      )
    ).rejects.toThrow(/no longer the latest/)
    expect(writes).toHaveLength(count)
  })

  it('refuses when no live inbox record stands', async () => {
    const renewal = {
      zcap: audienceZcap('urn:zcap:a2', '2026-11-10T00:00:00.000Z'),
      sourceZcapId: 'urn:zcap:audience'
    }
    const none = await connectedAgent({ grantsReceived: [] })
    await expect(renew(none.store, [renewal], T2)).rejects.toThrow(
      /no live inbox/
    )
    // Lapsed by its maximum lifetime, though its expires is far off.
    const lapsed = await connectedAgent()
    await expect(
      renew(lapsed.store, [renewal], T2, T2.getTime() - T1.getTime())
    ).rejects.toThrow(/no live inbox/)
    expect([...none.writes, ...lapsed.writes]).toEqual([])
  })

  it('refuses a renewed zcap of another scope or party, and a message with no zcaps', async () => {
    const { store, writes } = await connectedAgent()
    await expect(
      renew(
        store,
        [
          {
            zcap: inboxGrantZcap('urn:zcap:i2', '2026-11-11T00:00:00.000Z'),
            sourceZcapId: 'urn:zcap:audience'
          }
        ],
        T2
      )
    ).rejects.toThrow(TypeError)
    await expect(
      renew(
        store,
        [
          {
            zcap: zcap({ id: 'urn:zcap:a2', controller: OTHER }),
            sourceZcapId: 'urn:zcap:audience'
          }
        ],
        T2
      )
    ).rejects.toThrow(TypeError)
    await expect(
      recordRenewedGrants({
        store,
        hmacKey: HMAC_KEY,
        did: APP,
        pairwiseDid: PAIRWISE,
        spaceUrl: SPACE_URL,
        renewals: [
          {
            zcap: audienceZcap('urn:zcap:a2', '2026-11-10T00:00:00.000Z'),
            sourceZcapId: 'urn:zcap:audience'
          }
        ],
        message: grantMessage([]),
        channelMaxLifetimeMs: 30 * DAY_MS,
        now: T2
      })
    ).rejects.toThrow(TypeError)
    expect(writes).toEqual([])
  })
})

describe('settleOutboxItem', () => {
  it('removes the item queued at createdAt', async () => {
    const kept = { message: grantMessage([]), createdAt: T2.toISOString() }
    const { store, bodyOf, writes } = await seededAgent({
      outbox: [{ message: grantMessage([]), createdAt: T1.toISOString() }, kept]
    })
    const options = {
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      createdAt: T1.toISOString()
    }
    expect((await settleOutboxItem(options)).outcome).toBe('updated')
    expect(bodyOf().outbox).toEqual([kept])
    expect((await settleOutboxItem(options)).outcome).toBe('unchanged')
    expect(writes).toHaveLength(1)
    expect((await settleOutboxItem({ ...options, did: OTHER })).outcome).toBe(
      'absent'
    )
  })
})

describe('pruneSupersededGrants', () => {
  const EXPIRES = '2026-10-10T00:00:00.000Z'
  const expiresAt = Date.parse(EXPIRES)

  it('drops a superseded record past expires plus the skew, and keeps the latest', async () => {
    const superseded = grantRecord('urn:zcap:a1', EXPIRES)
    const latest = grantRecord('urn:zcap:a2', '2026-11-10T00:00:00.000Z')
    const single = grantRecord('urn:zcap:solo', '2026-01-01T00:00:00.000Z')
    single.zcap.invocationTarget = `${SPACE_URL}other/`
    const { store, bodyOf } = await seededAgent({
      grants: [superseded, latest, single]
    })
    const options = { store, hmacKey: HMAC_KEY, did: APP }
    expect(
      (
        await pruneSupersededGrants({
          ...options,
          now: new Date(expiresAt + SKEW_MS - 1)
        })
      ).outcome
    ).toBe('unchanged')
    expect(
      (
        await pruneSupersededGrants({
          ...options,
          now: new Date(expiresAt + SKEW_MS)
        })
      ).outcome
    ).toBe('updated')
    expect(bodyOf().grants).toEqual([latest, single])
  })

  it('drops a dead-chain id unless it is the latest of its scope', async () => {
    const superseded = grantRecord('urn:zcap:a1', EXPIRES)
    const latest = grantRecord('urn:zcap:a2', '2026-11-10T00:00:00.000Z')
    const { store, bodyOf } = await seededAgent({
      grants: [superseded, latest]
    })
    await pruneSupersededGrants({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      deadChainZcapIds: ['urn:zcap:a1', 'urn:zcap:a2'],
      now: T1
    })
    expect(bodyOf().grants).toEqual([latest])
  })

  it('discards an outbox item whose every zcap is expired, and keeps one with a live zcap', async () => {
    const unexpired = zcap({
      id: 'urn:zcap:u',
      controller: APP,
      expires: '2099-01-01T00:00:00.000Z'
    })
    const expired = zcap({
      id: 'urn:zcap:e',
      controller: APP,
      expires: EXPIRES
    })
    const live = {
      message: grantMessage([expired, unexpired]),
      createdAt: T2.toISOString()
    }
    const { store, bodyOf } = await seededAgent({
      outbox: [
        { message: grantMessage([expired]), createdAt: T1.toISOString() },
        live
      ]
    })
    await pruneSupersededGrants({
      store,
      hmacKey: HMAC_KEY,
      did: APP,
      now: new Date(expiresAt + SKEW_MS)
    })
    expect(bodyOf().outbox).toEqual([live])
  })
})

describe('clearReceivedGrants and markDeclined', () => {
  it('empties grantsReceived and outbox, and no-ops on a re-run', async () => {
    const { store, bodyOf, writes } = await seededAgent({
      grantsReceived: [receivedRecord('urn:zcap:inbox')],
      outbox: [{ message: grantMessage([]), createdAt: T1.toISOString() }]
    })
    const options = { store, hmacKey: HMAC_KEY, did: APP }
    expect((await clearReceivedGrants(options)).outcome).toBe('updated')
    expect(bodyOf()).toMatchObject({ grantsReceived: [], outbox: [] })
    expect((await clearReceivedGrants(options)).outcome).toBe('unchanged')
    expect(writes).toHaveLength(1)
    expect(
      (await clearReceivedGrants({ ...options, did: OTHER })).outcome
    ).toBe('absent')
  })

  it('sets declined once', async () => {
    const { store, bodyOf, writes } = await seededAgent()
    const options = { store, hmacKey: HMAC_KEY, did: APP }
    expect((await markDeclined({ ...options, now: T1 })).outcome).toBe(
      'updated'
    )
    expect((await markDeclined({ ...options, now: T2 })).outcome).toBe(
      'unchanged'
    )
    expect(bodyOf().declined).toBe(T1.toISOString())
    expect(writes).toHaveLength(1)
    expect((await markDeclined({ ...options, did: OTHER })).outcome).toBe(
      'absent'
    )
  })
})
