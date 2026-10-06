/**
 * Unit tests for the `connections` entry codec (`src/connections/entry.ts`),
 * the shared display-name rule (`src/labelText.ts`), the two-arm resource id
 * (`src/connections/resourceId.ts`), and the listing read's id binding
 * (`src/connections/read.ts`).
 */
import { describe, expect, it } from 'vitest'
import { SHA256HMACKey } from '@interop/data-integrity-core'
import {
  CONNECTION_WRITER_POLICY,
  connectionKindOf,
  connectionResourceId,
  grantKindOf,
  isWritableConnectionEntry,
  normalizeDisplayName,
  parseConnectionEntry,
  readConnections
} from '../../src/connections/index.js'
import {
  HMAC_KEY,
  OTHER_HMAC_KEY,
  PAIRWISE,
  SEED,
  memoryConnectionsStore,
  namedError,
  zcap
} from './fixtures/memoryConnections.js'

const DAY_MS = 24 * 60 * 60 * 1000
const APP = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
const STAMP = '2026-10-01T00:00:00.000Z'
// 32 bytes of 0x09 as base64url with no padding.
const TAG = 'CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk'
// Bidi controls, built from code points so no literal one sits in source.
const RLO = String.fromCodePoint(0x202e)
const LRI = String.fromCodePoint(0x2066)

function entry(overrides: Record<string, unknown> = {}) {
  return {
    version: 1,
    kind: 'app',
    id: APP,
    name: 'Example App',
    origin: 'https://app.example',
    url: 'https://app.example/',
    appKey: 'zAppKey',
    firstSeen: STAMP,
    lastSeen: STAMP,
    grants: [
      {
        zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
        grantKind: 'grant',
        grantedAt: STAMP
      }
    ],
    writers: [],
    ...overrides
  }
}

describe('normalizeDisplayName', () => {
  it('bounds a name at 1 to 64 code points after stripping and trimming', () => {
    expect(normalizeDisplayName({ value: '' })).toBeUndefined()
    expect(normalizeDisplayName({ value: '   ' })).toBeUndefined()
    expect(normalizeDisplayName({ value: 'a' })).toBe('a')
    expect(normalizeDisplayName({ value: 'a'.repeat(64) })).toBe('a'.repeat(64))
    expect(normalizeDisplayName({ value: 'a'.repeat(65) })).toBeUndefined()
    // Code points, not UTF-16 units: 64 emoji fit.
    expect(normalizeDisplayName({ value: '\u{1F600}'.repeat(64) })).toBe(
      '\u{1F600}'.repeat(64)
    )
  })

  it('strips control and bidi characters before measuring', () => {
    expect(
      normalizeDisplayName({ value: ` ${'a'.repeat(64)}\u0007${RLO} ` })
    ).toBe('a'.repeat(64))
    expect(normalizeDisplayName({ value: `\u0000${LRI}` })).toBeUndefined()
  })
})

describe('parseConnectionEntry', () => {
  it('reads every known member', () => {
    const parsed = parseConnectionEntry({
      ...entry({ label: 'Mine', retired: STAMP }),
      writers: [
        { writerId: 'w1', label: 'Chrome', lastSeen: STAMP, active: true }
      ]
    })
    expect(parsed).toMatchObject({
      version: 1,
      kind: 'app',
      id: APP,
      name: 'Example App',
      label: 'Mine',
      origin: 'https://app.example',
      url: 'https://app.example/',
      appKey: 'zAppKey',
      firstSeen: STAMP,
      lastSeen: STAMP,
      retired: STAMP
    })
    expect(parsed?.grants).toHaveLength(1)
    expect(parsed?.writers).toHaveLength(1)
  })

  it('checks every known member shape', () => {
    const malformed: unknown[] = [
      null,
      'text',
      [],
      entry({ version: 0 }),
      entry({ version: 1.5 }),
      entry({ version: '1' }),
      entry({ kind: '' }),
      entry({ kind: 3 }),
      entry({ id: 'not-a-did' }),
      entry({ id: 7 }),
      entry({ label: 7 }),
      entry({ origin: 7 }),
      entry({ url: 7 }),
      entry({ appKey: '' }),
      entry({ firstSeen: 'yesterday' }),
      entry({ lastSeen: undefined }),
      entry({ retired: 'never' }),
      entry({ grants: {} }),
      entry({ writers: undefined }),
      entry({
        grants: [{ zcap: { id: 'x' }, grantKind: 'grant', grantedAt: STAMP }]
      }),
      entry({
        grants: [
          {
            zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
            grantedAt: STAMP
          }
        ]
      }),
      entry({
        grants: [
          {
            zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
            grantKind: 'grant',
            grantedAt: 'soon'
          }
        ]
      }),
      entry({
        grants: [
          {
            zcap: {
              ...zcap({ id: 'urn:zcap:1', controller: APP }),
              expires: 'x'
            },
            grantKind: 'grant',
            grantedAt: STAMP
          }
        ]
      }),
      entry({
        grants: [
          {
            zcap: {
              ...zcap({ id: 'urn:zcap:1', controller: APP }),
              expires: undefined
            },
            grantKind: 'grant',
            grantedAt: STAMP
          }
        ]
      }),
      entry({
        writers: [{ writerId: '', label: 'x', lastSeen: STAMP, active: true }]
      }),
      entry({
        writers: [{ writerId: 'w', label: 'x', lastSeen: STAMP, active: 'yes' }]
      }),
      // No `id` beside anything but exactly one writer.
      entry({ id: undefined, writers: [] })
    ]
    for (const body of malformed) {
      expect(parseConnectionEntry(body)).toBeUndefined()
    }
  })

  it('bounds name by the display-name rule at 0, 1, 64, and 65 characters', () => {
    expect(parseConnectionEntry(entry({ name: '' }))).toBeUndefined()
    expect(parseConnectionEntry(entry({ name: 'a' }))?.name).toBe('a')
    expect(parseConnectionEntry(entry({ name: 'a'.repeat(64) }))?.name).toBe(
      'a'.repeat(64)
    )
    expect(
      parseConnectionEntry(entry({ name: 'a'.repeat(65) }))
    ).toBeUndefined()
    // A control character is stripped before measuring, and from the name read.
    expect(
      parseConnectionEntry(entry({ name: `${'a'.repeat(64)}\u0007` }))?.name
    ).toBe('a'.repeat(64))
    expect(parseConnectionEntry(entry({ name: '\u0007' }))).toBeUndefined()
    // `name` is optional.
    expect(
      parseConnectionEntry(entry({ name: undefined }))?.name
    ).toBeUndefined()
  })

  it('holds label and a writer label to the same rule', () => {
    expect(parseConnectionEntry(entry({ label: '' }))).toBeUndefined()
    expect(
      parseConnectionEntry(entry({ label: 'a'.repeat(65) }))
    ).toBeUndefined()
    expect(parseConnectionEntry(entry({ label: RLO }))).toBeUndefined()
    // The bidi control is stripped from the label read.
    expect(parseConnectionEntry(entry({ label: `Mine${RLO}` }))?.label).toBe(
      'Mine'
    )
    const member = { writerId: 'w1', lastSeen: STAMP, active: true }
    expect(
      parseConnectionEntry(
        entry({ writers: [{ ...member, label: 'a'.repeat(65) }] })
      )
    ).toBeUndefined()
    expect(
      parseConnectionEntry(entry({ writers: [{ ...member, label: LRI }] }))
    ).toBeUndefined()
    expect(
      parseConnectionEntry(
        entry({ writers: [{ ...member, label: `Chrome${LRI}`, extra: 1 }] })
      )?.writers[0]
    ).toEqual({ ...member, label: 'Chrome', extra: 1 })
  })

  it('accepts an unknown kind as an unclassified party', () => {
    const parsed = parseConnectionEntry(entry({ kind: 'robot' }))
    expect(parsed?.kind).toBe('robot')
    expect(connectionKindOf(parsed!)).toBeUndefined()
    for (const kind of ['app', 'agent', 'wallet-client', 'contact']) {
      expect(connectionKindOf(parseConnectionEntry(entry({ kind }))!)).toBe(
        kind
      )
    }
  })

  it('reads an unknown grantKind as a plain grant', () => {
    const parsed = parseConnectionEntry(
      entry({
        grants: [
          {
            zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
            grantKind: 'lease',
            grantedAt: STAMP
          },
          {
            zcap: zcap({ id: 'urn:zcap:2', controller: APP }),
            grantKind: 'share',
            grantedAt: STAMP
          }
        ]
      })
    )
    expect(parsed?.grants.map(grantKindOf)).toEqual(['grant', 'share'])
  })

  it('ignores unknown members and keeps a grant wrapper verbatim', () => {
    const wrapper = {
      zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
      grantKind: 'grant',
      grantedAt: STAMP,
      note: { from: 'a later build' }
    }
    const parsed = parseConnectionEntry(
      entry({ extra: true, grants: [wrapper] })
    )
    expect(parsed).not.toHaveProperty('extra')
    expect(parsed?.grants[0]).toEqual(wrapper)
  })

  it('reads an absent grantsReceived and outbox as empty', () => {
    const parsed = parseConnectionEntry(entry())
    expect(parsed?.grantsReceived).toEqual([])
    expect(parsed?.outbox).toEqual([])
    expect(parsed).not.toHaveProperty('seed')
    expect(parsed).not.toHaveProperty('declined')
  })

  it('reads the agent members and keeps their wrappers verbatim', () => {
    const received = {
      zcap: zcap({
        id: 'urn:zcap:channel',
        controller: PAIRWISE,
        target: 'https://agent.example/space/AGENT/inbox/'
      }),
      grantKind: 'inbox',
      receivedAt: STAMP,
      note: 'kept'
    }
    const item = {
      message: { type: 'Grant', actor: PAIRWISE, object: { zcaps: [] } },
      createdAt: STAMP,
      note: 'kept'
    }
    const renewed = {
      zcap: zcap({ id: 'urn:zcap:2', controller: APP }),
      grantKind: 'grant',
      grantedAt: STAMP,
      renewedAt: '2026-10-02T00:00:00.000Z'
    }
    const parsed = parseConnectionEntry(
      entry({
        kind: 'agent',
        seed: SEED,
        seedTag: TAG,
        declined: STAMP,
        grants: [renewed],
        grantsReceived: [received],
        outbox: [item]
      })
    )
    expect(parsed).toMatchObject({
      kind: 'agent',
      seed: SEED,
      seedTag: TAG,
      declined: STAMP
    })
    expect(parsed?.grants[0]).toEqual(renewed)
    expect(parsed?.grantsReceived).toEqual([received])
    expect(parsed?.outbox).toEqual([item])
  })

  it('keeps an unknown received grantKind as stored', () => {
    const parsed = parseConnectionEntry(
      entry({
        seed: SEED,
        seedTag: TAG,
        grantsReceived: [
          {
            zcap: zcap({ id: 'urn:zcap:x', controller: PAIRWISE }),
            grantKind: 'later-kind',
            receivedAt: STAMP
          }
        ]
      })
    )
    expect(parsed?.grantsReceived[0]?.grantKind).toBe('later-kind')
  })

  it('refuses a malformed seed, tag, received grant, outbox item, or marker', () => {
    const bad: Array<Record<string, unknown>> = [
      // 42 and 44 characters, non-base64url, and another decoded length.
      { seed: SEED.slice(0, 42), seedTag: TAG },
      { seed: `${SEED}A`, seedTag: TAG },
      { seed: `${SEED.slice(0, 42)}+`, seedTag: TAG },
      { seed: 'AAAA', seedTag: TAG },
      // A seed with no tag, and a tag with no seed.
      { seed: SEED },
      { seedTag: TAG },
      { seed: SEED, seedTag: 'short' },
      { declined: 'not a time' },
      { grantsReceived: 'none' },
      { grantsReceived: [{ zcap: {}, grantKind: 'inbox', receivedAt: STAMP }] },
      {
        grantsReceived: [
          { zcap: zcap({ id: 'urn:zcap:x', controller: APP }), grantKind: 1 }
        ]
      },
      {
        grantsReceived: [
          {
            zcap: zcap({ id: 'urn:zcap:x', controller: APP }),
            grantKind: 'inbox',
            receivedAt: 'never'
          }
        ]
      },
      { outbox: {} },
      { outbox: [{ message: 'text', createdAt: STAMP }] },
      { outbox: [{ message: {}, createdAt: 'never' }] },
      { outbox: [{ message: {} }] },
      {
        grants: [
          {
            zcap: zcap({ id: 'urn:zcap:1', controller: APP }),
            grantKind: 'grant',
            grantedAt: STAMP,
            renewedAt: 'never'
          }
        ]
      }
    ]
    for (const overrides of bad) {
      expect(
        parseConnectionEntry(entry(overrides)),
        JSON.stringify(overrides)
      ).toBeUndefined()
    }
  })

  it('reads a newer version for display and marks it unwritable', () => {
    const parsed = parseConnectionEntry(entry({ version: 2, future: [1] }))
    expect(parsed?.version).toBe(2)
    expect(parsed?.name).toBe('Example App')
    expect(isWritableConnectionEntry(parsed!)).toBe(false)
    expect(isWritableConnectionEntry(parseConnectionEntry(entry())!)).toBe(true)
    // A newer body that fails a known member's shape is unparseable.
    expect(parseConnectionEntry(entry({ version: 2, name: 7 }))).toBeUndefined()
  })

  it('reads a keyless writer entry with exactly one writer', () => {
    const parsed = parseConnectionEntry(
      entry({
        id: undefined,
        kind: 'app',
        writers: [
          { writerId: 'w1', label: 'Tool', lastSeen: STAMP, active: true }
        ]
      })
    )
    expect(parsed?.id).toBeUndefined()
    expect(parsed?.writers[0]?.writerId).toBe('w1')
  })

  it('carries the signed-off writer policy', () => {
    expect(CONNECTION_WRITER_POLICY).toEqual({
      inactiveAfterMs: 90 * DAY_MS,
      maxWriters: 8,
      touchIntervalMs: DAY_MS
    })
  })
})

describe('connectionResourceId', () => {
  it('derives both arms to fixed vectors', async () => {
    expect(await connectionResourceId({ hmacKey: HMAC_KEY, did: APP })).toBe(
      'z1A5pSF4wBnX5ETnBWPicZhwR'
    )
    expect(
      await connectionResourceId({ hmacKey: HMAC_KEY, writerId: 'w-1' })
    ).toBe('z19xUWKtCXG3worwqZawByGWK')
  })

  it('gives the same DID two ids under two accounts', async () => {
    const mine = await connectionResourceId({ hmacKey: HMAC_KEY, did: APP })
    const theirs = await connectionResourceId({
      hmacKey: OTHER_HMAC_KEY,
      did: APP
    })
    expect(theirs).toBe('z1A2eopib8jK18rG1aX6BFKwM')
    expect(theirs).not.toBe(mine)
  })

  it('keeps a writerId beginning with did: apart from the party', async () => {
    const writer = await connectionResourceId({
      hmacKey: HMAC_KEY,
      writerId: APP
    })
    expect(writer).toBe('z1A4ugRmFezL52pMPXqYEiW9B')
    expect(writer).not.toBe(
      await connectionResourceId({ hmacKey: HMAC_KEY, did: APP })
    )
  })

  it('derives the same id from a resolved blinding key', async () => {
    const blindingKey = await SHA256HMACKey.fromSecret({
      id: 'urn:uuid:blinding',
      secret: HMAC_KEY
    })
    expect(await connectionResourceId({ hmacKey: blindingKey, did: APP })).toBe(
      'z1A5pSF4wBnX5ETnBWPicZhwR'
    )
  })

  it('takes exactly one arm', async () => {
    await expect(
      connectionResourceId({
        hmacKey: HMAC_KEY,
        did: APP,
        writerId: 'w'
      } as unknown as { hmacKey: Uint8Array; did: string })
    ).rejects.toThrow(TypeError)
  })
})

describe('readConnections', () => {
  it('ignores a body at the wrong id and reports what it could not read', async () => {
    const { store, rows, seed } = memoryConnectionsStore()
    const id = await connectionResourceId({ hmacKey: HMAC_KEY, did: APP })
    seed(id, entry())
    // The same body copied under another id labels nothing.
    seed('zMisplaced', entry())
    // A malformed body at its own id is reported as unparseable.
    const other = 'did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG'
    const otherId = await connectionResourceId({
      hmacKey: HMAC_KEY,
      did: other
    })
    seed(otherId, entry({ id: other, name: 7 }))
    // A body that would not open is reported as unreadable.
    rows.set('zSealedElsewhere', {
      readError: namedError('UnknownEpochError'),
      etag: 'x'
    })

    const listing = await readConnections({ store, hmacKey: HMAC_KEY })
    expect(listing?.entries.map(item => item.resourceId)).toEqual([id])
    expect(listing?.entries[0]?.entry.id).toBe(APP)
    expect(listing?.unparseable).toEqual([otherId])
    expect(listing?.unreadable).toEqual(['zSealedElsewhere'])
  })

  it('reads an absent collection as null, not as an empty directory', async () => {
    const { store, setMissing } = memoryConnectionsStore()
    setMissing(true)
    expect(await readConnections({ store, hmacKey: HMAC_KEY })).toBeNull()
  })
})
