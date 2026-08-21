/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Client-annex GC: the cadence predicates read off the account log (which entry
 * established the current `#DelegatedClients` pointer, whether the quarterly
 * swap is due, whether the pointed generation is GC-quiet), the swap's fixed
 * stage order (mint + genesis, install the fresh delegation, revoke the old
 * one, re-point -- revoke strictly before both the re-point and the delete),
 * and the predicate-driven collect fan-out over every non-pointed `gen-`
 * collection (digest before delete, per-generation failure isolation, the
 * 400 already-revoked answer read as success, and a second pass over the
 * post-swap state as a no-op). Plus the `GenerationCollect` digest builder's
 * wire shape.
 */
import { describe, expect, it } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { WasClient } from '@interop/was-client'
import { spaceItems, toUrl } from '@interop/was-client/paths'
import {
  clientAnnexLogStore,
  delegatedClientsPointer,
  embeddedGenerationDelegation,
  ensureGenerationDelegationCurrent,
  mintCredentialClientAnnexGeneration,
  mintGenerationDelegation,
  setDelegatedClientsPointer
} from '../../src/clientAnnex/log.js'
import {
  clientAnnexGcDue,
  delegatedClientsPointerEstablishedAt,
  GENERATION_GC_PERIOD_MS,
  GENERATION_QUIET_BOUND_MS,
  GENERATION_QUIET_GRACE_MS,
  generationQuiet,
  runClientAnnexGc,
  swapClientAnnexGeneration
} from '../../src/clientAnnex/gc.js'
import {
  ensureDidWebvh,
  enrollWebvhClient,
  readPublishedLog,
  updateKeyMultibase
} from '../../src/webvh/didWebvh.js'
import type {
  PublishedWebvhLog,
  WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { ladderVmZcapClient } from '../../src/clientAnnex/zcap.js'
import { ACTIVITY_TYPE } from '../../src/space/activity.js'
import { addHistoryGenerationCollected } from '../../src/space/activity.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'https://storage.example'
const ACCOUNT_SPACE_ID = 'account-space-1'
const AUX_SPACE_ID = 'aux-space-1'

/**
 * The quiet window the guard actually compares against (the bound plus the
 * skew-margin grace hour).
 */
const QUIET_WINDOW_MS = GENERATION_QUIET_BOUND_MS + GENERATION_QUIET_GRACE_MS

/**
 * A deterministic 32-byte seed, so two derivations agree across helpers.
 */
function fixedSeed(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

/**
 * The standing credential's ladder seed: it mints every generation in these
 * fixtures, so its annex rung is the one revealed at each genesis.
 */
const LADDER_SEED = fixedSeed(11)

/**
 * One resource row in the fake server, versioned so its integer version can
 * serve as the ETag.
 */
interface StoredResource {
  text: string
  version: number
}

/**
 * An in-memory WAS server behind a fake ezcap client, modeled on the one in
 * `webvh-client-annex.test.ts` and extended with exactly what annex GC
 * drives: Space Descriptions (`describe` / `configure`), the collections
 * listing, collection delete (idempotent, recorded), versioned resources with
 * `if-match` / `if-none-match`, and the Space revocation endpoint, which
 * records every submitted capability verbatim and answers a repeat
 * submission with the server's 400 (mapped to a `ValidationError`).
 *
 * Every interesting side effect also appends a label to the shared `events`
 * list, so a test can assert the ceremony's stage ORDER across the two fakes
 * (this server and the account log's in-memory id store).
 *
 * @param [options] {object}
 * @param [options.events] {string[]}   the shared ordered event log
 * @returns {object}
 */
function fakeServer({ events = [] }: { events?: string[] } = {}) {
  const spaces = new Map<string, { id: string; type?: string[] }>()
  const collections = new Map<string, Set<string>>()
  const resources = new Map<string, StoredResource>()
  const revoked = new Set<string>()
  const revocations: Array<{ capabilityId: string; body: unknown }> = []
  const calls: Array<{ method: string; url: string }> = []

  const collectionsOf = (spaceId: string): Set<string> => {
    const existing = collections.get(spaceId)
    if (existing !== undefined) {
      return existing
    }
    const fresh = new Set<string>()
    collections.set(spaceId, fresh)
    return fresh
  }

  const lowerHeaders = (headers?: Record<string, string>) =>
    Object.fromEntries(
      Object.entries(headers ?? {}).map(([key, value]) => [
        key.toLowerCase(),
        value
      ])
    )

  const jsonResponse = (data: unknown) =>
    ({
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      data,
      async json() {
        return data
      }
    }) as unknown as Response

  const okResponse = () =>
    ({
      status: 200,
      headers: new Headers(),
      data: undefined,
      async json() {
        return undefined
      }
    }) as unknown as Response

  const textResponse = (row: StoredResource) =>
    ({
      status: 200,
      headers: new Headers({
        'content-type': 'text/jsonl',
        etag: `"${row.version}"`
      }),
      async text() {
        return row.text
      },
      async blob() {
        return new Blob([row.text], { type: 'text/jsonl' })
      }
    }) as unknown as Response

  const zcapClient = {
    invocationSigner: { id: 'did:example:client#key-1' },
    async request({
      url,
      method,
      headers,
      json,
      body
    }: {
      url: string
      method?: string
      headers?: Record<string, string>
      json?: object
      body?: Uint8Array
      capability?: unknown
    }) {
      const verb = (method ?? 'GET').toUpperCase()
      const lowered = lowerHeaders(headers)
      calls.push({ method: verb, url })
      const path = new URL(url).pathname
      const segments = path.split('/').filter(Boolean)
      if (segments[0] !== 'space') {
        throw new Error(`Unrouted path "${path}".`)
      }
      const spaceId = decodeURIComponent(segments[1] ?? '')

      // /space/<spaceId>/zcaps/revocations/<capabilityId>
      if (segments[2] === 'zcaps' && segments[3] === 'revocations') {
        const capabilityId = decodeURIComponent(segments[4] ?? '')
        events.push(`revoke:${capabilityId}`)
        revocations.push({ capabilityId, body: json })
        if (revoked.has(capabilityId)) {
          throw {
            status: 400,
            data: { title: `Capability "${capabilityId}" is already revoked.` }
          }
        }
        revoked.add(capabilityId)
        return okResponse()
      }

      // /space/<spaceId>/collections/ -- the collections listing.
      if (
        segments.length === 3 &&
        segments[2] === 'collections' &&
        path.endsWith('/')
      ) {
        const items = [...collectionsOf(spaceId)].map(id => ({
          id,
          name: id,
          url: `${WAS_URL}/space/${spaceId}/${id}`
        }))
        return jsonResponse({ items, totalItems: items.length, url })
      }

      // /space/<spaceId> -- the Space Description.
      if (segments.length === 2) {
        if (verb === 'PUT') {
          spaces.set(spaceId, (json ?? {}) as { id: string; type?: string[] })
          return okResponse()
        }
        const description = spaces.get(spaceId)
        if (description === undefined) {
          throw { status: 404, response: { status: 404 } }
        }
        return jsonResponse(description)
      }

      // /space/<spaceId>/<collectionId> -- the Collection Description.
      if (segments.length === 3) {
        const collectionId = decodeURIComponent(segments[2] ?? '')
        if (verb === 'DELETE') {
          events.push(`delete:${collectionId}`)
          collectionsOf(spaceId).delete(collectionId)
          for (const key of [...resources.keys()]) {
            if (key.startsWith(`/space/${spaceId}/${collectionId}/`)) {
              resources.delete(key)
            }
          }
          return okResponse()
        }
        if (verb === 'PUT') {
          collectionsOf(spaceId).add(collectionId)
          return okResponse()
        }
        if (!collectionsOf(spaceId).has(collectionId)) {
          throw { status: 404, response: { status: 404 } }
        }
        return jsonResponse({ id: collectionId })
      }

      // /space/<spaceId>/<collectionId>/<resourceId> -- a resource.
      if (segments.length === 4) {
        const row = resources.get(path)
        if (verb === 'GET') {
          if (row === undefined) {
            throw { status: 404, response: { status: 404 } }
          }
          return textResponse(row)
        }
        if (verb === 'PUT') {
          if (lowered['if-none-match'] === '*' && row !== undefined) {
            throw { status: 412, response: { status: 412 } }
          }
          const ifMatch = lowered['if-match']
          if (
            ifMatch !== undefined &&
            ifMatch !== `"${row?.version ?? 'absent'}"`
          ) {
            throw { status: 412, response: { status: 412 } }
          }
          collectionsOf(spaceId).add(decodeURIComponent(segments[2] ?? ''))
          resources.set(path, {
            text: new TextDecoder().decode(body),
            version: (row?.version ?? 0) + 1
          })
          return okResponse()
        }
      }
      throw new Error(`Unrouted ${verb} "${path}".`)
    }
  } as unknown as ZcapClient

  return {
    calls,
    events,
    resources,
    revocations,
    revoked,
    was: new WasClient({ serverUrl: WAS_URL, zcapClient }),
    /**
     * The collection ids the Space currently holds.
     */
    collectionIds(spaceId: string): string[] {
      return [...collectionsOf(spaceId)]
    },
    /**
     * Creates an empty collection (an orphan whose log was never published).
     */
    createCollection({
      spaceId,
      collectionId
    }: {
      spaceId: string
      collectionId: string
    }): void {
      collectionsOf(spaceId).add(collectionId)
    },
    /**
     * The server's minimal model of chain verification: would an invocation
     * whose chain contains `delegation` verify? A revoked capability answers
     * no, permanently.
     */
    chainVerifies({ delegation }: { delegation: IZcap }): boolean {
      return !revoked.has(delegation.id)
    }
  }
}

/**
 * Wraps the account's in-memory id store so its log writes land in the same
 * ordered event list the fake server appends to.
 *
 * @param options {object}
 * @param options.store {WebvhIdStore}   the wrapped store
 * @param options.events {string[]}   the shared ordered event log
 * @returns {WebvhIdStore}
 */
function recordingIdStore({
  store,
  events
}: {
  store: ReturnType<typeof memoryIdStore>['idStore']
  events: string[]
}): ReturnType<typeof memoryIdStore>['idStore'] {
  return {
    ...store,
    async putIdResource(options) {
      events.push(`account-put:${options.resourceId}`)
      return store.putIdResource(options)
    }
  }
}

/**
 * A published generation in the fake server's auxiliary Space, with its
 * generation-delegation service entry installed (so it has delegation bytes
 * to revoke) and its verified log in hand.
 *
 * @param options {object}
 * @param options.server {ReturnType<typeof fakeServer>}
 * @param options.accountDid {string}
 * @param options.zcapClient {ZcapClient}   signs the generation delegation
 * @returns {Promise<object>}
 */
async function publishGeneration({
  server,
  accountDid,
  zcapClient
}: {
  server: ReturnType<typeof fakeServer>
  accountDid: string
  zcapClient: ZcapClient
}) {
  const minted = await mintCredentialClientAnnexGeneration({
    was: server.was,
    wasServerUrl: WAS_URL,
    spaceId: AUX_SPACE_ID,
    controller: accountDid,
    ladderSeed: LADDER_SEED
  })
  const store = clientAnnexLogStore({
    was: server.was,
    spaceId: AUX_SPACE_ID,
    generationId: minted.generationId
  })
  await ensureGenerationDelegationCurrent({
    store,
    ladderSeed: LADDER_SEED,
    generationId: minted.generationId,
    mintGenerationDelegation: async ({ clientAnnexDid }) =>
      mintGenerationDelegation({
        zcapClient,
        wasServerUrl: WAS_URL,
        spaceId: ACCOUNT_SPACE_ID,
        clientAnnexDid
      }),
    expectedDid: minted.did
  })
  const published = await readClientAnnexLog({
    server,
    generationId: minted.generationId
  })
  return {
    did: minted.did,
    generationId: minted.generationId,
    published,
    delegation: embeddedGenerationDelegation({ doc: published.doc })!
  }
}

/**
 * Reads and verifies one generation's published annex log out of the fake
 * server.
 *
 * @param options {object}
 * @param options.server {ReturnType<typeof fakeServer>}
 * @param options.generationId {string}
 * @returns {Promise<PublishedWebvhLog>}
 */
async function readClientAnnexLog({
  server,
  generationId
}: {
  server: ReturnType<typeof fakeServer>
  generationId: string
}): Promise<PublishedWebvhLog> {
  const published = await readPublishedLog({
    idStore: clientAnnexLogStore({
      was: server.was,
      spaceId: AUX_SPACE_ID,
      generationId
    }) as WebvhIdStore
  })
  if (published === undefined) {
    throw new Error(`generation ${generationId} has no published log`)
  }
  return published
}

/**
 * The whole GC world: a real did:webvh account log over an in-memory id
 * store, a fake WAS server holding the auxiliary Space, one published
 * generation, and the account document pointed at it.
 *
 * @returns {Promise<object>}
 */
async function gcWorld() {
  const events: string[] = []
  const server = fakeServer({ events })
  const account = memoryIdStore()
  const idStore = recordingIdStore({ store: account.idStore, events })
  const updateKeys = { updateSeed: fixedSeed(1), stagedSeed: fixedSeed(2) }
  const { did: accountDid } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: ACCOUNT_SPACE_ID,
    clientKeys: CANONICAL_CLIENT_KEYS[0]!,
    updateKeys
  })
  const zcapClient = await ladderVmZcapClient({
    accountDid,
    ladderSeed: LADDER_SEED
  })
  const generation = await publishGeneration({
    server,
    accountDid,
    zcapClient
  })
  await setDelegatedClientsPointer({
    idStore,
    updateKeys,
    clientAnnexDid: generation.did,
    expectedDid: accountDid
  })
  return {
    events,
    server,
    account,
    idStore,
    updateKeys,
    accountDid,
    zcapClient,
    generation,
    /**
     * The account's verified published log, as `verifyAccountLog` hands it to
     * the GC pass.
     */
    async accountView(): Promise<PublishedWebvhLog> {
      const published = await readPublishedLog({ idStore })
      if (published === undefined) {
        throw new Error('the account log is not published')
      }
      return published
    }
  }
}

/**
 * The account view a GC pass reads, with the pointer-establishing entry (the
 * log's newest) dated `ageMs` before `now`. The doctored copy never reaches
 * the store: the ceremony's own re-point still rebases on the real log.
 *
 * @param options {object}
 * @param options.published {PublishedWebvhLog}
 * @param options.ageMs {number}   how long ago the pointer was established
 * @param options.now {number}   the pass's clock, epoch milliseconds
 * @returns {object}   the `{ did, doc, log }` account view
 */
function agedAccount({
  published,
  ageMs,
  now
}: {
  published: PublishedWebvhLog
  ageMs: number
  now: number
}): Pick<PublishedWebvhLog, 'did' | 'doc' | 'log'> {
  const last = published.log.length - 1
  const log = published.log.map((entry, index) =>
    index === last
      ? { ...entry, versionTime: new Date(now - ageMs).toISOString() }
      : entry
  ) as DIDLog
  return { did: published.did, doc: published.doc, log }
}

/**
 * A GC pass over one world, with the digest and collection callbacks
 * recorded. `ladderSeed` defaults to the standing credential's; pass `null`
 * for the no-standing-credential login.
 *
 * @param options {object}
 * @param options.world {Awaited<ReturnType<typeof gcWorld>>}
 * @param options.account {object}   the `{ did, doc, log }` account view
 * @param options.now {number}   the pass's clock, epoch milliseconds
 * @param [options.ladderSeed] {Uint8Array | null}
 * @param [options.recordDigest] {Function}   overrides the recording default
 * @returns {Promise<object>}
 */
async function runPass({
  world,
  account,
  now,
  ladderSeed = LADDER_SEED,
  recordDigest
}: {
  world: Awaited<ReturnType<typeof gcWorld>>
  account: Pick<PublishedWebvhLog, 'did' | 'doc' | 'log'>
  now: number
  ladderSeed?: Uint8Array | null
  recordDigest?: (digest: {
    generationId: string
    firstEntry?: string
    lastEntry?: string
    entryCount?: number
  }) => Promise<void>
}) {
  const digests: Array<{
    generationId: string
    firstEntry?: string
    lastEntry?: string
    entryCount?: number
  }> = []
  const onCollectedIds: string[] = []
  const report = await runClientAnnexGc({
    was: world.server.was,
    wasServerUrl: WAS_URL,
    accountSpaceId: ACCOUNT_SPACE_ID,
    account,
    idStore: world.idStore,
    updateKeys: world.updateKeys,
    zcapClient: world.zcapClient,
    ...(ladderSeed !== null ? { ladderSeed } : {}),
    recordDigest:
      recordDigest ??
      (async digest => {
        world.events.push(`digest:${digest.generationId}`)
        digests.push(digest)
      }),
    onCollected: async ({ generationId }) => {
      onCollectedIds.push(generationId)
    },
    now
  })
  return { report, digests, onCollectedIds }
}

describe('delegatedClientsPointerEstablishedAt', () => {
  it('is undefined until an entry carries the pointer', async () => {
    const account = memoryIdStore()
    const updateKeys = { updateSeed: fixedSeed(1), stagedSeed: fixedSeed(2) }
    await ensureDidWebvh({
      idStore: account.idStore,
      wasServerUrl: WAS_URL,
      spaceId: ACCOUNT_SPACE_ID,
      clientKeys: CANONICAL_CLIENT_KEYS[0]!,
      updateKeys
    })
    const published = await readPublishedLog({ idStore: account.idStore })
    expect(
      delegatedClientsPointerEstablishedAt({ log: published!.log })
    ).toBeUndefined()
  })

  it('reads the pointing entry, then the RE-POINT entry after a swap', async () => {
    const world = await gcWorld()
    const pointed = await world.accountView()
    const establishedAt = delegatedClientsPointerEstablishedAt({
      log: pointed.log
    })
    expect(establishedAt).toBe(pointed.log[pointed.log.length - 1]!.versionTime)

    // A re-point moves the clock to the entry that established the NEW value.
    const fresh = await publishGeneration({
      server: world.server,
      accountDid: world.accountDid,
      zcapClient: world.zcapClient
    })
    await setDelegatedClientsPointer({
      idStore: world.idStore,
      updateKeys: world.updateKeys,
      clientAnnexDid: fresh.did,
      expectedDid: world.accountDid
    })
    const repointed = await world.accountView()
    expect(repointed.log.length).toBe(pointed.log.length + 1)
    expect(delegatedClientsPointerEstablishedAt({ log: repointed.log })).toBe(
      repointed.log[repointed.log.length - 1]!.versionTime
    )
  })

  it('a later entry that does not touch the pointer does not advance it', async () => {
    const world = await gcWorld()
    const pointed = await world.accountView()
    const establishedAt = delegatedClientsPointerEstablishedAt({
      log: pointed.log
    })

    await enrollWebvhClient({
      idStore: world.idStore,
      updateKeys: world.updateKeys,
      newClient: {
        signingKeyMultibase: CANONICAL_CLIENT_KEYS[1]!.signingKeyMultibase,
        keyAgreementKeyMultibase:
          CANONICAL_CLIENT_KEYS[1]!.keyAgreementKeyMultibase,
        updateKeyMultibase: await updateKeyMultibase({ seed: fixedSeed(5) }),
        stagedUpdateKeyMultibase: await updateKeyMultibase({
          seed: fixedSeed(6)
        })
      }
    })
    const enrolled = await world.accountView()
    expect(enrolled.log.length).toBeGreaterThan(pointed.log.length)
    expect(delegatedClientsPointerEstablishedAt({ log: enrolled.log })).toBe(
      establishedAt
    )
  })
})

describe('clientAnnexGcDue', () => {
  it('is never due without a pointer', async () => {
    const world = await gcWorld()
    const pointed = await world.accountView()
    const noPointer = pointed.log.slice(0, 1) as DIDLog
    expect(
      clientAnnexGcDue({
        log: noPointer,
        now: Date.now() + GENERATION_GC_PERIOD_MS
      })
    ).toBe(false)
  })

  it('is false just under the period and true at or past it', async () => {
    const world = await gcWorld()
    const pointed = await world.accountView()
    const establishedMs = Date.parse(
      delegatedClientsPointerEstablishedAt({ log: pointed.log })!
    )
    expect(
      clientAnnexGcDue({
        log: pointed.log,
        now: establishedMs + GENERATION_GC_PERIOD_MS - 1000
      })
    ).toBe(false)
    expect(
      clientAnnexGcDue({
        log: pointed.log,
        now: establishedMs + GENERATION_GC_PERIOD_MS
      })
    ).toBe(true)
    expect(
      clientAnnexGcDue({
        log: pointed.log,
        now: establishedMs + GENERATION_GC_PERIOD_MS + 60_000
      })
    ).toBe(true)
  })
})

describe('generationQuiet', () => {
  const logWith = (versionTime?: string): DIDLog =>
    [{ versionId: '1-abc', versionTime }] as unknown as DIDLog

  it('a just-written generation is not quiet', async () => {
    const world = await gcWorld()
    expect(
      generationQuiet({
        log: world.generation.published.log,
        now: Date.now()
      })
    ).toBe(false)
  })

  it('stays not quiet inside the bound plus the grace margin', () => {
    const now = Date.parse('2026-08-19T12:00:00Z')
    const written = new Date(now - QUIET_WINDOW_MS + 60_000).toISOString()
    expect(generationQuiet({ log: logWith(written), now })).toBe(false)
  })

  it('is quiet past the bound plus the grace margin', () => {
    const now = Date.parse('2026-08-19T12:00:00Z')
    const written = new Date(now - QUIET_WINDOW_MS).toISOString()
    expect(generationQuiet({ log: logWith(written), now })).toBe(true)
  })

  it('an empty log or an unparseable versionTime is not quiet', () => {
    const now = Date.parse('2026-08-19T12:00:00Z')
    expect(generationQuiet({ log: [] as unknown as DIDLog, now })).toBe(false)
    expect(generationQuiet({ log: logWith(undefined), now })).toBe(false)
    expect(generationQuiet({ log: logWith('not a date'), now })).toBe(false)
  })
})

describe('the quarterly swap', () => {
  it(
    'mints and points at a fresh generation, revoking the old delegation ' +
      'before the re-point and digesting it before the delete',
    async () => {
      const world = await gcWorld()
      const old = world.generation
      // Far enough ahead that the pointed generation's entries are quiet, with
      // the pointer itself dated a full period back.
      const now = Date.now() + QUIET_WINDOW_MS + 60_000
      const account = agedAccount({
        published: await world.accountView(),
        ageMs: GENERATION_GC_PERIOD_MS + 60_000,
        now
      })
      world.events.length = 0

      const { report, digests, onCollectedIds } = await runPass({
        world,
        account,
        now
      })
      expect(report.swap).toBe('replaced')
      expect(report.failed).toEqual([])

      // A fresh generation stands in the auxiliary Space, with its own genesis
      // and its own generation-delegation service entry.
      const freshDid = report.pointedDid!
      expect(freshDid).not.toBe(old.did)
      const freshId = freshDid.split(':').pop()!
      const fresh = await readClientAnnexLog({
        server: world.server,
        generationId: freshId
      })
      const freshDelegation = embeddedGenerationDelegation({ doc: fresh.doc })
      expect(freshDelegation).toBeDefined()
      expect((freshDelegation as { controller?: string }).controller).toBe(
        freshDid
      )
      expect(freshDelegation!.invocationTarget).toBe(
        toUrl({ serverUrl: WAS_URL, path: spaceItems(ACCOUNT_SPACE_ID) })
      )

      // The old delegation was submitted for revocation VERBATIM.
      expect(world.server.revocations[0]!.capabilityId).toBe(old.delegation.id)
      expect(world.server.revocations[0]!.body).toEqual(old.delegation)

      // The account document points at the fresh DID, the service entry's id
      // preserved verbatim.
      const repointed = await world.accountView()
      expect(delegatedClientsPointer({ doc: repointed.doc })).toBe(freshDid)
      expect((repointed.doc.service ?? [])[0]!.id).toBe(
        `${world.accountDid}#delegated-clients`
      )

      // The old generation was digested from its own log, then collected.
      expect(digests).toEqual([
        {
          generationId: old.generationId,
          firstEntry: old.published.log[0]!.versionTime,
          lastEntry:
            old.published.log[old.published.log.length - 1]!.versionTime,
          entryCount: old.published.log.length
        }
      ])
      expect(onCollectedIds).toEqual([old.generationId])
      expect(report.collected).toEqual([old.generationId])

      // Stage order: the revoke precedes the re-point (a fail-open server must
      // not honor the old delegation after the pointer moves), and the digest
      // precedes the delete (the delete destroys its only source).
      const revokeAt = world.events.indexOf(`revoke:${old.delegation.id}`)
      const repointAt = world.events.indexOf('account-put:did.jsonl')
      expect(revokeAt).toBeGreaterThanOrEqual(0)
      expect(repointAt).toBeGreaterThan(revokeAt)
      expect(world.events.indexOf(`digest:${old.generationId}`)).toBeLessThan(
        world.events.indexOf(`delete:${old.generationId}`)
      )

      // Exactly one `gen-` collection remains, and it is the pointed one.
      expect(world.server.collectionIds(AUX_SPACE_ID)).toEqual([freshId])
    }
  )

  it('defers on a live pointed generation, but still collects orphans', async () => {
    const world = await gcWorld()
    const orphan = await publishGeneration({
      server: world.server,
      accountDid: world.accountDid,
      zcapClient: world.zcapClient
    })
    // Due by the cadence, but the pointed generation was written moments ago.
    const now = Date.now() + 1000
    const account = agedAccount({
      published: await world.accountView(),
      ageMs: GENERATION_GC_PERIOD_MS + 60_000,
      now
    })
    world.events.length = 0

    const { report } = await runPass({ world, account, now })
    expect(report.swap).toBe('deferred-live')
    expect(report.pointedDid).toBe(world.generation.did)
    // Nothing was minted and the pointer never moved.
    expect(world.events.some(event => event.startsWith('account-put:'))).toBe(
      false
    )
    const repointed = await world.accountView()
    expect(delegatedClientsPointer({ doc: repointed.doc })).toBe(
      world.generation.did
    )
    // The pointed generation's delegation stands; only the orphan's went.
    expect(world.server.revoked.has(world.generation.delegation.id)).toBe(false)
    expect(report.collected).toEqual([orphan.generationId])
    expect(world.server.collectionIds(AUX_SPACE_ID)).toEqual([
      world.generation.generationId
    ])
  })

  it('does not swap before the period is up, but still collects orphans', async () => {
    const world = await gcWorld()
    const orphan = await publishGeneration({
      server: world.server,
      accountDid: world.accountDid,
      zcapClient: world.zcapClient
    })
    const now = Date.now() + 1000
    const { report } = await runPass({
      world,
      account: await world.accountView(),
      now
    })
    expect(report.swap).toBe('not-due')
    expect(report.pointedDid).toBe(world.generation.did)
    expect(report.collected).toEqual([orphan.generationId])
    expect(world.server.collectionIds(AUX_SPACE_ID)).toEqual([
      world.generation.generationId
    ])
  })

  it('no-ops entirely on an account with no client annex pointer', async () => {
    const world = await gcWorld()
    const pointed = await world.accountView()
    world.server.calls.length = 0
    const { report } = await runPass({
      world,
      account: {
        did: pointed.did,
        doc: { id: pointed.did } as PublishedWebvhLog['doc'],
        log: pointed.log
      },
      now: Date.now() + GENERATION_GC_PERIOD_MS
    })
    expect(report).toEqual({ swap: 'no-pointer', collected: [], failed: [] })
    // Without a pointer there is no auxiliary Space to list.
    expect(
      world.server.calls.some(call => call.url.endsWith('/collections/'))
    ).toBe(false)
  })

  it('reports no-ladder-seed on a due swap the login cannot mint for', async () => {
    const world = await gcWorld()
    const orphan = await publishGeneration({
      server: world.server,
      accountDid: world.accountDid,
      zcapClient: world.zcapClient
    })
    const now = Date.now() + QUIET_WINDOW_MS + 60_000
    const account = agedAccount({
      published: await world.accountView(),
      ageMs: GENERATION_GC_PERIOD_MS + 60_000,
      now
    })
    const { report } = await runPass({
      world,
      account,
      now,
      ladderSeed: null
    })
    expect(report.swap).toBe('no-ladder-seed')
    expect(report.pointedDid).toBe(world.generation.did)
    // The collect fan-out still ran.
    expect(report.collected).toEqual([orphan.generationId])
  })
})

describe('swapClientAnnexGeneration (the off-cadence swap)', () => {
  it(
    'mints a fresh generation from the surviving seed, re-points the ' +
      'account document, and revokes the old delegation first',
    async () => {
      const world = await gcWorld()
      const old = world.generation
      world.events.length = 0

      const freshDid = await swapClientAnnexGeneration({
        was: world.server.was,
        wasServerUrl: WAS_URL,
        accountSpaceId: ACCOUNT_SPACE_ID,
        account: await world.accountView(),
        idStore: world.idStore,
        updateKeys: world.updateKeys,
        zcapClient: world.zcapClient,
        ladderSeed: LADDER_SEED
      })
      expect(freshDid).not.toBe(old.did)

      // The fresh generation stands with its own delegation installed.
      const freshId = freshDid.split(':').pop()!
      const fresh = await readClientAnnexLog({
        server: world.server,
        generationId: freshId
      })
      const freshDelegation = embeddedGenerationDelegation({ doc: fresh.doc })
      expect(freshDelegation).toBeDefined()
      expect((freshDelegation as { controller?: string }).controller).toBe(
        freshDid
      )

      // The pointer names it now, and the old delegation went for revocation
      // verbatim, before the re-point.
      const repointed = await world.accountView()
      expect(delegatedClientsPointer({ doc: repointed.doc })).toBe(freshDid)
      expect(world.server.revocations[0]!.capabilityId).toBe(old.delegation.id)
      expect(world.server.revocations[0]!.body).toEqual(old.delegation)
      const revokeAt = world.events.indexOf(`revoke:${old.delegation.id}`)
      expect(revokeAt).toBeGreaterThanOrEqual(0)
      expect(world.events.indexOf('account-put:did.jsonl')).toBeGreaterThan(
        revokeAt
      )

      // The swap is authority removal, not hygiene: the abandoned generation
      // is left to the standing orphan discovery rather than deleted here.
      expect(world.server.collectionIds(AUX_SPACE_ID).sort()).toEqual(
        [old.generationId, freshId].sort()
      )
      expect(world.events.some(event => event.startsWith('delete:'))).toBe(
        false
      )
    }
  )

  it('skips the revoke when the pointed generation is unreadable', async () => {
    const world = await gcWorld()
    const old = world.generation
    // The old generation's log is gone (a torn collect, or a host that lost
    // it): there are no delegation bytes left to submit.
    world.server.resources.delete(
      `/space/${AUX_SPACE_ID}/${old.generationId}/did.jsonl`
    )

    const freshDid = await swapClientAnnexGeneration({
      was: world.server.was,
      wasServerUrl: WAS_URL,
      accountSpaceId: ACCOUNT_SPACE_ID,
      account: await world.accountView(),
      idStore: world.idStore,
      updateKeys: world.updateKeys,
      zcapClient: world.zcapClient,
      ladderSeed: LADDER_SEED
    })
    expect(freshDid).not.toBe(old.did)
    expect(world.server.revocations).toEqual([])
    const repointed = await world.accountView()
    expect(delegatedClientsPointer({ doc: repointed.doc })).toBe(freshDid)
  })

  it('refuses an account document with no client annex pointer', async () => {
    const world = await gcWorld()
    const pointed = await world.accountView()
    await expect(
      swapClientAnnexGeneration({
        was: world.server.was,
        wasServerUrl: WAS_URL,
        accountSpaceId: ACCOUNT_SPACE_ID,
        account: {
          did: pointed.did,
          doc: { id: pointed.did } as PublishedWebvhLog['doc']
        },
        idStore: world.idStore,
        updateKeys: world.updateKeys,
        zcapClient: world.zcapClient,
        ladderSeed: LADDER_SEED
      })
    ).rejects.toThrow(/no delegated-clients service entry/)
  })
})

describe('the collect fan-out', () => {
  it('deletes an orphan that never published a log, with no digest', async () => {
    const world = await gcWorld()
    world.server.createCollection({
      spaceId: AUX_SPACE_ID,
      collectionId: 'gen-AAAAAAAAAAAAAAAA'
    })
    const now = Date.now() + 1000
    const { report, digests } = await runPass({
      world,
      account: await world.accountView(),
      now
    })
    expect(report.collected).toEqual(['gen-AAAAAAAAAAAAAAAA'])
    expect(digests).toEqual([])
    expect(world.server.collectionIds(AUX_SPACE_ID)).toEqual([
      world.generation.generationId
    ])
  })

  it('keeps a tampered generation and still collects its healthy sibling', async () => {
    const world = await gcWorld()
    const tampered = await publishGeneration({
      server: world.server,
      accountDid: world.accountDid,
      zcapClient: world.zcapClient
    })
    const healthy = await publishGeneration({
      server: world.server,
      accountDid: world.accountDid,
      zcapClient: world.zcapClient
    })
    // The host rewrites a byte of the served log: verification fails, so the
    // evidence is kept rather than deleted.
    const path = `/space/${AUX_SPACE_ID}/${tampered.generationId}/did.jsonl`
    const stored = world.server.resources.get(path)!
    world.server.resources.set(path, {
      ...stored,
      text: stored.text.replace(
        '#generation-delegation',
        '#generation-delegationX'
      )
    })

    const now = Date.now() + 1000
    const { report } = await runPass({
      world,
      account: await world.accountView(),
      now
    })
    expect(report.collected).toEqual([healthy.generationId])
    expect(report.failed.map(entry => entry.generationId)).toEqual([
      tampered.generationId
    ])
    // The refusal is the log's own, not an incidental transport miss.
    expect(String(report.failed[0]!.error)).toMatch(/hash chain broken/i)
    expect(world.events).not.toContain(`delete:${tampered.generationId}`)
    expect(world.server.collectionIds(AUX_SPACE_ID)).toEqual([
      world.generation.generationId,
      tampered.generationId
    ])
  })

  it('keeps a generation whose digest could not be written', async () => {
    const world = await gcWorld()
    const orphan = await publishGeneration({
      server: world.server,
      accountDid: world.accountDid,
      zcapClient: world.zcapClient
    })
    const now = Date.now() + 1000
    const { report } = await runPass({
      world,
      account: await world.accountView(),
      now,
      recordDigest: async () => {
        throw new Error('the wallet-activity write failed')
      }
    })
    expect(report.collected).toEqual([])
    expect(report.failed.map(entry => entry.generationId)).toEqual([
      orphan.generationId
    ])
    expect(world.events).not.toContain(`delete:${orphan.generationId}`)
    expect(
      world.server.collectionIds(AUX_SPACE_ID).includes(orphan.generationId)
    ).toBe(true)
  })
})

describe('the resume contract', () => {
  it(
    'reads an already-revoked answer as success, deletes idempotently, ' +
      'and converges to one pointed generation on a second pass',
    async () => {
      const world = await gcWorld()
      const orphan = await publishGeneration({
        server: world.server,
        accountDid: world.accountDid,
        zcapClient: world.zcapClient
      })
      // A torn earlier pass already revoked the orphan's delegation, so the
      // blind re-POST gets the server's 400.
      world.server.revoked.add(orphan.delegation.id)

      const now = Date.now() + QUIET_WINDOW_MS + 60_000
      const first = await runPass({
        world,
        account: agedAccount({
          published: await world.accountView(),
          ageMs: GENERATION_GC_PERIOD_MS + 60_000,
          now
        }),
        now
      })
      expect(first.report.swap).toBe('replaced')
      expect(first.report.failed).toEqual([])
      expect(first.report.collected.sort()).toEqual(
        [orphan.generationId, world.generation.generationId].sort()
      )

      // A collection the pass already deleted deletes again without error.
      await world.server.was
        .space(AUX_SPACE_ID)
        .collection(orphan.generationId)
        .delete()

      // The second pass, against the fresh pointer, is a no-op.
      const freshDid = first.report.pointedDid!
      const second = await runPass({
        world,
        account: await world.accountView(),
        now: Date.now() + 1000
      })
      expect(second.report.swap).toBe('not-due')
      expect(second.report.pointedDid).toBe(freshDid)
      expect(second.report.collected).toEqual([])
      expect(second.report.failed).toEqual([])
      expect(second.digests).toEqual([])

      // The completion predicate over durable state alone: exactly one `gen-`
      // collection, and it is the one the pointer names.
      const remaining = world.server.collectionIds(AUX_SPACE_ID)
      expect(remaining).toHaveLength(1)
      expect(freshDid.endsWith(`:${remaining[0]!}`)).toBe(true)
    }
  )

  it(
    "a stale transient session's delegation stops verifying after the " +
      'hostile swap, while the fresh generation is honored',
    async () => {
      const world = await gcWorld()
      const stale = world.generation
      // The transient visit's chain rides the pointed generation's delegation.
      expect(world.server.chainVerifies({ delegation: stale.delegation })).toBe(
        true
      )

      const now = Date.now() + QUIET_WINDOW_MS + 60_000
      const { report } = await runPass({
        world,
        account: agedAccount({
          published: await world.accountView(),
          ageMs: GENERATION_GC_PERIOD_MS + 60_000,
          now
        }),
        now
      })
      expect(report.swap).toBe('replaced')

      // The stale session's whole chain is dead at the server, independently
      // of the pointer move.
      expect(world.server.revoked.has(stale.delegation.id)).toBe(true)
      expect(world.server.chainVerifies({ delegation: stale.delegation })).toBe(
        false
      )

      const freshId = report.pointedDid!.split(':').pop()!
      const fresh = await readClientAnnexLog({
        server: world.server,
        generationId: freshId
      })
      expect(
        world.server.chainVerifies({
          delegation: embeddedGenerationDelegation({ doc: fresh.doc })!
        })
      ).toBe(true)
    }
  )
})

describe('addHistoryGenerationCollected', () => {
  it('builds the digest row: the generation id verbatim as the activity id', () => {
    const activity = addHistoryGenerationCollected({
      user: { email: 'holder@example.com' },
      generationId: 'gen-Ux3v0kQf9aPmB2hZ',
      firstEntry: '2026-05-01T00:00:00Z',
      lastEntry: '2026-07-29T11:22:33Z',
      entryCount: 7,
      created: '2026-08-19T12:00:00.000Z'
    })
    expect(activity).toEqual({
      id: 'gen-Ux3v0kQf9aPmB2hZ',
      type: [ACTIVITY_TYPE.GenerationCollect],
      summary: 'Collected client-annex generation "gen-Ux3v0kQf9aPmB2hZ".',
      actor: { email: 'holder@example.com' },
      object: {
        generationId: 'gen-Ux3v0kQf9aPmB2hZ',
        firstEntry: '2026-05-01T00:00:00Z',
        lastEntry: '2026-07-29T11:22:33Z',
        entryCount: 7
      },
      created: '2026-08-19T12:00:00.000Z'
    })
  })

  it('defaults created to now and tolerates an unpublished log', () => {
    const activity = addHistoryGenerationCollected({
      user: {},
      generationId: 'gen-Ux3v0kQf9aPmB2hZ'
    })
    expect(activity.id).toBe('gen-Ux3v0kQf9aPmB2hZ')
    expect(Date.parse(activity.created as string)).toBeGreaterThan(0)
    expect(activity.object).toEqual({
      generationId: 'gen-Ux3v0kQf9aPmB2hZ',
      firstEntry: undefined,
      lastEntry: undefined,
      entryCount: undefined
    })
  })
})
