/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The transient visit's client-annex ensure
 * (`ensureCredentialClientAnnexGeneration`): each of the four unreachable
 * states healed from a visit holding nothing but the credential (no pointer
 * with a sibling in hand, a GC'd pointed generation, an expiring generation
 * delegation, a record without a sibling), the fresh-Space arm's genesis
 * ordering, the two typed refusals (`ladder-vm-not-anchored`,
 * `update-key-not-attributable`) with nothing written, the healthy account's
 * pure no-op report, the rung-uncommitted fall-through to a fresh mint, and
 * the synchronous `onRebindRecord` TypeError.
 */
import { describe, expect, it } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import type { IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { WasClient } from '@interop/was-client'
import {
  clientAnnexDidParts,
  clientAnnexLogStore,
  delegatedClientsDelegationSpaceId,
  delegatedClientsPointer,
  embeddedGenerationDelegation,
  ensureClientAnnexSpace,
  ensureGenerationDelegationCurrent,
  GENERATION_DELEGATION_TTL_MS,
  mintCredentialClientAnnexGeneration,
  mintDelegatedClientsDelegation,
  setDelegatedClientsPointer
} from '../../src/clientAnnex/log.js'
import {
  ClientAnnexGenerationUnavailableError,
  ensureCredentialClientAnnexGeneration,
  ladderSignedGenerationDelegationMinter
} from '../../src/clientAnnex/heal.js'
import type { ClientAnnexGenerationEnsureOutcome } from '../../src/clientAnnex/heal.js'
import { memoryResourceLogPinStore } from '@interop/vh-resource-log'
import { ladderRung } from '../../src/clientAnnex/ladder.js'
import { ladderVmZcapClient } from '../../src/clientAnnex/zcap.js'
import { ensureLadderAnchoredDidWebvh } from '../../src/clientAnnex/ladderAnchored.js'
import { accountLogPinId } from '../../src/webvh/verifyLog.js'
import {
  ensureDidWebvh,
  pinOfLog,
  readPublishedLog
} from '../../src/webvh/didWebvh.js'
import type {
  PublishedWebvhLog,
  WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'https://storage.example'
const ACCOUNT_SPACE_ID = 'account-space-heal'
const AUX_SPACE_ID = 'aux-space-heal'

/**
 * A deterministic 32-byte seed, so two derivations agree across helpers.
 */
function fixedSeed(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

/**
 * The standing credential's ladder seed -- the account is anchored on it.
 */
const LADDER_SEED = fixedSeed(11)

/**
 * A DIFFERENT credential's ladder seed, for the attribution refusal and the
 * rung-uncommitted fall-through fixtures.
 */
const OTHER_LADDER_SEED = fixedSeed(22)

/**
 * One resource row in the fake server, versioned so its integer version can
 * serve as the ETag.
 */
interface StoredResource {
  text: string
  version: number
}

/**
 * An in-memory WAS server behind a fake ezcap client, the `clientAnnex-gc`
 * suite's model trimmed to what the heal drives: Space Descriptions
 * (`describe` / `configure`), collection create/delete, versioned resources
 * with `if-match` / `if-none-match`, and the revocation endpoint (repeat
 * submissions answered with the server's 400, mapped to a
 * `ValidationError`). Every call is recorded so a refusal test can assert
 * nothing was written.
 *
 * @returns {object}
 */
function fakeServer() {
  const spaces = new Map<string, object>()
  const collections = new Map<string, Set<string>>()
  const resources = new Map<string, StoredResource>()
  const revoked = new Set<string>()
  const revocations: Array<{ capabilityId: string; body: unknown }> = []
  const calls: Array<{ method: string; url: string; capability?: unknown }> = []

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
      body,
      capability
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
      calls.push({ method: verb, url, capability })
      const path = new URL(url).pathname
      const segments = path.split('/').filter(Boolean)
      if (segments[0] !== 'space') {
        throw new Error(`Unrouted path "${path}".`)
      }
      const spaceId = decodeURIComponent(segments[1] ?? '')

      // /space/<spaceId>/zcaps/revocations/<capabilityId>
      if (segments[2] === 'zcaps' && segments[3] === 'revocations') {
        const capabilityId = decodeURIComponent(segments[4] ?? '')
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
          spaces.set(spaceId, (json ?? {}) as object)
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
    resources,
    revocations,
    revoked,
    spaces,
    zcapClient,
    was: new WasClient({ serverUrl: WAS_URL, zcapClient }),
    /**
     * The collection ids a Space currently holds.
     */
    collectionIds(spaceId: string): string[] {
      return [...collectionsOf(spaceId)]
    },
    /**
     * The write (non-GET) calls the server has answered.
     */
    writeCalls(): Array<{ method: string; url: string; capability?: unknown }> {
      return calls.filter(call => call.method !== 'GET')
    }
  }
}

/**
 * The heal world: a real ladder-anchored account log over an in-memory id
 * store (updateKeys = [rung 0], the ladder VM a document verification
 * method), a fake WAS server, the standing-client identity, and the shared
 * accessors every case reads.
 *
 * @returns {Promise<object>}
 */
async function healWorld() {
  const server = fakeServer()
  const account = memoryIdStore()
  const accountPuts: string[] = []
  const idStore = {
    ...account.idStore,
    async putIdResource(options: Parameters<WebvhIdStore['putIdResource']>[0]) {
      accountPuts.push(options.resourceId)
      return account.idStore.putIdResource(options)
    }
  }
  const { did } = await ensureLadderAnchoredDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: ACCOUNT_SPACE_ID,
    ladderSeed: LADDER_SEED,
    keyAgreement: {
      publicKeyMultibase: CANONICAL_CLIENT_KEYS[9]!.keyAgreementKeyMultibase
    }
  })
  const ladderClient = await ladderVmZcapClient({
    accountDid: did,
    ladderSeed: LADDER_SEED
  })
  const standingClient = {
    did: `did:key:${CANONICAL_CLIENT_KEYS[0]!.signingKeyMultibase}`,
    zcapClient: server.zcapClient
  }
  return {
    server,
    account,
    accountPuts,
    idStore,
    did,
    ladderClient,
    standingClient,
    /**
     * The account's verified published log, as `verifyAccountLog` hands it
     * to the ensure.
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

type HealWorld = Awaited<ReturnType<typeof healWorld>>

/**
 * A sibling delegation for the given auxiliary Space, ladder-VM-signed and
 * delegated to the standing client -- the record's `delegatedClients` member.
 */
async function mintSibling({
  world,
  spaceId = AUX_SPACE_ID,
  now
}: {
  world: HealWorld
  spaceId?: string
  now?: number
}): Promise<IZcap> {
  return mintDelegatedClientsDelegation({
    zcapClient: world.ladderClient,
    wasServerUrl: WAS_URL,
    clientAnnexSpaceId: spaceId,
    controller: world.standingClient.did,
    ...(now !== undefined ? { now } : {})
  })
}

/**
 * A published generation in the fake server's auxiliary Space with its
 * ladder-signed delegation installed, plus the account document pointed at
 * it (the pointer entry signed by the ladder's revealed rung 0).
 */
async function publishPointedGeneration({
  world,
  ladderSeed = LADDER_SEED,
  installDelegation = true,
  now
}: {
  world: HealWorld
  ladderSeed?: Uint8Array
  installDelegation?: boolean
  now?: number
}) {
  const minted = await mintCredentialClientAnnexGeneration({
    was: world.server.was,
    wasServerUrl: WAS_URL,
    spaceId: AUX_SPACE_ID,
    controller: world.did,
    ladderSeed
  })
  let delegation: IZcap | undefined
  if (installDelegation) {
    const ensured = await ensureGenerationDelegationCurrent({
      store: clientAnnexLogStore({
        was: world.server.was,
        spaceId: AUX_SPACE_ID,
        generationId: minted.generationId
      }),
      ladderSeed,
      generationId: minted.generationId,
      mintGenerationDelegation: ladderSignedGenerationDelegationMinter({
        accountDid: world.did,
        ladderSeed: LADDER_SEED,
        wasServerUrl: WAS_URL,
        spaceId: ACCOUNT_SPACE_ID,
        ...(now !== undefined ? { now } : {})
      }),
      expectedDid: minted.did,
      ...(now !== undefined ? { now } : {})
    })
    delegation = ensured.delegation
  }
  const rung0 = await ladderRung({ ladderSeed: LADDER_SEED, index: 0 })
  const rung1 = await ladderRung({ ladderSeed: LADDER_SEED, index: 1 })
  await setDelegatedClientsPointer({
    idStore: world.idStore,
    updateKeys: { updateSeed: rung0.seed, stagedSeed: rung1.seed },
    clientAnnexDid: minted.did,
    expectedDid: world.did
  })
  return { did: minted.did, generationId: minted.generationId, delegation }
}

/**
 * A `bootstrapWasFor` that must never be reached: the arms under test stay
 * inside an existing Space.
 */
function noBootstrap(): WasClient {
  throw new Error('the fresh-Space arm must not run in this case')
}

/**
 * Runs the ensure with the world's shared members and a recording
 * `onRebindRecord`, returning the outcome beside what the seam was handed.
 */
async function runEnsure({
  world,
  delegatedClients,
  bootstrapWasFor = noBootstrap,
  ladderSeed = LADDER_SEED,
  idStore = undefined,
  now
}: {
  world: HealWorld
  delegatedClients?: IZcap
  bootstrapWasFor?: (options: object) => WasClient
  ladderSeed?: Uint8Array
  idStore?: WebvhIdStore
  now?: number
}): Promise<{
  outcome: ClientAnnexGenerationEnsureOutcome
  rebound: IZcap[]
}> {
  const rebound: IZcap[] = []
  const outcome = await ensureCredentialClientAnnexGeneration({
    wasServerUrl: WAS_URL,
    spaceId: ACCOUNT_SPACE_ID,
    account: await world.accountView(),
    ladderSeed,
    standingClient: world.standingClient,
    bootstrapWasFor,
    idStore: idStore ?? world.idStore,
    onRebindRecord: async ({ delegatedClients: fresh }) => {
      rebound.push(fresh)
    },
    ...(delegatedClients !== undefined ? { delegatedClients } : {}),
    ...(now !== undefined ? { now } : {})
  })
  return { outcome, rebound }
}

/**
 * The delegated capability a recorded call rode, by zcap id -- `undefined`
 * for a root invocation (no capability, or a bare root-id string).
 */
function delegatedCapabilityIdOf(call: {
  capability?: unknown
}): string | undefined {
  const capability = call.capability
  return typeof capability === 'object' && capability !== null
    ? (capability as { id?: string }).id
    : undefined
}

describe('ensureCredentialClientAnnexGeneration', () => {
  it('no pointer, sibling in hand: mints into the sibling Space and points', async () => {
    const world = await healWorld()
    // The torn-establishment shape: the auxiliary Space exists (typed), the
    // record carries the sibling, but no generation was ever pointed.
    await ensureClientAnnexSpace({
      was: world.server.was,
      spaceId: AUX_SPACE_ID,
      controller: world.did
    })
    const sibling = await mintSibling({ world })
    world.server.calls.length = 0

    const { outcome, rebound } = await runEnsure({
      world,
      delegatedClients: sibling
    })
    expect(outcome.generationMinted).toBe(true)
    expect(outcome.spaceMinted).toBe(false)
    expect(outcome.delegationRenewed).toBe(false)
    expect(outcome.siblingReminted).toBe(false)
    expect(rebound).toEqual([])
    expect(outcome.delegatedClients).toBe(sibling)
    // Every annex-Space request of the ensure rode the usable sibling as its
    // invocation capability.
    const annexCalls = world.server.calls.filter(call =>
      new URL(call.url).pathname.startsWith(`/space/${AUX_SPACE_ID}/`)
    )
    expect(annexCalls.length).toBeGreaterThan(0)
    expect(
      annexCalls.every(
        call => delegatedCapabilityIdOf(call) === (sibling as { id: string }).id
      )
    ).toBe(true)
    // The generation landed in the SIBLING's Space, not a fresh one.
    expect(clientAnnexDidParts({ did: outcome.clientAnnexDid }).spaceId).toBe(
      AUX_SPACE_ID
    )
    // The pointer entry landed (log only) and names the fresh generation.
    const view = await world.accountView()
    expect(delegatedClientsPointer({ doc: view.doc })).toBe(
      outcome.clientAnnexDid
    )
    // The generation's delegation is embedded and names the account subtree.
    const parts = clientAnnexDidParts({ did: outcome.clientAnnexDid })
    const published = await readPublishedLog({
      idStore: clientAnnexLogStore({
        was: world.server.was,
        spaceId: AUX_SPACE_ID,
        generationId: parts.generationId
      }) as WebvhIdStore
    })
    expect(embeddedGenerationDelegation({ doc: published!.doc })).toEqual(
      outcome.generationDelegation
    )
  })

  it('a GC-d pointed generation: fresh generation in the same Space, sibling untouched', async () => {
    const world = await healWorld()
    const old = await publishPointedGeneration({ world })
    const sibling = await mintSibling({ world })
    // The generation's log is gone (collected, or never re-minted).
    world.server.resources.delete(
      `/space/${AUX_SPACE_ID}/${old.generationId}/did.jsonl`
    )

    const { outcome, rebound } = await runEnsure({
      world,
      delegatedClients: sibling
    })
    expect(outcome.generationMinted).toBe(true)
    expect(outcome.spaceMinted).toBe(false)
    expect(outcome.siblingReminted).toBe(false)
    expect(rebound).toEqual([])
    expect(outcome.clientAnnexDid).not.toBe(old.did)
    expect(clientAnnexDidParts({ did: outcome.clientAnnexDid }).spaceId).toBe(
      AUX_SPACE_ID
    )
    expect(world.server.revocations).toEqual([])
    const view = await world.accountView()
    expect(delegatedClientsPointer({ doc: view.doc })).toBe(
      outcome.clientAnnexDid
    )
  })

  it('an expiring generation delegation: renewed ladder-signed, nothing minted', async () => {
    const world = await healWorld()
    const mintedAt = Date.now()
    const old = await publishPointedGeneration({ world, now: mintedAt })
    // One day of delegation life left: inside the 30-day renewal window. The
    // sibling is minted on the heal's clock so it alone stays fresh.
    const now = mintedAt + GENERATION_DELEGATION_TTL_MS - 24 * 60 * 60 * 1000
    const sibling = await mintSibling({ world, now })
    const collectionsBefore = world.server.collectionIds(AUX_SPACE_ID)
    const accountEntriesBefore = (await world.accountView()).log.length
    const { outcome, rebound } = await runEnsure({
      world,
      delegatedClients: sibling,
      now
    })
    expect(outcome.delegationRenewed).toBe(true)
    expect(outcome.generationMinted).toBe(false)
    expect(outcome.spaceMinted).toBe(false)
    expect(outcome.siblingReminted).toBe(false)
    expect(rebound).toEqual([])
    expect(outcome.clientAnnexDid).toBe(old.did)
    // The fresh delegation replaced the embedded one in place.
    expect(outcome.generationDelegation.id).not.toBe(old.delegation!.id)
    // Compared as instants: the delegation serializes `expires` without
    // fractional seconds.
    expect(
      Date.parse(
        (outcome.generationDelegation as { expires?: string }).expires!
      )
    ).toBe(Math.floor((now + GENERATION_DELEGATION_TTL_MS) / 1000) * 1000)
    // Nothing was minted and the account log never moved.
    expect(world.server.collectionIds(AUX_SPACE_ID)).toEqual(collectionsBefore)
    expect((await world.accountView()).log.length).toBe(accountEntriesBefore)
  })

  it('a record without a sibling: one minted ladder-signed and re-bound', async () => {
    const world = await healWorld()
    await publishPointedGeneration({ world })

    const { outcome, rebound } = await runEnsure({ world })
    expect(outcome.siblingReminted).toBe(true)
    expect(outcome.generationMinted).toBe(false)
    expect(outcome.delegationRenewed).toBe(false)
    expect(rebound).toEqual([outcome.delegatedClients])
    // The fresh sibling targets the pointed Space and names the standing
    // client as controller.
    expect(
      delegatedClientsDelegationSpaceId({
        delegation: outcome.delegatedClients
      })
    ).toBe(AUX_SPACE_ID)
    expect(
      (outcome.delegatedClients as { controller?: string }).controller
    ).toBe(world.standingClient.did)
  })

  it('neither pointer nor sibling: a fresh Space in the genesis ordering', async () => {
    const world = await healWorld()
    const { outcome, rebound } = await runEnsure({
      world,
      bootstrapWasFor: () => world.server.was
    })
    expect(outcome.spaceMinted).toBe(true)
    expect(outcome.generationMinted).toBe(true)
    expect(outcome.siblingReminted).toBe(true)
    expect(rebound).toEqual([outcome.delegatedClients])

    const parts = clientAnnexDidParts({ did: outcome.clientAnnexDid })
    expect(parts.spaceId).not.toBe(AUX_SPACE_ID)
    // The bootstrap arm's writes rode no delegated capability: they invoke
    // as the ladder VM's bare did:key while the Space still answers to it.
    const freshSpaceCalls = world.server.calls.filter(call =>
      new URL(call.url).pathname.startsWith(`/space/${parts.spaceId}`)
    )
    expect(freshSpaceCalls.length).toBeGreaterThan(0)
    expect(
      freshSpaceCalls.every(call => delegatedCapabilityIdOf(call) === undefined)
    ).toBe(true)
    // The Space's controller was flipped to the account DID after the
    // delegation embedded under the bootstrap key.
    expect(
      (world.server.spaces.get(parts.spaceId) as { controller?: string })
        .controller
    ).toBe(world.did)
    // The pointer names the fresh generation, and the sibling targets its
    // Space.
    const view = await world.accountView()
    expect(delegatedClientsPointer({ doc: view.doc })).toBe(
      outcome.clientAnnexDid
    )
    expect(
      delegatedClientsDelegationSpaceId({
        delegation: outcome.delegatedClients
      })
    ).toBe(parts.spaceId)
  })

  it('refuses ladder-vm-not-anchored on a durable-clients account, writing nothing', async () => {
    const server = fakeServer()
    const account = memoryIdStore()
    await ensureDidWebvh({
      idStore: account.idStore,
      wasServerUrl: WAS_URL,
      spaceId: ACCOUNT_SPACE_ID,
      clientKeys: CANONICAL_CLIENT_KEYS[0]!,
      updateKeys: { updateSeed: fixedSeed(1), stagedSeed: fixedSeed(2) }
    })
    const published = await readPublishedLog({ idStore: account.idStore })
    const logBefore = account.log()
    // The document lists durable clients only -- no ladder VM stands in it.
    const error = await ensureCredentialClientAnnexGeneration({
      wasServerUrl: WAS_URL,
      spaceId: ACCOUNT_SPACE_ID,
      account: published!,
      ladderSeed: LADDER_SEED,
      standingClient: {
        did: `did:key:${CANONICAL_CLIENT_KEYS[1]!.signingKeyMultibase}`,
        zcapClient: server.zcapClient
      },
      bootstrapWasFor: () => server.was,
      idStore: account.idStore,
      onRebindRecord: async () => {}
    }).then(
      () => undefined,
      (err: unknown) => err
    )
    expect(error).toBeInstanceOf(ClientAnnexGenerationUnavailableError)
    expect((error as ClientAnnexGenerationUnavailableError).reason).toBe(
      'ladder-vm-not-anchored'
    )
    expect((error as Error).name).toBe('ClientAnnexGenerationUnavailableError')
    // Nothing was written anywhere: no server calls, no log movement.
    expect(server.calls).toEqual([])
    expect(account.log()).toBe(logBefore)
  })

  it('refuses update-key-not-attributable before any Space or annex write', async () => {
    const world = await healWorld()
    // The document lists this ladder's VM, but the served parameters
    // authorize ANOTHER ladder's rung -- no pointer entry could be signed.
    const view = await world.accountView()
    const otherRung = await ladderRung({
      ladderSeed: OTHER_LADDER_SEED,
      index: 0
    })
    const last = view.log.length - 1
    const doctoredLog = view.log.map((entry, index) =>
      index === last
        ? {
            ...entry,
            parameters: {
              ...entry.parameters,
              updateKeys: [otherRung.keyMultibase],
              nextKeyHashes: []
            }
          }
        : entry
    ) as DIDLog
    const logBefore = world.account.log()

    const error = await ensureCredentialClientAnnexGeneration({
      wasServerUrl: WAS_URL,
      spaceId: ACCOUNT_SPACE_ID,
      account: { did: view.did, doc: view.doc, log: doctoredLog },
      ladderSeed: LADDER_SEED,
      standingClient: world.standingClient,
      bootstrapWasFor: () => {
        throw new Error('nothing may be minted past the pre-flight refusal')
      },
      idStore: world.idStore,
      onRebindRecord: async () => {}
    }).then(
      () => undefined,
      (err: unknown) => err
    )
    expect(error).toBeInstanceOf(ClientAnnexGenerationUnavailableError)
    expect((error as ClientAnnexGenerationUnavailableError).reason).toBe(
      'update-key-not-attributable'
    )
    // The pre-flight fired before any Space or annex resource existed.
    expect(world.server.calls).toEqual([])
    expect(world.server.spaces.size).toBe(0)
    expect(world.account.log()).toBe(logBefore)
  })

  it('a healthy account is a pure no-op report', async () => {
    const world = await healWorld()
    const now = Date.now()
    const old = await publishPointedGeneration({ world, now })
    const sibling = await mintSibling({ world, now })
    const accountEntriesBefore = (await world.accountView()).log.length
    world.accountPuts.length = 0
    world.server.calls.length = 0

    const { outcome, rebound } = await runEnsure({
      world,
      delegatedClients: sibling,
      now: now + 1000
    })
    expect(outcome).toEqual({
      clientAnnexDid: old.did,
      generationDelegation: old.delegation,
      delegatedClients: sibling,
      generationMinted: false,
      spaceMinted: false,
      delegationRenewed: false,
      siblingReminted: false
    })
    expect(rebound).toEqual([])
    // Reads only: no write reached the server or the account log.
    expect(world.server.writeCalls()).toEqual([])
    expect(world.accountPuts).toEqual([])
    expect((await world.accountView()).log.length).toBe(accountEntriesBefore)
  })

  it('rung-uncommitted renewal falls through to a fresh mint', async () => {
    const world = await healWorld()
    // The pointed generation was minted by ANOTHER credential's ladder, and
    // never embedded a delegation: this credential's rung is neither revealed
    // nor committed there, so the renewal refuses and the ensure mints fresh.
    const old = await publishPointedGeneration({
      world,
      ladderSeed: OTHER_LADDER_SEED,
      installDelegation: false
    })
    const sibling = await mintSibling({ world })

    const { outcome } = await runEnsure({ world, delegatedClients: sibling })
    expect(outcome.generationMinted).toBe(true)
    expect(outcome.spaceMinted).toBe(false)
    expect(outcome.clientAnnexDid).not.toBe(old.did)
    expect(clientAnnexDidParts({ did: outcome.clientAnnexDid }).spaceId).toBe(
      AUX_SPACE_ID
    )
    const view = await world.accountView()
    expect(delegatedClientsPointer({ doc: view.doc })).toBe(
      outcome.clientAnnexDid
    )
  })

  it('a hard-expired foreign delegation: fresh mint, no revocation attempted', async () => {
    const world = await healWorld()
    const mintedAt = Date.now()
    // The pointed generation was minted by ANOTHER credential's ladder with
    // a delegation embedded; by heal time that delegation is hard-expired, so
    // the renewal is attempted, refuses on the uncommitted rung, and the
    // fresh-mint arm re-points. No revocation is POSTed for the superseded
    // delegation: a visit has no reach that could invoke it, and the pointer
    // move itself retires it on a conforming server.
    const foreign = await publishPointedGeneration({
      world,
      ladderSeed: OTHER_LADDER_SEED,
      installDelegation: true,
      now: mintedAt
    })
    // The sibling must outlive the heal clock a year out, so it is minted on
    // the same shifted clock.
    const now = mintedAt + GENERATION_DELEGATION_TTL_MS + 24 * 60 * 60 * 1000
    const sibling = await mintSibling({ world, now })

    const { outcome } = await runEnsure({
      world,
      delegatedClients: sibling,
      now
    })
    expect(outcome.generationMinted).toBe(true)
    expect(outcome.clientAnnexDid).not.toBe(foreign.did)
    expect(world.server.revocations).toEqual([])
    expect('oldDelegationRevoked' in outcome).toBe(false)
    const view = await world.accountView()
    expect(delegatedClientsPointer({ doc: view.doc })).toBe(
      outcome.clientAnnexDid
    )
  })

  it('a mis-targeted sibling is re-minted for the pointed Space and re-bound', async () => {
    const world = await healWorld()
    await publishPointedGeneration({ world })
    // The record's sibling targets some OTHER Space than the pointed one.
    const misTargeted = await mintSibling({
      world,
      spaceId: 'some-other-space'
    })

    const { outcome, rebound } = await runEnsure({
      world,
      delegatedClients: misTargeted
    })
    expect(outcome.siblingReminted).toBe(true)
    expect(outcome.generationMinted).toBe(false)
    expect(rebound).toEqual([outcome.delegatedClients])
    expect(outcome.delegatedClients).not.toBe(misTargeted)
    expect(
      delegatedClientsDelegationSpaceId({
        delegation: outcome.delegatedClients
      })
    ).toBe(AUX_SPACE_ID)
  })

  it('an expired sibling is re-minted and re-bound', async () => {
    const world = await healWorld()
    const now = Date.now()
    await publishPointedGeneration({ world, now })
    // Right Space, but its expiry has passed. Built by restamping a fresh
    // sibling's `expires` (the signer refuses to mint one already expired);
    // the staleness predicate reads the recorded expiry, not the proof.
    const fresh = await mintSibling({ world, now })
    const expired = {
      ...fresh,
      expires: new Date(now - 1000).toISOString()
    } as IZcap

    const { outcome, rebound } = await runEnsure({
      world,
      delegatedClients: expired,
      now
    })
    expect(outcome.siblingReminted).toBe(true)
    expect(outcome.generationMinted).toBe(false)
    expect(rebound).toEqual([outcome.delegatedClients])
    expect(outcome.delegatedClients).not.toBe(expired)
    expect(
      delegatedClientsDelegationSpaceId({
        delegation: outcome.delegatedClients
      })
    ).toBe(AUX_SPACE_ID)
  })

  it('a signer-rotted sibling is re-minted and re-bound', async () => {
    const world = await healWorld()
    await publishPointedGeneration({ world })
    // Signed by a ladder VM the account document does not list: the
    // current-key-set rule already killed it server-side.
    const rottedSigner = await ladderVmZcapClient({
      accountDid: world.did,
      ladderSeed: OTHER_LADDER_SEED
    })
    const rotted = await mintDelegatedClientsDelegation({
      zcapClient: rottedSigner,
      wasServerUrl: WAS_URL,
      clientAnnexSpaceId: AUX_SPACE_ID,
      controller: world.standingClient.did
    })

    const { outcome, rebound } = await runEnsure({
      world,
      delegatedClients: rotted
    })
    expect(outcome.siblingReminted).toBe(true)
    expect(rebound).toEqual([outcome.delegatedClients])
    expect(outcome.delegatedClients).not.toBe(rotted)
  })

  it('a run torn before the pointer entry converges on re-run', async () => {
    const world = await healWorld()
    await ensureClientAnnexSpace({
      was: world.server.was,
      spaceId: AUX_SPACE_ID,
      controller: world.did
    })
    const sibling = await mintSibling({ world })
    // The first account-log write (the pointer entry) dies once: the run is
    // torn after the generation mint, before the pointer.
    let tornOnce = false
    const tearingStore: WebvhIdStore = {
      ...world.idStore,
      async putIdResource(
        options: Parameters<WebvhIdStore['putIdResource']>[0]
      ) {
        if (!tornOnce) {
          tornOnce = true
          throw new Error('torn before the pointer entry')
        }
        return world.idStore.putIdResource(options)
      }
    }
    await expect(
      runEnsure({ world, delegatedClients: sibling, idStore: tearingStore })
    ).rejects.toThrow(/torn before the pointer entry/)
    // The tear left an unpointed (authorization-inert) generation.
    const tornView = await world.accountView()
    expect(delegatedClientsPointer({ doc: tornView.doc })).toBeUndefined()

    // The re-run converges: a generation is pointed, its delegation embedded
    // -- possibly a different fresh generation than the torn run's.
    const { outcome } = await runEnsure({ world, delegatedClients: sibling })
    expect(outcome.generationMinted).toBe(true)
    const view = await world.accountView()
    expect(delegatedClientsPointer({ doc: view.doc })).toBe(
      outcome.clientAnnexDid
    )
    const parts = clientAnnexDidParts({ did: outcome.clientAnnexDid })
    const published = await readPublishedLog({
      idStore: clientAnnexLogStore({
        was: world.server.was,
        spaceId: AUX_SPACE_ID,
        generationId: parts.generationId
      }) as WebvhIdStore
    })
    expect(embeddedGenerationDelegation({ doc: published!.doc })).toEqual(
      outcome.generationDelegation
    )
  })

  it("refuses ladder-vm-not-anchored for another credential's ladder on a client-less account", async () => {
    const world = await healWorld()
    // The account is anchored on LADDER_SEED's ladder; a standing credential
    // whose own ladder VM no ceremony ever published visits it.
    const logBefore = world.account.log()
    world.server.calls.length = 0
    const error = await runEnsure({
      world,
      ladderSeed: OTHER_LADDER_SEED
    }).then(
      () => undefined,
      (err: unknown) => err
    )
    expect(error).toBeInstanceOf(ClientAnnexGenerationUnavailableError)
    expect((error as ClientAnnexGenerationUnavailableError).reason).toBe(
      'ladder-vm-not-anchored'
    )
    expect(world.server.calls).toEqual([])
    expect(world.account.log()).toBe(logBefore)
  })

  it('setDelegatedClientsPointer advances the chain-head pin past its entry', async () => {
    const world = await healWorld()
    const minted = await mintCredentialClientAnnexGeneration({
      was: world.server.was,
      wasServerUrl: WAS_URL,
      spaceId: AUX_SPACE_ID,
      controller: world.did,
      ladderSeed: LADDER_SEED
    })
    const pinStore = memoryResourceLogPinStore()
    const logId = accountLogPinId({ spaceId: ACCOUNT_SPACE_ID })
    const rung0 = await ladderRung({ ladderSeed: LADDER_SEED, index: 0 })
    const rung1 = await ladderRung({ ladderSeed: LADDER_SEED, index: 1 })
    await setDelegatedClientsPointer({
      idStore: world.idStore,
      updateKeys: { updateSeed: rung0.seed, stagedSeed: rung1.seed },
      clientAnnexDid: minted.did,
      expectedDid: world.did,
      pinStore,
      logId,
      logOnly: true
    })
    // The pin names the entry the call just published, so a host serving the
    // pre-entry log straight afterwards is refused as a rollback.
    const view = await world.accountView()
    expect(await pinStore.read({ logId })).toEqual(pinOfLog(view.log))
  })

  it('throws a synchronous TypeError when onRebindRecord is omitted', async () => {
    const world = await healWorld()
    const view = await world.accountView()
    expect(() =>
      ensureCredentialClientAnnexGeneration({
        wasServerUrl: WAS_URL,
        spaceId: ACCOUNT_SPACE_ID,
        account: view,
        ladderSeed: LADDER_SEED,
        standingClient: world.standingClient,
        bootstrapWasFor: () => world.server.was,
        idStore: world.idStore,
        onRebindRecord: undefined as never
      })
    ).toThrow(TypeError)
  })
})
