/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The generation delegation: the mint's permanent wire shape (the account
 * Space items subtree target with its load-bearing trailing slash, the full
 * closed action vocabulary, the bare client annex DID controller, the 365-day
 * expiry, the account-Space-rooted chain), the depth-3 App Connect chain
 * shape and the per-hop expires clamp, the annex-document service-entry
 * embedding (type-IRI dispatch, map-form endpoint byte-identical to the
 * delegate output, installed with the first transient VM and never by
 * genesis), and the renew-precedes-mint stage (in-place endpoint
 * replacement, rung-0 reveal, the mid-generation lockout refusal).
 */
import { describe, expect, it } from 'vitest'
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import type { ServiceEndpoint } from '@interop/did-method-webvh'
import type { IZcap } from '@interop/data-integrity-core'
import {
  collectionItems,
  collectionMeta,
  collectionPath,
  resourcePath,
  rootCapabilityId,
  spaceItems,
  spacePath,
  toUrl
} from '@interop/was-client/paths'
import {
  clientAnnexRung,
  generateLadderSeed,
  ladderVmKeyMultibase
} from '../../src/unlock/ladder.js'
import {
  clampGrantExpires,
  ClientAnnexRungUncommittedError,
  createClientAnnexLog,
  embeddedGenerationDelegation,
  enrollClientAnnexTransientClient,
  ensureGenerationDelegationCurrent,
  GENERATION_DELEGATION_ACTIONS,
  GENERATION_DELEGATION_SERVICE_TYPE,
  GENERATION_DELEGATION_TTL_MS,
  generationDelegationServiceEntry,
  mintGenerationDelegation,
  mintGenerationId
} from '../../src/webvh/clientAnnex.js'
import type { PublishedKeyDocument } from '../../src/webvh/listClients.js'
import { ZCAP_RENEWAL_WINDOW_MS } from '../../src/webvh/standingZcap.js'
import { putLogResource, updateKeySigner } from '../../src/webvh/didWebvh.js'
import { ladderVmZcapClient } from '../../src/webvh/zcap.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

/** A sub-path deployment, so the path-join discipline is pinned. */
const WAS_URL = 'https://storage.example/was'
const ACCOUNT_SPACE_ID = 'account-space-1'
const AUX_SPACE_ID = 'aux-space-1'
const ACCOUNT_DID = 'did:webvh:QmScidAccount:storage.example'

const DAY_MS = 24 * 60 * 60 * 1000

/**
 * A deterministic 32-byte ladder seed, so two derivations agree across
 * helpers.
 */
function fixedSeed(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}

const TRANSIENT_KEY = CANONICAL_CLIENT_KEYS[3]!.signingKeyMultibase
const SECOND_TRANSIENT_KEY = CANONICAL_CLIENT_KEYS[4]!.signingKeyMultibase

/**
 * Mints and publishes one annex generation into a fresh in-memory store:
 * credential A is the minting writer (its rung-0 key revealed at genesis),
 * credential B stands committed only.
 */
async function clientAnnexFixture() {
  const ladderSeedA = fixedSeed(11)
  const ladderSeedB = fixedSeed(22)
  const generationId = mintGenerationId()
  const rungA = await clientAnnexRung({ ladderSeed: ladderSeedA, generationId })
  const rungB = await clientAnnexRung({ ladderSeed: ladderSeedB, generationId })
  const hashA = await deriveNextKeyHash(rungA.keyMultibase)
  const hashB = await deriveNextKeyHash(rungB.keyMultibase)
  const created = await createClientAnnexLog({
    wasServerUrl: WAS_URL,
    spaceId: AUX_SPACE_ID,
    generationId,
    updateKeyPublicKeyMultibase: rungA.keyMultibase,
    nextKeyHashes: [hashA, hashB],
    signer: await updateKeySigner({ seed: rungA.seed })
  })
  const fixture = memoryIdStore()
  await putLogResource({
    store: fixture.idStore,
    log: created.log,
    ifNoneMatch: true
  })
  return {
    ladderSeedA,
    ladderSeedB,
    generationId,
    rungA,
    rungB,
    did: created.did,
    fixture
  }
}

/**
 * A counted mint closure over the ladder-VM signer, minting for the ACCOUNT
 * Space (optionally with a shifted clock, to install an already-expiring
 * delegation).
 */
function countedMint({
  ladderSeed,
  now
}: {
  ladderSeed: Uint8Array
  now?: number
}) {
  const calls: string[] = []
  const mint = async ({ clientAnnexDid }: { clientAnnexDid: string }) => {
    calls.push(clientAnnexDid)
    const zcapClient = await ladderVmZcapClient({
      accountDid: ACCOUNT_DID,
      ladderSeed
    })
    return mintGenerationDelegation({
      zcapClient,
      wasServerUrl: WAS_URL,
      spaceId: ACCOUNT_SPACE_ID,
      clientAnnexDid,
      ...(now !== undefined ? { now } : {})
    })
  }
  return { mint, calls }
}

/**
 * The service entries of the published annex document's latest entry.
 */
function publishedServices(
  fixture: ReturnType<typeof memoryIdStore>
): ServiceEndpoint[] {
  const text = fixture.log()
  if (text === undefined) {
    throw new Error('no log published')
  }
  const lines = text.trim().split('\n')
  const last = JSON.parse(lines[lines.length - 1]!) as {
    state: { service?: ServiceEndpoint[] }
  }
  return last.state.service ?? []
}

describe('mintGenerationDelegation', () => {
  it(
    'mints the permanent wire shape: subtree target, full vocabulary, ' +
      'bare client annex DID controller, 365-day expiry, account-Space root',
    async () => {
      const { did } = await clientAnnexFixture()
      const ladderSeed = generateLadderSeed()
      const zcapClient = await ladderVmZcapClient({
        accountDid: ACCOUNT_DID,
        ladderSeed
      })
      const now = Date.now()
      const delegation = (await mintGenerationDelegation({
        zcapClient,
        wasServerUrl: WAS_URL,
        spaceId: ACCOUNT_SPACE_ID,
        clientAnnexDid: did,
        now
      })) as IZcap & {
        expires: string
        allowedAction: string[]
        parentCapability: string
        proof: { verificationMethod: string; capabilityChain: unknown[] }
      }

      // The items subtree, trailing slash, joined onto the sub-path base.
      expect(delegation.invocationTarget).toBe(
        'https://storage.example/was/space/account-space-1/'
      )
      expect(delegation.invocationTarget.endsWith('/')).toBe(true)
      expect(delegation.allowedAction).toEqual([
        'GET',
        'HEAD',
        'POST',
        'PUT',
        'DELETE'
      ])
      expect(delegation.allowedAction).toEqual(GENERATION_DELEGATION_ACTIONS)
      expect(delegation.controller).toBe(did)

      // Rooted in the ACCOUNT Space's root zcap (the bare Space URL), so the
      // bare URL -- the Space Description PUT and the Space DELETE -- sits
      // outside the capability bytes while remaining the chain's root.
      const spaceUrl = toUrl({
        serverUrl: WAS_URL,
        path: spacePath(ACCOUNT_SPACE_ID)
      })
      expect(delegation.parentCapability).toBe(rootCapabilityId(spaceUrl))
      expect(delegation.proof.capabilityChain).toEqual([
        rootCapabilityId(spaceUrl)
      ])

      // 365 days out (ezcap stores second precision).
      expect(Date.parse(delegation.expires)).toBe(
        Math.floor((now + GENERATION_DELEGATION_TTL_MS) / 1000) * 1000
      )

      // Signed under the ladder VM's document id.
      expect(delegation.proof.verificationMethod).toBe(
        `${ACCOUNT_DID}#${await ladderVmKeyMultibase({ ladderSeed })}`
      )
    }
  )

  it('refuses a malformed client annex DID before delegating', async () => {
    const zcapClient = await ladderVmZcapClient({
      accountDid: ACCOUNT_DID,
      ladderSeed: generateLadderSeed()
    })
    await expect(
      mintGenerationDelegation({
        zcapClient,
        wasServerUrl: WAS_URL,
        spaceId: ACCOUNT_SPACE_ID,
        clientAnnexDid: 'did:webvh:QmX:host:space:aux:not-a-generation-id'
      })
    ).rejects.toThrow(/Not a generation id/)
  })
})

describe('the depth-3 App Connect chain', () => {
  it(
    'a grant under the delegation chains [root id string, the full ' +
      'embedded delegation object], expires clamped within the parent',
    async () => {
      const { did } = await clientAnnexFixture()
      const ladderSeed = generateLadderSeed()
      const zcapClient = await ladderVmZcapClient({
        accountDid: ACCOUNT_DID,
        ladderSeed
      })
      const delegation = await mintGenerationDelegation({
        zcapClient,
        wasServerUrl: WAS_URL,
        spaceId: ACCOUNT_SPACE_ID,
        clientAnnexDid: did
      })

      const grant = (await zcapClient.delegate({
        capability: delegation,
        invocationTarget: toUrl({
          serverUrl: WAS_URL,
          path: collectionPath(ACCOUNT_SPACE_ID, 'notes')
        }),
        controller: 'did:key:z6MkfEnrolledAppController',
        allowedActions: ['GET'],
        expires: clampGrantExpires({ ttlMs: 30 * DAY_MS, delegation })
      })) as IZcap & {
        expires: string
        parentCapability: string
        proof: { capabilityChain: unknown[] }
      }

      expect(grant.parentCapability).toBe(delegation.id)
      const chain = grant.proof.capabilityChain
      expect(chain).toHaveLength(2)
      const spaceUrl = toUrl({
        serverUrl: WAS_URL,
        path: spacePath(ACCOUNT_SPACE_ID)
      })
      expect(chain[0]).toBe(rootCapabilityId(spaceUrl))
      // All strings except the last, which embeds the parent whole.
      expect(chain[1]).toEqual(delegation)
      // Per-hop monotonicity holds by the clamp.
      expect(Date.parse(grant.expires)).toBeLessThanOrEqual(
        Date.parse((delegation as { expires?: string }).expires ?? '')
      )
    }
  )
})

describe('clampGrantExpires', () => {
  const delegationWith = (expires: string) => ({ expires }) as unknown as IZcap

  it('grants the full TTL when it fits inside the parent', () => {
    const now = Date.parse('2026-08-19T12:00:00Z')
    const parent = new Date(now + 200 * DAY_MS).toISOString()
    const expires = clampGrantExpires({
      ttlMs: 30 * DAY_MS,
      delegation: delegationWith(parent),
      now
    })
    expect(expires.getTime()).toBe(now + 30 * DAY_MS)
  })

  it('clamps a 365-day-class TTL to the parent expiry', () => {
    const now = Date.parse('2026-08-19T12:00:00Z')
    const parent = new Date(now + 200 * DAY_MS).toISOString()
    const expires = clampGrantExpires({
      ttlMs: 365 * DAY_MS,
      delegation: delegationWith(parent),
      now
    })
    expect(expires.toISOString()).toBe(parent)
  })

  it('refuses a parent with no parseable expiry', () => {
    expect(() =>
      clampGrantExpires({
        ttlMs: 30 * DAY_MS,
        delegation: {} as unknown as IZcap
      })
    ).toThrow(/no parseable/)
  })
})

describe('the service-entry embedding', () => {
  it('genesis carries no service entry (the SCID-circularity rule)', async () => {
    const { fixture } = await clientAnnexFixture()
    expect(publishedServices(fixture)).toEqual([])
  })

  it(
    'the first transient VM installs the delegation: type-IRI entry, ' +
      'map endpoint byte-identical to the delegate output',
    async () => {
      const { fixture, ladderSeedA, generationId, did } =
        await clientAnnexFixture()
      const { mint, calls } = countedMint({ ladderSeed: ladderSeedA })
      const { doc } = await enrollClientAnnexTransientClient({
        store: fixture.idStore,
        ladderSeed: ladderSeedA,
        generationId,
        transientKeyMultibase: TRANSIENT_KEY,
        mintGenerationDelegation: mint
      })
      expect(calls).toEqual([did])

      const services = publishedServices(fixture)
      expect(services).toHaveLength(1)
      const entry = services[0]!
      expect(entry.type).toBe(GENERATION_DELEGATION_SERVICE_TYPE)
      expect(entry.id).toBe(`${did}#generation-delegation`)

      const embedded = embeddedGenerationDelegation({ doc })
      expect(embedded).toBeDefined()
      // Byte-identical to what zcapClient.delegate produced: the embedded map
      // is the signed zcap itself, proof included.
      expect((embedded as unknown as { proof?: object }).proof).toBeDefined()
      expect(JSON.stringify(entry.serviceEndpoint)).toBe(
        JSON.stringify(embedded)
      )
      expect((embedded as { controller?: string }).controller).toBe(did)
    }
  )

  it('a later transient VM does not re-mint or disturb the entry', async () => {
    const { fixture, ladderSeedA, ladderSeedB, generationId } =
      await clientAnnexFixture()
    const first = countedMint({ ladderSeed: ladderSeedA })
    await enrollClientAnnexTransientClient({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      mintGenerationDelegation: first.mint
    })
    const installed = publishedServices(fixture)[0]!

    const second = countedMint({ ladderSeed: ladderSeedB })
    const { doc } = await enrollClientAnnexTransientClient({
      store: fixture.idStore,
      ladderSeed: ladderSeedB,
      generationId,
      transientKeyMultibase: SECOND_TRANSIENT_KEY,
      mintGenerationDelegation: second.mint
    })
    expect(second.calls).toEqual([])
    const services = publishedServices(fixture)
    expect(services).toEqual([installed])
    expect(doc.verificationMethod).toHaveLength(2)
  })

  it(
    'embeddedGenerationDelegation dispatches on the type IRI and ignores ' +
      'a non-map endpoint',
    async () => {
      const { did } = await clientAnnexFixture()
      const delegation = { id: 'urn:zcap:delegated:x' } as unknown as IZcap
      const doc = {
        id: did,
        service: [
          {
            id: `${did}#other`,
            type: 'https://w3id.org/byoe#DelegatedClients',
            serviceEndpoint:
              'did:webvh:QmOther:host:space:s:gen-aaaaaaaaaaaaaaaa'
          },
          generationDelegationServiceEntry({ clientAnnexDid: did, delegation })
        ]
      }
      expect(embeddedGenerationDelegation({ doc })).toEqual(delegation)
      const stringForm = {
        id: did,
        service: [
          {
            id: `${did}#generation-delegation`,
            type: GENERATION_DELEGATION_SERVICE_TYPE,
            serviceEndpoint: 'urn:zcap:delegated:x'
          }
        ]
      }
      expect(embeddedGenerationDelegation({ doc: stringForm })).toBeUndefined()
    }
  )
})

describe('ensureGenerationDelegationCurrent (renew precedes mint)', () => {
  it('hands back a standing delegation outside the renewal window', async () => {
    const { fixture, ladderSeedA, generationId } = await clientAnnexFixture()
    const install = countedMint({ ladderSeed: ladderSeedA })
    await enrollClientAnnexTransientClient({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      mintGenerationDelegation: install.mint
    })
    const logBefore = fixture.log()

    const renew = countedMint({ ladderSeed: ladderSeedA })
    const { delegation, renewed } = await ensureGenerationDelegationCurrent({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      mintGenerationDelegation: renew.mint
    })
    expect(renewed).toBe(false)
    expect(renew.calls).toEqual([])
    expect(fixture.log()).toBe(logBefore)
    expect(JSON.stringify(delegation)).toBe(
      JSON.stringify(publishedServices(fixture)[0]!.serviceEndpoint)
    )
  })

  it(
    'renews an expiring delegation in place: endpoint replaced, fragment ' +
      "and VMs preserved, the renewing credential's rung-0 key revealed",
    async () => {
      const { fixture, ladderSeedA, ladderSeedB, generationId, rungB, did } =
        await clientAnnexFixture()
      // Installed already inside the 30-day renewal window.
      const stale = countedMint({
        ladderSeed: ladderSeedA,
        now:
          Date.now() -
          (GENERATION_DELEGATION_TTL_MS - ZCAP_RENEWAL_WINDOW_MS / 2)
      })
      await enrollClientAnnexTransientClient({
        store: fixture.idStore,
        ladderSeed: ladderSeedA,
        generationId,
        transientKeyMultibase: TRANSIENT_KEY,
        mintGenerationDelegation: stale.mint
      })
      const staleEntry = publishedServices(fixture)[0]!

      // Credential B (committed only, never revealed) runs the renewal.
      const renew = countedMint({ ladderSeed: ladderSeedB })
      const { delegation, renewed } = await ensureGenerationDelegationCurrent({
        store: fixture.idStore,
        ladderSeed: ladderSeedB,
        generationId,
        mintGenerationDelegation: renew.mint
      })
      expect(renewed).toBe(true)
      expect(renew.calls).toEqual([did])

      const services = publishedServices(fixture)
      expect(services).toHaveLength(1)
      const entry = services[0]!
      expect(entry.id).toBe(staleEntry.id)
      expect(entry.type).toBe(GENERATION_DELEGATION_SERVICE_TYPE)
      expect(JSON.stringify(entry.serviceEndpoint)).toBe(
        JSON.stringify(delegation)
      )
      expect(JSON.stringify(entry.serviceEndpoint)).not.toBe(
        JSON.stringify(staleEntry.serviceEndpoint)
      )

      // The transient VM and B's reveal both stand on the renewed log.
      const text = fixture.log()!
      const last = JSON.parse(text.trim().split('\n').pop()!) as {
        parameters: { updateKeys?: string[] }
        state: { verificationMethod?: unknown[] }
      }
      expect(last.state.verificationMethod).toHaveLength(1)
      expect(last.parameters.updateKeys).toContain(rungB.keyMultibase)
    }
  )

  it('installs the entry when a visited generation somehow lost it', async () => {
    // No first-VM install (no closure passed at enrollment).
    const { fixture, ladderSeedA, generationId, did } =
      await clientAnnexFixture()
    await enrollClientAnnexTransientClient({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY
    })
    expect(publishedServices(fixture)).toEqual([])

    const install = countedMint({ ladderSeed: ladderSeedA })
    const { renewed } = await ensureGenerationDelegationCurrent({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      mintGenerationDelegation: install.mint
    })
    expect(renewed).toBe(true)
    expect(install.calls).toEqual([did])
    expect(publishedServices(fixture)).toHaveLength(1)
  })

  it('refuses an uncommitted credential (the mid-generation lockout)', async () => {
    const { fixture, ladderSeedA, generationId } = await clientAnnexFixture()
    // Installed already inside the renewal window, so the renewal path (not
    // the standing early return) is what the uncommitted credential hits.
    const stale = countedMint({
      ladderSeed: ladderSeedA,
      now:
        Date.now() - (GENERATION_DELEGATION_TTL_MS - ZCAP_RENEWAL_WINDOW_MS / 2)
    })
    await enrollClientAnnexTransientClient({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      mintGenerationDelegation: stale.mint
    })
    // Credential C: bound after genesis, its rung-0 hash committed nowhere.
    const uncommitted = countedMint({ ladderSeed: fixedSeed(33) })
    await expect(
      ensureGenerationDelegationCurrent({
        store: fixture.idStore,
        ladderSeed: fixedSeed(33),
        generationId,
        mintGenerationDelegation: uncommitted.mint
      })
    ).rejects.toThrow(ClientAnnexRungUncommittedError)
    // The rung refusal precedes the mint: nothing was delegated.
    expect(uncommitted.calls).toEqual([])
  })
})

describe('ensureGenerationDelegationCurrent (the signer-death axis)', () => {
  /**
   * A verified account document publishing exactly the given key multibases,
   * in the did:webvh spelling the delegation's proof names.
   *
   * @param multibases {string[]}
   * @returns {PublishedKeyDocument}
   */
  function accountDocumentWith(multibases: string[]): PublishedKeyDocument {
    return {
      verificationMethod: multibases.map(publicKeyMultibase => ({
        id: `${ACCOUNT_DID}#${publicKeyMultibase}`,
        publicKeyMultibase
      }))
    }
  }

  /**
   * A generation carrying an installed, non-expiring delegation signed by the
   * ladder VM of credential A's seed.
   */
  async function installedFixture() {
    const world = await clientAnnexFixture()
    const install = countedMint({ ladderSeed: world.ladderSeedA })
    await enrollClientAnnexTransientClient({
      store: world.fixture.idStore,
      ladderSeed: world.ladderSeedA,
      generationId: world.generationId,
      transientKeyMultibase: TRANSIENT_KEY,
      mintGenerationDelegation: install.mint
    })
    return {
      ...world,
      installedEntry: publishedServices(world.fixture)[0]!,
      signerKeyMultibase: await ladderVmKeyMultibase({
        ladderSeed: world.ladderSeedA
      })
    }
  }

  it('replaces a delegation whose signer the account document dropped', async () => {
    const { fixture, ladderSeedA, generationId, did, installedEntry } =
      await installedFixture()

    // The account document no longer lists the signing key: the durable
    // client that minted the delegation was revoked, or the ladder VM left.
    const renew = countedMint({ ladderSeed: ladderSeedA })
    const { delegation, renewed } = await ensureGenerationDelegationCurrent({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      mintGenerationDelegation: renew.mint,
      accountDoc: accountDocumentWith(['z6MkSomeOtherEnrolledClientKey'])
    })
    expect(renewed).toBe(true)
    expect(renew.calls).toEqual([did])

    // One replacement entry, the service-entry fragment preserved verbatim
    // and the endpoint swapped for the fresh delegation.
    const services = publishedServices(fixture)
    expect(services).toHaveLength(1)
    expect(services[0]!.id).toBe(installedEntry.id)
    expect(services[0]!.type).toBe(GENERATION_DELEGATION_SERVICE_TYPE)
    expect(JSON.stringify(services[0]!.serviceEndpoint)).toBe(
      JSON.stringify(delegation)
    )
    expect(JSON.stringify(services[0]!.serviceEndpoint)).not.toBe(
      JSON.stringify(installedEntry.serviceEndpoint)
    )
  })

  it('leaves a healthy delegation alone when the document still lists its signer', async () => {
    const {
      fixture,
      ladderSeedA,
      generationId,
      installedEntry,
      signerKeyMultibase
    } = await installedFixture()
    const logBefore = fixture.log()

    const renew = countedMint({ ladderSeed: ladderSeedA })
    const { delegation, renewed } = await ensureGenerationDelegationCurrent({
      store: fixture.idStore,
      ladderSeed: ladderSeedA,
      generationId,
      mintGenerationDelegation: renew.mint,
      accountDoc: accountDocumentWith([signerKeyMultibase])
    })
    expect(renewed).toBe(false)
    expect(renew.calls).toEqual([])
    expect(fixture.log()).toBe(logBefore)
    expect(JSON.stringify(delegation)).toBe(
      JSON.stringify(installedEntry.serviceEndpoint)
    )
  })
})

describe('the write-set floor lands inside the subtree', () => {
  // The zcap attenuation rule for a trailing-slash base: a child target is
  // covered iff it extends the base. The floor is the design doc's
  // 2026-08-18 inventory of every request a transient session must make.
  const subtree = toUrl({
    serverUrl: WAS_URL,
    path: spaceItems(ACCOUNT_SPACE_ID)
  })
  const covered = (url: string) => url.startsWith(subtree)

  it('covers every floor request class', () => {
    const floor = [
      // The roster read and the torn-rotation roster PUT.
      resourcePath(ACCOUNT_SPACE_ID, 'key-map', 'user-key.jsonl'),
      // Descriptor and /meta GETs.
      collectionMeta(ACCOUNT_SPACE_ID, 'private-credentials'),
      // Credential and app-key listings and bodies.
      collectionItems(ACCOUNT_SPACE_ID, 'private-credentials'),
      resourcePath(ACCOUNT_SPACE_ID, 'private-credentials', 'cid-abc'),
      // The app-connections app-key PUT (the wallet-internal exemption).
      resourcePath(ACCOUNT_SPACE_ID, 'app-connections', 'envelope-hash'),
      // The Login-activity PUT that gates delivery.
      resourcePath(ACCOUNT_SPACE_ID, 'wallet-activity', 'activity-1'),
      // Collection provisioning: a Description PUT on a name that does not
      // exist at delegation mint time.
      collectionPath(ACCOUNT_SPACE_ID, 'brand-new-app-collection'),
      // The cascade fan-out's per-collection Description GET + CAS PUT.
      collectionPath(ACCOUNT_SPACE_ID, 'contacts')
    ]
    for (const path of floor) {
      expect(covered(toUrl({ serverUrl: WAS_URL, path }))).toBe(true)
    }
  })

  it('excludes the bare Space URL (Description PUT, Space DELETE)', () => {
    const bare = toUrl({
      serverUrl: WAS_URL,
      path: spacePath(ACCOUNT_SPACE_ID)
    })
    expect(covered(bare)).toBe(false)
    // Another Space is out, prefix or not.
    expect(
      covered(toUrl({ serverUrl: WAS_URL, path: spacePath('account-space-2') }))
    ).toBe(false)
    // A sibling Space id sharing the string prefix is out: the slash is part
    // of the base.
    expect(
      covered(
        toUrl({ serverUrl: WAS_URL, path: spacePath('account-space-1x') })
      )
    ).toBe(false)
  })
})
