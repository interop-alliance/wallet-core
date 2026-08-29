/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The account-genesis ceremony (`src/genesis/accountGenesis.ts`): the local
 * mint of a new account's key set, the promotion state machine over the Space
 * Description, and the full stage order -- Space provisioning, the optional
 * KMS key-map acquisition, did:webvh genesis, user-key roster genesis, the
 * encrypted collections' epoch[0] install, and the controller promotion.
 *
 * Driven with real key material (`agentsFromSeed` over the minted client seed,
 * `mintUserKey`, `mintClientWebvhUpdateKeys`) against in-memory fakes: the
 * shared `memoryIdStore` for the `id` / `key-map` resources -- so the genesis
 * mints and publishes a real, verifiable did:webvh log -- plus one stateful
 * was-client fake carrying the union of the surfaces the provisioning, the
 * epoch install and the promotion probe drive. What the suite pins is the
 * resumable-success contract: each collected stage's failure is reported
 * rather than thrown, and re-running the whole ceremony over the same durable
 * state adopts everything instead of extending the log or re-installing
 * epochs.
 */
import { describe, expect, it } from 'vitest'

import { readLogFromString } from '@interop/did-method-webvh'
import type { CollectionEncryption, WasClient } from '@interop/was-client'
import { PreconditionFailedError } from '@interop/was-client'
import type { EncryptionDescriptorStore } from '@interop/was-client/edv'

import {
  ensureAccountGenesis,
  ensurePromotedSpaceController,
  mintAccountKeySet,
  mintSpaceId,
  type AccountKeySet
} from '../../src/genesis/index.js'
import { agentsFromSeed } from '../../src/identity/index.js'
import {
  WALLET_SPACE_NAME,
  WALLET_SPACE_PROVISION_ROSTER
} from '../../src/space/index.js'
import type { DidWebKeyMapV2, ICapabilityAgent } from '../../src/webvh/index.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-genesis'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`

/**
 * The encrypted roster collections -- the ones epoch[0] lands on.
 */
const EDV_ROSTER_IDS = WALLET_SPACE_PROVISION_ROSTER.filter(
  spec => spec.encryption === 'edv'
).map(spec => spec.collectionId)

/**
 * The Collection Description fields the fake stores: what
 * `provisionWalletSpace` declares plus what the epoch install writes back.
 */
interface StoredDescription {
  name?: string
  encryption?: CollectionEncryption
}

/**
 * A stateful was-client fake carrying the union of the three surfaces the
 * ceremony drives: the Space Description (`describe` / `configure`, read by
 * the provisioning and by the promotion probe), the collection provisioning
 * surface (`describe` / `configure` / `isPublic` / `setPublic`), and the
 * Collection Description CAS surface the epoch install runs on
 * (`describeWithEtag` / `replaceDescription`). One run's writes are visible to
 * the next stage and to a re-run, which is what makes the idempotence cases
 * meaningful.
 *
 * @param [options] {object}
 * @param [options.failDescribeWithEtag] {Function}   throws on the Collection
 *   Description read of every matching collection -- the transient failure the
 *   epoch stage's partial outcome is about
 * @returns {object}   the `was` handle, the recorded calls, and a descriptor
 *   reader
 */
function fakeWas({
  failDescribeWithEtag
}: { failDescribeWithEtag?: (collectionId: string) => boolean } = {}) {
  let spaceDescription: { name?: string; controller?: string } | null = null
  const collections = new Map<
    string,
    { description: StoredDescription; version: number; isPublic: boolean }
  >()
  const calls = {
    spaceConfigures: [] as Array<{ name?: string; controller?: string }>,
    collectionConfigures: [] as string[],
    setPublics: [] as string[],
    replaces: [] as string[]
  }
  const was = {
    space: (spaceId: string) => {
      expect(spaceId).toBe(SPACE_ID)
      return {
        describe: async () =>
          spaceDescription ? { id: SPACE_ID, ...spaceDescription } : null,
        configure: async (options: { name?: string; controller?: string }) => {
          calls.spaceConfigures.push({ ...options })
          spaceDescription = { ...options }
          return { id: SPACE_ID, type: ['Space'], ...options }
        },
        collection: (collectionId: string) => ({
          describe: async () => {
            const entry = collections.get(collectionId)
            return entry ? structuredClone(entry.description) : null
          },
          configure: async (options: {
            name?: string
            encryption?: CollectionEncryption
          }) => {
            calls.collectionConfigures.push(collectionId)
            const entry = collections.get(collectionId)
            const description: StoredDescription = {
              name: options.name,
              ...(options.encryption ? { encryption: options.encryption } : {})
            }
            if (entry) {
              entry.description = description
              entry.version++
            } else {
              collections.set(collectionId, {
                description,
                version: 0,
                isPublic: false
              })
            }
          },
          isPublic: async () =>
            collections.get(collectionId)?.isPublic ?? false,
          setPublic: async () => {
            calls.setPublics.push(collectionId)
            const entry = collections.get(collectionId)
            if (entry) {
              entry.isPublic = true
            }
          },
          describeWithEtag: async () => {
            if (failDescribeWithEtag?.(collectionId)) {
              throw new Error(`Service unavailable for "${collectionId}".`)
            }
            const entry = collections.get(collectionId)
            return entry
              ? {
                  description: structuredClone(entry.description),
                  etag: `v${entry.version}`
                }
              : null
          },
          replaceDescription: async (
            description: StoredDescription,
            { ifMatch }: { ifMatch?: string }
          ) => {
            const entry = collections.get(collectionId)!
            if (ifMatch !== `v${entry.version}`) {
              throw new PreconditionFailedError('stale description etag')
            }
            entry.description = structuredClone(description)
            entry.version++
            calls.replaces.push(collectionId)
          }
        })
      }
    }
  } as unknown as WasClient
  return {
    was,
    calls,
    controller: () => spaceDescription?.controller,
    descriptorOf: (collectionId: string) =>
      collections.get(collectionId)!.description.encryption!
  }
}

/**
 * An in-memory `EncryptionDescriptorStore` for the user-key roster, with an
 * optional one-shot write failure -- the torn-roster case the ceremony
 * collects as `{ stage: 'roster' }`.
 *
 * @param [options] {object}
 * @param [options.failFirstWrite] {boolean}   throws on the first `create` /
 *   `replace`, then behaves normally
 * @returns {EncryptionDescriptorStore}   plus a `_getDescriptor` reader
 */
function memoryDescriptorStore({
  failFirstWrite = false
}: { failFirstWrite?: boolean } = {}): EncryptionDescriptorStore & {
  _getDescriptor(): CollectionEncryption | null
} {
  let descriptor: CollectionEncryption | null = null
  let version = 0
  let pendingFailure = failFirstWrite
  const failOnce = () => {
    if (pendingFailure) {
      pendingFailure = false
      throw new Error('injected: the roster store is unavailable')
    }
  }
  return {
    async read() {
      return descriptor
        ? { descriptor: structuredClone(descriptor), etag: `v${version}` }
        : null
    },
    async replace(next, { ifMatch }: { ifMatch?: string }) {
      failOnce()
      if (ifMatch !== `v${version}`) {
        throw new PreconditionFailedError('stale descriptor etag')
      }
      descriptor = next
      version++
    },
    async create(next) {
      failOnce()
      if (descriptor) {
        throw new PreconditionFailedError('descriptor already exists')
      }
      descriptor = next
      version++
    },
    _getDescriptor() {
      return descriptor ? structuredClone(descriptor) : null
    }
  }
}

/**
 * The KMS key map a wallet keeping a KMS hands the genesis.
 */
function didWebKeyMap(): DidWebKeyMapV2 {
  return {
    authentication: { vmId: `${DID_WEB}#z6MkAuth`, kmsKeyId: 'kms/keys/auth' },
    keyAgreement: { vmId: `${DID_WEB}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
  }
}

/**
 * The founding client: its minted key set plus the real agents derived from
 * the set's client seed.
 */
async function foundingClient(): Promise<{
  keySet: AccountKeySet
  keyAgent: ICapabilityAgent
  clientKeyAgreementKey: Awaited<
    ReturnType<typeof agentsFromSeed>
  >['keyAgreementKey']
}> {
  const keySet = await mintAccountKeySet()
  const { keyAgent, keyAgreementKey } = await agentsFromSeed({
    seed: keySet.clientSeed
  })
  return { keySet, keyAgent, clientKeyAgreementKey: keyAgreementKey }
}

/**
 * The number of entries in the published did:webvh log -- what the adoption
 * assertions compare across a re-run.
 */
function logLength(log: string | undefined): number {
  return readLogFromString(log!).length
}

describe('mintSpaceId / mintAccountKeySet', () => {
  it('mints a 43-character Space id, fresh each call', () => {
    const spaceId = mintSpaceId()
    // 32 random bytes, base64url with no padding.
    expect(spaceId).toHaveLength(43)
    expect(spaceId).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(mintSpaceId()).not.toBe(spaceId)
  })

  it('mints the complete key set: Space id, client seed, user key, update keys', async () => {
    const keySet = await mintAccountKeySet()

    expect(keySet.spaceId).toHaveLength(43)
    expect(keySet.clientSeed).toHaveLength(32)
    expect(keySet.userKey.id.startsWith('did:key:')).toBe(true)
    expect(keySet.userKey.secret).toHaveLength(32)
    expect(keySet.userKey.signingSeed).toHaveLength(32)
    // The two client-held did:webvh seeds are distinct, with nothing staged
    // mid-rotation.
    expect(keySet.updateKeys.updateSeed).toHaveLength(32)
    expect(keySet.updateKeys.stagedSeed).toHaveLength(32)
    expect(keySet.updateKeys.updateSeed).not.toEqual(
      keySet.updateKeys.stagedSeed
    )
    expect(keySet.updateKeys.pendingStagedSeed).toBeUndefined()

    // Nothing is shared between the account-wide user key and this client's
    // own identity seed.
    expect(keySet.userKey.secret).not.toEqual(keySet.clientSeed)
  })
})

describe('ensurePromotedSpaceController', () => {
  const did = 'did:webvh:zScid:localhost%3A8080:space:space-genesis:id'

  /**
   * A minimal Space-Description fake: what `describe` serves, and every
   * `configure` it records.
   */
  function spaceFake(
    description: { name?: string; controller?: string } | null
  ) {
    const configures: Array<{ name?: string; controller?: string }> = []
    const was = {
      space: (spaceId: string) => ({
        describe: async () =>
          description ? { id: spaceId, ...description } : null,
        configure: async (options: { name?: string; controller?: string }) => {
          configures.push(options)
          return { id: spaceId, type: ['Space'], ...options }
        }
      })
    } as unknown as WasClient
    return { was, configures }
  }

  it('confirms a Space already naming the account DID, writing nothing', async () => {
    const { was, configures } = spaceFake({
      name: WALLET_SPACE_NAME,
      controller: did
    })

    expect(
      await ensurePromotedSpaceController({ was, spaceId: SPACE_ID, did })
    ).toBe('confirmed')
    expect(configures).toEqual([])
  })

  it('promotes a Space still naming this client did:key', async () => {
    const { was, configures } = spaceFake({
      name: WALLET_SPACE_NAME,
      controller: 'did:key:zFoundingClient'
    })

    expect(
      await ensurePromotedSpaceController({ was, spaceId: SPACE_ID, did })
    ).toBe('promoted')
    // The PUT always carries the full description, so no field is defaulted
    // from a state the ceremony cannot see.
    expect(configures).toEqual([{ name: WALLET_SPACE_NAME, controller: did }])
  })

  it('heals an unreadable Description through the did:key-signed client', async () => {
    const { was, configures } = spaceFake(null)
    const asClient = spaceFake({ name: WALLET_SPACE_NAME, controller: did })

    expect(
      await ensurePromotedSpaceController({
        was,
        wasAsClient: asClient.was,
        spaceId: SPACE_ID,
        did
      })
    ).toBe('healed')
    expect(configures).toEqual([])
    expect(asClient.configures).toEqual([
      { name: WALLET_SPACE_NAME, controller: did }
    ])
  })

  it('refuses to heal with no did:key-signed client supplied', async () => {
    const { was } = spaceFake(null)

    await expect(
      ensurePromotedSpaceController({ was, spaceId: SPACE_ID, did })
    ).rejects.toThrow(/no did:key-signed client was supplied/)
  })
})

describe('ensureAccountGenesis (fresh, client-keys-only)', () => {
  it('provisions, publishes a did:webvh, seeds the roster and epochs, and promotes', async () => {
    const { keySet, keyAgent, clientKeyAgreementKey } = await foundingClient()
    const fakes = memoryIdStore()
    const keysBefore = fakes.keys()
    const store = memoryDescriptorStore()
    const rosterDids: string[] = []
    const { was, calls, controller, descriptorOf } = fakeWas()
    const published: string[] = []

    const result = await ensureAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      keyAgent,
      clientKeyAgreementKey,
      userKey: keySet.userKey,
      updateKeys: keySet.updateKeys,
      idStore: fakes.idStore,
      rosterStoreFor: ({ did }) => {
        rosterDids.push(did)
        return store
      },
      onDidPublished: async ({ did }) => {
        published.push(did)
      }
    })

    expect(result.failed).toEqual([])
    expect(result.did.startsWith('did:webvh:')).toBe(true)
    expect(published).toEqual([result.did])
    // The roster store is built for the DID the genesis just published.
    expect(rosterDids).toEqual([result.did])

    // The client-keys-only genesis writes no keys.json at all: the record
    // exists to bind relations to KMS keys, and there are none. Object
    // identity is the proof of "never written".
    expect(fakes.keys()).toBe(keysBefore)
    expect(fakes.keys()).toEqual({})
    // A real log, with its did:web projection alongside.
    expect(logLength(fakes.log())).toBe(1)
    expect(fakes.didDocument()).toBeTruthy()

    // Every roster collection was provisioned before anything else ran.
    expect([...calls.collectionConfigures].sort()).toEqual(
      WALLET_SPACE_PROVISION_ROSTER.map(spec => spec.collectionId).sort()
    )

    // The roster's current epoch IS the user key, wrapped to this client's own
    // key-agreement key.
    expect(result.rosterDescriptor!.currentEpoch).toBe(keySet.userKey.id)
    expect(result.rosterDescriptor!.epochs).toHaveLength(1)
    expect(
      result.rosterDescriptor!.epochs![0]!.recipients.map(
        entry => entry.header.kid
      )
    ).toEqual([clientKeyAgreementKey.id])
    expect(store._getDescriptor()).toEqual(result.rosterDescriptor)

    // epoch[0] landed on every encrypted roster collection, freshly installed.
    expect(result.epochs!.failed).toEqual([])
    expect(Object.keys(result.epochs!.outcomes).sort()).toEqual(
      [...EDV_ROSTER_IDS].sort()
    )
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(result.epochs!.outcomes[collectionId]!.installed).toBe(true)
      const descriptor = descriptorOf(collectionId)
      expect(descriptor.epochs).toHaveLength(1)
      expect(descriptor.currentEpoch).toBe(descriptor.epochs![0]!.id)
      // A fresh random epoch key, never the user-key generation itself.
      expect(descriptor.currentEpoch).not.toBe(keySet.userKey.id)
    }

    // The Space ends up controlled by the account DID.
    expect(result.promotion).toBe('promoted')
    expect(controller()).toBe(result.did)
  })

  it('is idempotent: a second full run adopts everything', async () => {
    const { keySet, keyAgent, clientKeyAgreementKey } = await foundingClient()
    const fakes = memoryIdStore()
    const store = memoryDescriptorStore()
    const { was, controller, descriptorOf } = fakeWas()
    const run = () =>
      ensureAccountGenesis({
        was,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        keyAgent,
        clientKeyAgreementKey,
        userKey: keySet.userKey,
        updateKeys: keySet.updateKeys,
        idStore: fakes.idStore,
        rosterStoreFor: () => store
      })

    const first = await run()
    const settledEpochs = EDV_ROSTER_IDS.map(collectionId =>
      structuredClone(descriptorOf(collectionId))
    )
    const entriesAfterFirst = logLength(fakes.log())

    const second = await run()

    expect(second.did).toBe(first.did)
    expect(second.failed).toEqual([])
    // The log is adopted, never extended.
    expect(logLength(fakes.log())).toBe(entriesAfterFirst)
    // The roster and the collection epochs are the first run's, untouched.
    expect(second.rosterDescriptor).toEqual(first.rosterDescriptor)
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(second.epochs!.outcomes[collectionId]!.installed).toBe(false)
    }
    expect(
      EDV_ROSTER_IDS.map(collectionId => descriptorOf(collectionId))
    ).toEqual(settledEpochs)
    // The controller is already the DID, so the promotion writes nothing.
    expect(second.promotion).toBe('confirmed')
    expect(controller()).toBe(first.did)
  })

  it('skips the promotion stage when the caller runs it itself', async () => {
    const { keySet, keyAgent, clientKeyAgreementKey } = await foundingClient()
    const fakes = memoryIdStore()
    const { was, calls, controller } = fakeWas()

    const result = await ensureAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      keyAgent,
      clientKeyAgreementKey,
      userKey: keySet.userKey,
      updateKeys: keySet.updateKeys,
      idStore: fakes.idStore,
      rosterStoreFor: () => memoryDescriptorStore(),
      promoteController: false
    })

    expect(result.failed).toEqual([])
    expect('promotion' in result).toBe(false)
    // The Space is still controlled by the founding client's did:key: no
    // configure named the account DID as controller.
    expect(
      calls.spaceConfigures.some(
        configure => configure.controller === result.did
      )
    ).toBe(false)
    expect(controller()).toBe(keyAgent.id)
  })

  it('raises the typed Space refusal when provisioning fails', async () => {
    const { keySet, keyAgent, clientKeyAgreementKey } = await foundingClient()
    const fakes = memoryIdStore()
    const { was } = fakeWas()
    // Every collection configure fails: the Space never comes up, so the
    // ceremony refuses with the stable-named class instead of proceeding (or
    // collecting) -- the refusal a caller that treats later stages as
    // non-fatal still propagates.
    const brokenWas = {
      space: (spaceId: string) => {
        const space = (was as unknown as { space: (id: string) => any }).space(
          spaceId
        )
        return {
          ...space,
          collection: (collectionId: string) => ({
            ...space.collection(collectionId),
            configure: async () => {
              throw new Error('injected: provisioning is down')
            }
          })
        }
      }
    } as unknown as WasClient

    const attempt = ensureAccountGenesis({
      was: brokenWas,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      keyAgent,
      clientKeyAgreementKey,
      userKey: keySet.userKey,
      updateKeys: keySet.updateKeys,
      idStore: fakes.idStore,
      rosterStoreFor: () => memoryDescriptorStore()
    })
    await expect(attempt).rejects.toMatchObject({
      name: 'AccountGenesisSpaceError'
    })
    // Nothing downstream ran: no did:webvh log was published.
    expect(fakes.log()).toBeUndefined()
  })
})

describe('ensureAccountGenesis (KMS-backed)', () => {
  it('records the webvh block in keys.json and acquires the map after Space provisioning', async () => {
    const { keySet, keyAgent, clientKeyAgreementKey } = await foundingClient()
    const fakes = memoryIdStore()
    const { was, calls } = fakeWas()
    let collectionsAtAcquisition = -1

    const result = await ensureAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      keyAgent,
      clientKeyAgreementKey,
      userKey: keySet.userKey,
      updateKeys: keySet.updateKeys,
      idStore: fakes.idStore,
      rosterStoreFor: () => memoryDescriptorStore(),
      provideDidWebKeys: async () => {
        // The KMS key map is acquired only once the Space it writes into
        // exists: the whole roster is provisioned by now.
        collectionsAtAcquisition = calls.collectionConfigures.length
        return didWebKeyMap()
      }
    })

    expect(result.failed).toEqual([])
    expect(collectionsAtAcquisition).toBe(WALLET_SPACE_PROVISION_ROSTER.length)

    // keys.json now carries the narrowed webvh block beside the KMS bindings.
    const keys = fakes.keys() as DidWebKeyMapV2
    expect(keys.webvh).toEqual({ did: result.did })
    expect(keys.authentication).toEqual(didWebKeyMap().authentication)
    expect(result.promotion).toBe('promoted')
  })

  it('degrades to the client-keys-only genesis when the key map throws', async () => {
    const { keySet, keyAgent, clientKeyAgreementKey } = await foundingClient()
    const fakes = memoryIdStore()
    const keysBefore = fakes.keys()
    const { was, controller, descriptorOf } = fakeWas()

    const result = await ensureAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      keyAgent,
      clientKeyAgreementKey,
      userKey: keySet.userKey,
      updateKeys: keySet.updateKeys,
      idStore: fakes.idStore,
      rosterStoreFor: () => memoryDescriptorStore(),
      provideDidWebKeys: async () => {
        throw new Error('injected: the KMS is unreachable')
      }
    })

    // The one collected stage; everything downstream still landed.
    expect(result.failed).toHaveLength(1)
    expect(result.failed[0]!.stage).toBe('didWebKeys')
    expect((result.failed[0]!.error as Error).message).toContain('injected')
    expect(result.did.startsWith('did:webvh:')).toBe(true)
    expect(fakes.keys()).toBe(keysBefore)
    expect(result.rosterDescriptor!.currentEpoch).toBe(keySet.userKey.id)
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(result.epochs!.outcomes[collectionId]!.installed).toBe(true)
      expect(descriptorOf(collectionId).epochs).toHaveLength(1)
    }
    expect(result.promotion).toBe('promoted')
    expect(controller()).toBe(result.did)
  })
})

describe('ensureAccountGenesis (a torn run heals by re-running)', () => {
  it('collects the roster failure, lands the rest, and converges on the re-run', async () => {
    const { keySet, keyAgent, clientKeyAgreementKey } = await foundingClient()
    const fakes = memoryIdStore()
    const { was, controller, descriptorOf } = fakeWas()
    // The roster store fails its first write, then behaves. Both runs share it,
    // exactly as the durable state is shared.
    const store = memoryDescriptorStore({ failFirstWrite: true })
    const run = () =>
      ensureAccountGenesis({
        was,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        keyAgent,
        clientKeyAgreementKey,
        userKey: keySet.userKey,
        updateKeys: keySet.updateKeys,
        idStore: fakes.idStore,
        rosterStoreFor: () => store
      })

    const torn = await run()

    // The roster stage is a collected failure, not a throw: the account exists
    // and is identified, and the later stages ran anyway.
    expect(torn.failed).toHaveLength(1)
    expect(torn.failed[0]!.stage).toBe('roster')
    expect(torn.rosterDescriptor).toBeUndefined()
    expect(store._getDescriptor()).toBeNull()
    expect(torn.did.startsWith('did:webvh:')).toBe(true)
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(torn.epochs!.outcomes[collectionId]!.installed).toBe(true)
    }
    expect(torn.promotion).toBe('promoted')

    const entriesAfterTorn = logLength(fakes.log())
    const settledEpochs = EDV_ROSTER_IDS.map(collectionId =>
      structuredClone(descriptorOf(collectionId))
    )

    const healed = await run()

    expect(healed.failed).toEqual([])
    expect(healed.did).toBe(torn.did)
    // The re-run adopts the published log rather than extending it.
    expect(logLength(fakes.log())).toBe(entriesAfterTorn)
    // The roster is initialized now, with the user key as its first epoch.
    expect(healed.rosterDescriptor!.currentEpoch).toBe(keySet.userKey.id)
    expect(
      healed.rosterDescriptor!.epochs![0]!.recipients.map(
        entry => entry.header.kid
      )
    ).toEqual([clientKeyAgreementKey.id])
    // The epochs the torn run installed are adopted untouched.
    for (const collectionId of EDV_ROSTER_IDS) {
      expect(healed.epochs!.outcomes[collectionId]!.installed).toBe(false)
    }
    expect(
      EDV_ROSTER_IDS.map(collectionId => descriptorOf(collectionId))
    ).toEqual(settledEpochs)
    // The controller promotion the torn run already landed is confirmed.
    expect(healed.promotion).toBe('confirmed')
    expect(controller()).toBe(torn.did)
  })

  it('collects an epoch-stage failure without costing the caller the rest', async () => {
    const { keySet, keyAgent, clientKeyAgreementKey } = await foundingClient()
    const fakes = memoryIdStore()
    // Every Collection Description read fails, so the fan-out reports each
    // collection rather than settling one.
    const { was, controller } = fakeWas({ failDescribeWithEtag: () => true })

    const result = await ensureAccountGenesis({
      was,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      keyAgent,
      clientKeyAgreementKey,
      userKey: keySet.userKey,
      updateKeys: keySet.updateKeys,
      idStore: fakes.idStore,
      rosterStoreFor: () => memoryDescriptorStore()
    })

    // The fan-out's own failures stay inside the epochs result -- the stage
    // itself ran, so nothing lands in `failed`.
    expect(result.failed).toEqual([])
    expect(result.epochs!.outcomes).toEqual({})
    expect(
      result.epochs!.failed.map(entry => entry.collectionId).sort()
    ).toEqual([...EDV_ROSTER_IDS].sort())
    expect(result.rosterDescriptor!.currentEpoch).toBe(keySet.userKey.id)
    expect(result.promotion).toBe('promoted')
    expect(controller()).toBe(result.did)
  })
})
