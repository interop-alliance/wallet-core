/**
 * Unit tests for the forget ceremony (`src/unlock/forget.ts`) over a real
 * in-memory did:webvh log and real epoch crypto: the pre-edit roster rotation
 * off the forgetting client's own wrap (the fresh key read back through the
 * credential's standing wrap), the collection fan-out, the atomic removal
 * entry, convergence under a naive re-run, the graceful no-roster completion,
 * and the last-durable-client refusal firing BEFORE anything rotates.
 */
import { describe, expect, it } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  epochKeyIdFor,
  initRecipients,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import {
  defaultWebvhLogVerifier,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { forgetDurableClient } from '../../src/clientAnnex/forget.js'
import { generateLadderSeed, ladderRung } from '../../src/clientAnnex/ladder.js'
import {
  LastDurableClientForgetError,
  selfEnrollWebvhClient
} from '../../src/clientAnnex/ladderAnchored.js'
import { publishUnlockKey } from '../../src/unlock/standingWebvh.js'
import type { StandingUnlockKeys } from '../../src/unlock/standingWebvh.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  rosterRecipientKid
} from '../../src/keys/userKeyRoster.js'
import { userKeyAsRecipient } from '../../src/keys/userKeyCascade.js'
import {
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import {
  memoryResourceLogPinStore,
  ResourceLogContinuityError
} from '@interop/vh-resource-log'
import { pinOfLog } from '../../src/webvh/didWebvh.js'
import { accountLogPinId } from '../../src/webvh/verifyLog.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { truncatingLogStore } from './fixtures/truncatingLogStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-forget-ceremony'

/**
 * An in-memory descriptor store with a write counter and create-if-absent.
 *
 * @param [initial] {CollectionEncryption}
 * @returns {object}
 */
function memoryStore(
  initial?: CollectionEncryption
): EncryptionDescriptorStore & {
  state: { descriptor?: CollectionEncryption }
  writes: number
} {
  const holder = {
    state: { descriptor: initial },
    writes: 0,
    async read() {
      return holder.state.descriptor
        ? { descriptor: holder.state.descriptor, etag: '"v"' }
        : null
    },
    async replace(descriptor: CollectionEncryption) {
      holder.state.descriptor = descriptor
      holder.writes += 1
    },
    async create(descriptor: CollectionEncryption) {
      holder.state.descriptor = descriptor
      holder.writes += 1
    }
  }
  return holder
}

/**
 * A real X25519 key-agreement key in the self-describing did:key form.
 *
 * @returns {Promise<IKeyAgreementKey & { publicKeyMultibase: string }>}
 */
async function makeKak(): Promise<
  IKeyAgreementKey & { publicKeyMultibase: string }
> {
  const kak = await X25519KeyAgreementKey2020.generate()
  const did = `did:key:${kak.publicKeyMultibase}`
  kak.controller = did
  kak.id = `${did}#${kak.publicKeyMultibase}`
  return kak as IKeyAgreementKey & { publicKeyMultibase: string }
}

/**
 * The account log's pin slot for this suite's fixtures.
 */
const LOG_ID = accountLogPinId({ spaceId: SPACE_ID })

/**
 * A full forget-shaped account: a provisioned log with client A, a bound
 * standing credential (its key-agreement key REAL, published as a
 * commitment), a self-enrolled second client B (the remembered browser the
 * forget removes), and a roster wrapping the user key to the credential and
 * to B.
 */
async function forgetFixture() {
  const { idStore, log } = memoryIdStore()
  const updateKeys = await mintClientWebvhUpdateKeys()
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
    updateKeys
  })

  const ladderSeed = generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const credentialKak = await makeKak()
  const unlockKeys: StandingUnlockKeys = {
    keyAgreement: {
      commitment: await keyAgreementCommitment({
        keyAgreementKeyMultibase: credentialKak.publicKeyMultibase
      })
    },
    updateKeyMultibase: rung0.keyMultibase
  }
  await publishUnlockKey({ idStore, updateKeys, unlockKeys })

  const enrolledSeeds = await mintClientWebvhUpdateKeys()
  const enrolledKeys = {
    ...CANONICAL_CLIENT_KEYS[3]!,
    updateKeyMultibase: await updateKeyMultibase({
      seed: enrolledSeeds.updateSeed
    }),
    stagedUpdateKeyMultibase: await updateKeyMultibase({
      seed: enrolledSeeds.stagedSeed
    })
  }
  await selfEnrollWebvhClient({
    store: idStore,
    ladderSeed,
    newClientKeys: enrolledKeys,
    newClientUpdateSeeds: enrolledSeeds,
    expectedDid: did
  })

  const userKey = await mintUserKey()
  const rosterStore = memoryStore()
  await ensureUserKeyRoster({
    store: rosterStore,
    userKey,
    clientKeyAgreementKey: credentialKak
  })
  const forgottenKid = rosterRecipientKid({
    signingKeyMultibase: enrolledKeys.signingKeyMultibase,
    keyAgreementKeyMultibase: enrolledKeys.keyAgreementKeyMultibase
  })
  await addUserKeyRosterRecipient({
    store: rosterStore,
    recipient: {
      id: forgottenKid,
      publicKeyMultibase: enrolledKeys.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: credentialKak
  })

  return {
    idStore,
    log,
    did,
    ladderSeed,
    credentialKak,
    enrolledKeys,
    userKey,
    rosterStore,
    forgottenKid,
    forgottenClient: {
      signingKeyMultibase: enrolledKeys.signingKeyMultibase,
      updateKeyMultibase: enrolledKeys.updateKeyMultibase
    }
  }
}

describe('forgetDurableClient', () => {
  it('rotates off the forgotten wrap, cascades, and publishes the removal', async () => {
    const fixture = await forgetFixture()
    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [userKeyAsRecipient({ userKey: fixture.userKey })]
    })
    const adopted: Array<{ userKey: { id: string } }> = []
    const entriesBefore = readLogFromString(fixture.log()!).length

    const result = await forgetDurableClient({
      logStore: fixture.idStore,
      ladderSeed: fixture.ladderSeed,
      forgottenClient: fixture.forgottenClient,
      forgottenKeyAgreementKeyMultibase:
        fixture.enrolledKeys.keyAgreementKeyMultibase,
      expectedDid: fixture.did,
      rosterStore: fixture.rosterStore,
      credentialKeyAgreementKey: fixture.credentialKak,
      userKey: fixture.userKey,
      onUserKeyAdopted: async entry => {
        adopted.push(entry)
      },
      collections: {
        collectionIds: ['private-credentials'],
        storeFor: () => collectionStore
      }
    })

    // The rotation retired the forgotten client's wrap and minted a fresh
    // key, adopted through the credential's standing wrap.
    expect(result.rotated).toBe(true)
    expect(result.userKey!.id).not.toBe(fixture.userKey.id)
    expect(adopted).toHaveLength(1)
    const fresh = result.rosterDescriptor!.epochs!.find(
      epoch => epoch.id === result.rosterDescriptor!.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([
      fixture.credentialKak.id
    ])

    // The collection re-epoch'd onto the fresh key.
    expect(result.collections.outcomes['private-credentials']).toBe('rotated')
    expect(result.collections.failed).toEqual([])
    const collectionEpoch = collectionStore.state.descriptor!.epochs!.find(
      epoch => epoch.id === collectionStore.state.descriptor!.currentEpoch
    )!
    expect(collectionEpoch.recipients.map(entry => entry.header.kid)).toContain(
      epochKeyIdFor(result.userKey!.id)
    )

    // The removal entry landed as ONE entry and the log still verifies.
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore + 1)
    const resolvedState = await resolveDIDFromLog(
      readLogFromString(fixture.log()!),
      { verifier: defaultWebvhLogVerifier }
    )
    expect(resolvedState.meta.error).toBeUndefined()
    expect(resolvedState.doc?.capabilityInvocation ?? []).not.toContain(
      `${fixture.did}#${fixture.enrolledKeys.signingKeyMultibase}`
    )
    expect(resolvedState.meta.updateKeys).not.toContain(
      fixture.enrolledKeys.updateKeyMultibase
    )

    // A naive full re-run converges: the wrap is already gone, the
    // collection is already current, the entry is already published.
    const rerun = await forgetDurableClient({
      logStore: fixture.idStore,
      ladderSeed: fixture.ladderSeed,
      forgottenClient: fixture.forgottenClient,
      forgottenKeyAgreementKeyMultibase:
        fixture.enrolledKeys.keyAgreementKeyMultibase,
      expectedDid: fixture.did,
      rosterStore: fixture.rosterStore,
      credentialKeyAgreementKey: fixture.credentialKak,
      collections: {
        collectionIds: ['private-credentials'],
        storeFor: () => collectionStore
      }
    })
    expect(rerun.rotated).toBe(false)
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore + 1)
  })

  it('completes with nothing rotated on an account with no roster', async () => {
    const fixture = await forgetFixture()
    const emptyRoster = memoryStore()

    const result = await forgetDurableClient({
      logStore: fixture.idStore,
      ladderSeed: fixture.ladderSeed,
      forgottenClient: fixture.forgottenClient,
      forgottenKeyAgreementKeyMultibase:
        fixture.enrolledKeys.keyAgreementKeyMultibase,
      expectedDid: fixture.did,
      rosterStore: emptyRoster,
      credentialKeyAgreementKey: fixture.credentialKak,
      collections: { collectionIds: [], storeFor: () => memoryStore() }
    })

    expect(result.rotated).toBe(false)
    expect(result.userKey).toBeUndefined()
    expect(emptyRoster.writes).toBe(0)
    const resolvedState = await resolveDIDFromLog(
      readLogFromString(fixture.log()!),
      { verifier: defaultWebvhLogVerifier }
    )
    expect(resolvedState.doc?.capabilityInvocation ?? []).not.toContain(
      `${fixture.did}#${fixture.enrolledKeys.signingKeyMultibase}`
    )
  })

  it('refuses the last enrolled durable client before anything rotates', async () => {
    const { idStore } = memoryIdStore()
    const updateKeys = await mintClientWebvhUpdateKeys()
    const { did } = await ensureDidWebvh({
      idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
      updateKeys
    })
    const ladderSeed = generateLadderSeed()
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    const credentialKak = await makeKak()
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: {
        keyAgreement: {
          commitment: await keyAgreementCommitment({
            keyAgreementKeyMultibase: credentialKak.publicKeyMultibase
          })
        },
        updateKeyMultibase: rung0.keyMultibase
      }
    })
    const userKey = await mintUserKey()
    const rosterStore = memoryStore()
    await ensureUserKeyRoster({
      store: rosterStore,
      userKey,
      clientKeyAgreementKey: credentialKak
    })
    const writesBefore = rosterStore.writes

    await expect(
      forgetDurableClient({
        logStore: idStore as WebvhIdStore,
        ladderSeed,
        forgottenClient: {
          signingKeyMultibase: CANONICAL_CLIENT_KEYS[0].signingKeyMultibase,
          updateKeyMultibase: await updateKeyMultibase({
            seed: updateKeys.updateSeed
          })
        },
        forgottenKeyAgreementKeyMultibase:
          CANONICAL_CLIENT_KEYS[0].keyAgreementKeyMultibase,
        expectedDid: did,
        rosterStore,
        credentialKeyAgreementKey: credentialKak,
        userKey,
        collections: { collectionIds: [], storeFor: () => memoryStore() }
      })
    ).rejects.toThrow(LastDurableClientForgetError)
    // The refusal fired before the rotation: nothing was retired.
    expect(rosterStore.writes).toBe(writesBefore)
  })
  it('advances the chain-head pin to the removal entry it published', async () => {
    const fixture = await forgetFixture()
    const pinStore = memoryResourceLogPinStore()

    await forgetDurableClient({
      logStore: fixture.idStore,
      pinStore,
      logId: LOG_ID,
      ladderSeed: fixture.ladderSeed,
      forgottenClient: fixture.forgottenClient,
      forgottenKeyAgreementKeyMultibase:
        fixture.enrolledKeys.keyAgreementKeyMultibase,
      expectedDid: fixture.did,
      rosterStore: fixture.rosterStore,
      credentialKeyAgreementKey: fixture.credentialKak,
      userKey: fixture.userKey,
      collections: { collectionIds: [], storeFor: () => memoryStore() }
    })

    expect(await pinStore.read({ logId: LOG_ID })).toEqual(
      pinOfLog(readLogFromString(fixture.log()!))
    )
  })

  it('refuses a served prefix of the pinned log before anything rotates', async () => {
    const fixture = await forgetFixture()
    const pinStore = memoryResourceLogPinStore()
    // Pinned at the real head, then the host serves the log one entry short.
    await pinStore.write({
      logId: LOG_ID,
      pin: pinOfLog(readLogFromString(fixture.log()!))
    })
    const { store } = truncatingLogStore({
      idStore: fixture.idStore,
      dropEntries: 1
    })
    const writesBefore = fixture.rosterStore.writes
    const logBefore = fixture.log()

    let caught: unknown
    try {
      await forgetDurableClient({
        logStore: store,
        pinStore,
        logId: LOG_ID,
        ladderSeed: fixture.ladderSeed,
        forgottenClient: fixture.forgottenClient,
        forgottenKeyAgreementKeyMultibase:
          fixture.enrolledKeys.keyAgreementKeyMultibase,
        expectedDid: fixture.did,
        rosterStore: fixture.rosterStore,
        credentialKeyAgreementKey: fixture.credentialKak,
        userKey: fixture.userKey,
        collections: { collectionIds: [], storeFor: () => memoryStore() }
      })
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(ResourceLogContinuityError)
    expect((caught as ResourceLogContinuityError).reason).toBe('rollback')
    // Nothing rotated and nothing published.
    expect(fixture.rosterStore.writes).toBe(writesBefore)
    expect(fixture.log()).toBe(logBefore)
  })

  it('refuses a prefix served only to the removal entry read', async () => {
    const fixture = await forgetFixture()
    const pinStore = memoryResourceLogPinStore()
    await pinStore.write({
      logId: LOG_ID,
      pin: pinOfLog(readLogFromString(fixture.log()!))
    })
    // The orchestrator's pre-read sees the full log; the removal entry's own
    // read inside the conflict-retry loop is served the prefix.
    const { store, counter } = truncatingLogStore({
      idStore: fixture.idStore,
      dropEntries: 1,
      fromRead: 2
    })
    const writesBefore = fixture.rosterStore.writes
    const logBefore = fixture.log()

    let caught: unknown
    try {
      await forgetDurableClient({
        logStore: store,
        pinStore,
        logId: LOG_ID,
        ladderSeed: fixture.ladderSeed,
        forgottenClient: fixture.forgottenClient,
        forgottenKeyAgreementKeyMultibase:
          fixture.enrolledKeys.keyAgreementKeyMultibase,
        expectedDid: fixture.did,
        rosterStore: fixture.rosterStore,
        credentialKeyAgreementKey: fixture.credentialKak,
        userKey: fixture.userKey,
        collections: { collectionIds: [], storeFor: () => memoryStore() }
      })
    } catch (err) {
      caught = err
    }

    expect(caught).toBeInstanceOf(ResourceLogContinuityError)
    expect((caught as ResourceLogContinuityError).reason).toBe('rollback')
    expect(counter.reads).toBeGreaterThan(1)
    // The rotation ran (the removal entry comes last), but the removal entry
    // itself was never published.
    expect(fixture.rosterStore.writes).toBeGreaterThan(writesBefore)
    expect(fixture.log()).toBe(logBefore)
  })
})
