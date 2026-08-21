/**
 * Unit tests for the last-durable-client forget (`src/clientAnnex/forgetLast.ts`)
 * over a real in-memory did:webvh account log, a real annex generation log,
 * and real epoch crypto: the two-entry install-revoke-remove shape (the
 * both-present transitional state visible to the pre-removal seam), the
 * ladder-signed one-append roster rotation anchored at the install entry, the
 * history-walk revocations filtered to this ladder VM's still-unexpired
 * delegations, the forced ladder-signed delegation replacement, convergence
 * under a torn run's re-run, the not-last refusal, and the honest generation
 * skips (no pointer, uncommitted rung).
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
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { forgetLastDurableClient } from '../../src/clientAnnex/forgetLast.js'
import {
  clientAnnexRung,
  generateLadderSeed,
  ladderRung,
  ladderVmKeyMultibase
} from '../../src/clientAnnex/ladder.js'
import { selfEnrollWebvhClient } from '../../src/clientAnnex/ladderAnchored.js'
import {
  createClientAnnexLog,
  embeddedGenerationDelegation,
  ensureGenerationDelegationCurrent,
  mintGenerationDelegation,
  mintGenerationId,
  setDelegatedClientsPointer
} from '../../src/clientAnnex/log.js'
import { ladderVmZcapClient } from '../../src/clientAnnex/zcap.js'
import { publishUnlockKey } from '../../src/unlock/standingWebvh.js'
import type { StandingUnlockKeys } from '../../src/unlock/standingWebvh.js'
import { mintUserKey } from '../../src/keys/userKey.js'
import {
  addUserKeyRosterRecipient,
  ensureUserKeyRoster,
  rosterRecipientKid
} from '../../src/keys/userKeyRoster.js'
import { userKeyAsRecipient } from '../../src/keys/userKeyCascade.js'
import { ladderVmIds } from '../../src/webvh/listClients.js'
import type { DIDDoc } from '@interop/did-method-webvh'
import { delegationProofKeyId } from '../../src/webvh/standingZcap.js'
import {
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  putLogResource,
  relationIds,
  updateKeyMultibase,
  updateKeySigner
} from '../../src/webvh/didWebvh.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-forget-last-ceremony'
const AUX_SPACE_ID = 'aux-space-forget-last'

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
 * A last-client account with the annex reach: a provisioned log whose ONLY
 * enrolled durable client is A, a bound standing credential (commitment
 * posture, rung-0 hash committed), a pointed annex generation whose genesis
 * reveals this credential's annex rung, two embedded generation delegations
 * in the annex history (one signed by a FOREIGN ladder VM, then this
 * credential's own, which replaced it in the head entry), and a roster
 * wrapping the user key to the credential and to A.
 *
 * @param [options] {object}
 * @param [options.annexRungSeed] {Uint8Array}   the seed whose annex rung the
 *   generation's genesis reveals (defaults to the login credential's ladder
 *   seed; a different one makes the credential's rung uncommitted)
 * @param [options.withPointer] {boolean}
 * @returns {Promise<object>}
 */
async function forgetLastFixture(options?: {
  annexRungSeed?: Uint8Array
  withPointer?: boolean
}) {
  const withPointer = options?.withPointer ?? true
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

  // The annex generation: genesis reveals the writing credential's rung.
  const generationId = mintGenerationId()
  const annexRungSeed = options?.annexRungSeed ?? ladderSeed
  const annexRung = await clientAnnexRung({
    ladderSeed: annexRungSeed,
    generationId
  })
  const created = await createClientAnnexLog({
    wasServerUrl: WAS_URL,
    spaceId: AUX_SPACE_ID,
    generationId,
    updateKeyPublicKeyMultibase: annexRung.keyMultibase,
    nextKeyHashes: [await deriveNextKeyHash(annexRung.keyMultibase)],
    signer: await updateKeySigner({ seed: annexRung.seed })
  })
  const annexFixture = memoryIdStore()
  await putLogResource({
    store: annexFixture.idStore,
    log: created.log,
    ifNoneMatch: true
  })

  // Two delegations into the history: a foreign ladder VM's first (standing
  // in for authority this credential's forget must NOT revoke), then this
  // credential's own, replacing it in the head service entry.
  const foreignSeed = generateLadderSeed()
  const foreignClient = await ladderVmZcapClient({
    accountDid: did,
    ladderSeed: foreignSeed
  })
  const foreign = await ensureGenerationDelegationCurrent({
    store: annexFixture.idStore,
    ladderSeed: annexRungSeed,
    generationId,
    mintGenerationDelegation: async ({ clientAnnexDid }) =>
      mintGenerationDelegation({
        zcapClient: foreignClient,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        clientAnnexDid
      }),
    expectedDid: created.did
  })
  const ownClient = await ladderVmZcapClient({ accountDid: did, ladderSeed })
  const own = await ensureGenerationDelegationCurrent({
    store: annexFixture.idStore,
    ladderSeed: annexRungSeed,
    generationId,
    mintGenerationDelegation: async ({ clientAnnexDid }) =>
      mintGenerationDelegation({
        zcapClient: ownClient,
        wasServerUrl: WAS_URL,
        spaceId: SPACE_ID,
        clientAnnexDid
      }),
    expectedDid: created.did,
    force: true
  })

  if (withPointer) {
    await setDelegatedClientsPointer({
      idStore,
      updateKeys,
      clientAnnexDid: created.did,
      expectedDid: did
    })
  }

  const userKey = await mintUserKey()
  const rosterStore = memoryStore()
  await ensureUserKeyRoster({
    store: rosterStore,
    userKey,
    clientKeyAgreementKey: credentialKak
  })
  const clientKeys = CANONICAL_CLIENT_KEYS[0]
  const forgottenKid = rosterRecipientKid({
    signingKeyMultibase: clientKeys.signingKeyMultibase,
    keyAgreementKeyMultibase: clientKeys.keyAgreementKeyMultibase
  })
  await addUserKeyRosterRecipient({
    store: rosterStore,
    recipient: {
      id: forgottenKid,
      publicKeyMultibase: clientKeys.keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: credentialKak
  })

  return {
    idStore,
    log,
    did,
    ladderSeed,
    credentialKak,
    userKey,
    rosterStore,
    forgottenKid,
    annexIdStore: annexFixture.idStore,
    annexLog: annexFixture.log,
    annexDid: created.did,
    generationId,
    foreignDelegationId: (foreign.delegation as { id?: string }).id!,
    ownDelegationId: (own.delegation as { id?: string }).id!,
    forgottenClient: {
      signingKeyMultibase: clientKeys.signingKeyMultibase,
      updateKeyMultibase: await updateKeyMultibase({
        seed: updateKeys.updateSeed
      })
    },
    forgottenKeyAgreementKeyMultibase: clientKeys.keyAgreementKeyMultibase
  }
}

/**
 * The ceremony call with the fixture's wiring, overridable per test.
 */
async function runCeremony(
  fixture: Awaited<ReturnType<typeof forgetLastFixture>>,
  overrides?: {
    revoke?: (delegation: unknown) => Promise<void>
    collectionStore?: ReturnType<typeof memoryStore>
    onBeforeRemoval?: (published: { doc: object }) => Promise<void>
  }
) {
  const revokedIds: string[] = []
  const collectionStore = overrides?.collectionStore ?? memoryStore()
  const result = await forgetLastDurableClient({
    logStore: fixture.idStore,
    ladderSeed: fixture.ladderSeed,
    forgottenClient: fixture.forgottenClient,
    forgottenKeyAgreementKeyMultibase:
      fixture.forgottenKeyAgreementKeyMultibase,
    expectedDid: fixture.did,
    rosterStoreFor: () => fixture.rosterStore,
    credentialKeyAgreementKey: fixture.credentialKak,
    userKey: fixture.userKey,
    collections: {
      collectionIds: ['private-credentials'],
      storeFor: () => collectionStore
    },
    annex: {
      storeFor: () => fixture.annexIdStore,
      revoke:
        overrides?.revoke ??
        (async delegation => {
          revokedIds.push((delegation as { id: string }).id)
        }),
      wasServerUrl: WAS_URL,
      accountSpaceId: SPACE_ID
    },
    ...(overrides?.onBeforeRemoval
      ? { onBeforeRemoval: overrides.onBeforeRemoval }
      : {})
  })
  return { result, revokedIds, collectionStore }
}

describe('forgetLastDurableClient', () => {
  it('runs the two-entry transition: install, rotate, revoke, replace, remove', async () => {
    const fixture = await forgetLastFixture()
    const collectionStore = memoryStore()
    await initRecipients({
      store: collectionStore,
      recipients: [userKeyAsRecipient({ userKey: fixture.userKey })]
    })
    const entriesBefore = readLogFromString(fixture.log()!).length
    const rosterWritesBefore = fixture.rosterStore.writes
    const seamDocs: DIDDoc[] = []

    const { result, revokedIds } = await runCeremony(fixture, {
      collectionStore,
      onBeforeRemoval: async ({ doc }) => {
        seamDocs.push(doc as DIDDoc)
      }
    })

    // Two entries: the install and the removal.
    expect(result.installed).toBe(true)
    const finalLog = readLogFromString(fixture.log()!)
    expect(finalLog.length).toBe(entriesBefore + 2)
    const resolved = await resolveDIDFromLog(finalLog, {
      verifier: defaultWebvhLogVerifier
    })
    expect(resolved.meta.error).toBeUndefined()

    // The end state is the client-less, ladder-anchored account: the
    // client's whole footprint is out, the ladder VM stands under exactly
    // its two relations, and the rung is revealed with the client's update
    // key gone.
    const doc = resolved.doc as DIDDoc
    const ladderVmId = `${fixture.did}#${await ladderVmKeyMultibase({
      ladderSeed: fixture.ladderSeed
    })}`
    expect(relationIds(doc.capabilityInvocation)).toEqual([])
    expect(relationIds(doc.authentication)).toEqual([])
    expect(ladderVmIds({ doc })).toEqual([ladderVmId])
    expect(relationIds(doc.assertionMethod)).toContain(ladderVmId)
    const rung0 = await ladderRung({
      ladderSeed: fixture.ladderSeed,
      index: 0
    })
    expect(resolved.meta.updateKeys).toContain(rung0.keyMultibase)
    expect(resolved.meta.updateKeys).not.toContain(
      fixture.forgottenClient.updateKeyMultibase
    )

    // The pre-removal seam saw the both-present transitional state.
    expect(seamDocs).toHaveLength(1)
    const seamDoc = seamDocs[0]!
    expect(ladderVmIds({ doc: seamDoc })).toEqual([ladderVmId])
    expect(relationIds(seamDoc.capabilityInvocation)).toContain(
      `${fixture.did}#${fixture.forgottenClient.signingKeyMultibase}`
    )

    // The rotation was ONE append that retired the client's wrap; the fresh
    // key came back through the credential's standing wrap.
    expect(result.rotated).toBe(true)
    expect(fixture.rosterStore.writes).toBe(rosterWritesBefore + 1)
    expect(result.userKey!.id).not.toBe(fixture.userKey.id)
    const fresh = result.rosterDescriptor!.epochs!.find(
      epoch => epoch.id === result.rosterDescriptor!.currentEpoch
    )!
    expect(fresh.recipients.map(entry => entry.header.kid)).toEqual([
      fixture.credentialKak.id
    ])

    // The collection re-epoch'd onto the fresh key.
    expect(result.collections.outcomes['private-credentials']).toBe('rotated')
    const collectionEpoch = collectionStore.state.descriptor!.epochs!.find(
      epoch => epoch.id === collectionStore.state.descriptor!.currentEpoch
    )!
    expect(collectionEpoch.recipients.map(entry => entry.header.kid)).toContain(
      epochKeyIdFor(result.userKey!.id)
    )

    // The revocations covered exactly this ladder VM's history -- the
    // foreign delegation was left alone -- and the forced replacement left a
    // fresh ladder-signed delegation embedded.
    expect(result.generation.replaced).toBe(true)
    expect(result.generation.skipped).toBeUndefined()
    expect(revokedIds).toEqual([fixture.ownDelegationId])
    expect(result.generation.revoked).toEqual([fixture.ownDelegationId])
    const annexDoc = (
      await resolveDIDFromLog(readLogFromString(fixture.annexLog()!), {
        verifier: defaultWebvhLogVerifier
      })
    ).doc as DIDDoc
    const embedded = embeddedGenerationDelegation({ doc: annexDoc })!
    expect((embedded as { id?: string }).id).not.toBe(fixture.ownDelegationId)
    expect(delegationProofKeyId(embedded)).toBe(ladderVmId)

    // Calling again after completion is the finish-the-wipe state: nothing
    // runs, nothing is published.
    const again = await runCeremony(fixture)
    expect(again.result.installed).toBe(false)
    expect(again.result.generation.skipped).toBe('already-removed')
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore + 2)
  })

  it('converges on re-run after a run torn at the revocation POST', async () => {
    const fixture = await forgetLastFixture()
    const entriesBefore = readLogFromString(fixture.log()!).length

    // First run: the revocation POST dies (a network flap, rethrown
    // unchanged) AFTER the install entry, the rotation, and the forced
    // replacement have landed.
    await expect(
      runCeremony(fixture, {
        revoke: async () => {
          const err = new Error('connection reset')
          err.name = 'NetworkError'
          throw err
        }
      })
    ).rejects.toThrow('connection reset')
    const rosterWritesAfterTear = fixture.rosterStore.writes

    // Re-run: the install is skipped, no second roster append is attempted,
    // the prior run's fresh delegation is revoked as history (with the torn
    // run's own target re-POSTed blind -- here answered already-revoked),
    // and the removal entry lands.
    const validationError = new Error('already revoked')
    validationError.name = 'ValidationError'
    const seen: string[] = []
    const { result } = await runCeremony(fixture, {
      revoke: async delegation => {
        seen.push((delegation as { id: string }).id)
        if ((delegation as { id: string }).id === fixture.ownDelegationId) {
          throw validationError
        }
      }
    })

    expect(result.installed).toBe(false)
    expect(fixture.rosterStore.writes).toBe(rosterWritesAfterTear)
    expect(result.rotated).toBe(false)
    expect(seen).toContain(fixture.ownDelegationId)
    expect(seen).not.toContain(fixture.foreignDelegationId)
    // The torn run's replacement delegation is in the doomed set now; the
    // re-run's own replacement stays embedded.
    expect(seen.length).toBe(2)
    expect(result.generation.replaced).toBe(true)
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore + 2)
    const resolved = await resolveDIDFromLog(
      readLogFromString(fixture.log()!),
      {
        verifier: defaultWebvhLogVerifier
      }
    )
    expect(resolved.meta.error).toBeUndefined()
    expect(relationIds((resolved.doc as DIDDoc).capabilityInvocation)).toEqual(
      []
    )
  })

  it('refuses when another enrolled durable client remains', async () => {
    const fixture = await forgetLastFixture()
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
      store: fixture.idStore,
      ladderSeed: fixture.ladderSeed,
      newClientKeys: enrolledKeys,
      newClientUpdateSeeds: enrolledSeeds,
      expectedDid: fixture.did
    })
    const entriesBefore = readLogFromString(fixture.log()!).length

    await expect(runCeremony(fixture)).rejects.toThrow(/ordinary forget/)
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore)
  })

  it('completes with the generation stage skipped on an unpointed account', async () => {
    const fixture = await forgetLastFixture({ withPointer: false })
    const entriesBefore = readLogFromString(fixture.log()!).length

    const { result, revokedIds } = await runCeremony(fixture)

    expect(result.generation).toEqual({
      revoked: [],
      replaced: false,
      skipped: 'no-pointer'
    })
    expect(revokedIds).toEqual([])
    expect(result.rotated).toBe(true)
    expect(readLogFromString(fixture.log()!).length).toBe(entriesBefore + 2)
  })

  it('revokes but reports the honest skip when the annex rung is uncommitted', async () => {
    // The generation's genesis committed a DIFFERENT credential's rung, so
    // this credential cannot write the replacement entry -- the doomed
    // revocations still run, and the ceremony completes.
    const fixture = await forgetLastFixture({
      annexRungSeed: generateLadderSeed()
    })

    const { result, revokedIds } = await runCeremony(fixture)

    expect(result.generation.replaced).toBe(false)
    expect(result.generation.skipped).toBe('rung-uncommitted')
    expect(revokedIds).toEqual([fixture.ownDelegationId])
    const resolved = await resolveDIDFromLog(
      readLogFromString(fixture.log()!),
      {
        verifier: defaultWebvhLogVerifier
      }
    )
    expect(relationIds((resolved.doc as DIDDoc).capabilityInvocation)).toEqual(
      []
    )
  })
})
