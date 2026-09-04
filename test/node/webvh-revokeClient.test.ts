/**
 * Unit tests for client revocation's did:webvh half (`revokeWebvhClient`):
 * the one-entry roster edit against an in-memory store with full log
 * verification -- the verification methods and update key removed, BOTH
 * standing commitments removed (the carry-over hash and the log-attributed
 * staged hash), idempotence under a naive re-run, the self-revocation
 * refusal, attribution across a rotation, the stale-update-key case (the
 * target self-rotates after the listing and is still revoked at the key the
 * log states), the staged-key-supplied case (the same re-derivation, since a
 * committed-but-unrevealed key would strike nothing), the torn-enrollment
 * cleanup (a committed hash with no verification methods published), the
 * multi-commitment entries the decision-0007 append order resolves
 * positionally (a standing credential's self-enrollment, a recovery
 * continuation), and the residue position that resolves neither way and is
 * refused loudly.
 */
import { describe, expect, it } from 'vitest'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog,
  updateDID
} from '@interop/did-method-webvh'
import { DID_LOG_RESOURCE } from '../../src/space/collections.js'
import { ensureDidWebProjection } from '../../src/webvh/didWebProjection.js'
import {
  clientKeyAgreementController,
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  MULTIKEY_VM_TYPE,
  publishUpdatedLog,
  readPublishedLog,
  rotateWebvhUpdateKey,
  updateKeyMultibase,
  updateKeySigner,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { enrollWebvhClient } from '../../src/webvh/enrollClient.js'
import { relationIds } from '../../src/resourceLog/document.js'
import {
  generateLadderSeed,
  ladderRung,
  ladderRungSeed,
  ladderVmKeyMultibase
} from '../../src/clientAnnex/ladder.js'
import { selfEnrollWebvhClient } from '../../src/clientAnnex/ladderAnchored.js'
import { publishUnlockKey } from '../../src/unlock/standingWebvh.js'
import {
  revokeWebvhClient,
  StagedCommitmentAmbiguousError
} from '../../src/webvh/revokeClient.js'
import {
  publishRecoveryKey,
  recoverWebvhClient
} from '../../src/recovery/recoveryWebvh.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-revoke'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`

/**
 * Provisions a one-client account and enrolls a second client, returning
 * everything the revocation tests need.
 *
 * @returns {Promise<object>}
 */
async function accountWithTwoClients() {
  const { idStore, log } = memoryIdStore()
  const firstSeeds = await mintClientWebvhUpdateKeys()
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    didWebKeys: {
      authentication: {
        vmId: `${DID_WEB}#z6MkAuth`,
        kmsKeyId: 'kms/keys/auth'
      }
    },
    clientKeys: {
      ...CANONICAL_CLIENT_KEYS[0]
    },
    updateKeys: firstSeeds
  })
  const secondSeeds = await mintClientWebvhUpdateKeys()
  const secondClient = {
    ...CANONICAL_CLIENT_KEYS[1],
    updateKeyMultibase: await updateKeyMultibase({
      seed: secondSeeds.updateSeed
    }),
    stagedUpdateKeyMultibase: await updateKeyMultibase({
      seed: secondSeeds.stagedSeed
    })
  }
  await enrollWebvhClient({
    idStore,
    signer: { kind: 'client', updateKeys: firstSeeds },
    newClient: secondClient
  })
  return { idStore, log, did, firstSeeds, secondSeeds, secondClient }
}

/**
 * Publishes one more `keyAgreement` verification method under a client's
 * controller marker -- the shape a client with several published
 * key-agreement keys leaves in the document, which no ordinary ceremony
 * produces (enrollment is idempotent on the client's signing key).
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the publishing client's
 *   own update-key seeds
 * @param options.signingKeyMultibase {string}   the client the marker names
 * @param options.keyAgreementKeyMultibase {string}   the extra key
 * @returns {Promise<void>}
 */
async function publishMarkedKeyAgreement({
  idStore,
  updateKeys,
  signingKeyMultibase,
  keyAgreementKeyMultibase
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  signingKeyMultibase: string
  keyAgreementKeyMultibase: string
}): Promise<void> {
  const published = (await readPublishedLog({ idStore }))!
  const { did, doc, log, etag } = published
  const vmId = `${did}#${keyAgreementKeyMultibase}`
  const updated = await updateDID({
    log,
    signer: await updateKeySigner({ seed: updateKeys.updateSeed }),
    alsoKnownAsWeb: true,
    updateKeys: published.updateKeys,
    nextKeyHashes: published.nextKeyHashes,
    verificationMethods: [
      ...(doc.verificationMethod ?? []),
      {
        id: vmId,
        type: MULTIKEY_VM_TYPE,
        controller: clientKeyAgreementController({ signingKeyMultibase }),
        publicKeyMultibase: keyAgreementKeyMultibase
      }
    ],
    authentication: relationIds(doc.authentication),
    assertionMethod: relationIds(doc.assertionMethod),
    keyAgreement: [...relationIds(doc.keyAgreement), vmId],
    capabilityInvocation: relationIds(doc.capabilityInvocation),
    capabilityDelegation: relationIds(doc.capabilityDelegation)
  })
  await publishUpdatedLog({ idStore, updated, ifMatch: etag })
}

/**
 * Publishes a sparse commit entry appending the given hashes to
 * `nextKeyHashes` in exactly the order supplied -- the seam the append-order
 * tests need, since the shipped ceremonies always emit the decision-0007
 * order.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.updateKeys {ClientWebvhUpdateKeys}   the signing client's own
 *   update-key seeds
 * @param options.addedHashes {string[]}   the hashes to append, in order
 * @returns {Promise<void>}
 */
async function publishHashCommitEntry({
  idStore,
  updateKeys,
  addedHashes
}: {
  idStore: WebvhIdStore
  updateKeys: ClientWebvhUpdateKeys
  addedHashes: string[]
}): Promise<void> {
  const published = (await readPublishedLog({ idStore }))!
  const updated = await updateDID({
    log: published.log,
    signer: await updateKeySigner({ seed: updateKeys.updateSeed }),
    alsoKnownAsWeb: true,
    updateKeys: published.updateKeys,
    nextKeyHashes: [...new Set([...published.nextKeyHashes, ...addedHashes])]
  })
  await publishUpdatedLog({ idStore, updated, ifMatch: published.etag })
}

/**
 * A freshly minted client's public halves plus the update seeds behind them.
 *
 * @param index {number}   which canonical key set to use
 * @returns {Promise<object>}
 */
async function mintedNewClient(index: number) {
  const seeds = await mintClientWebvhUpdateKeys()
  return {
    seeds,
    keys: {
      ...CANONICAL_CLIENT_KEYS[index]!,
      updateKeyMultibase: await updateKeyMultibase({ seed: seeds.updateSeed }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: seeds.stagedSeed
      })
    }
  }
}

/**
 * A one-client account with a bound standing credential and a SECOND client
 * self-enrolled through that credential's ladder -- the shape whose
 * reveal-and-commit entry commits three hashes at once (the new client's
 * update- and staged-key hashes plus the ladder's next-rung hash), so the
 * staged-hash attribution has two candidates left after the prune and must
 * resolve them positionally.
 *
 * @returns {Promise<object>}
 */
async function accountWithSelfEnrolledClient() {
  const { idStore, log, didDocument } = memoryIdStore()
  const firstSeeds = await mintClientWebvhUpdateKeys()
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
    updateKeys: firstSeeds
  })
  const ladderSeed = generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  await publishUnlockKey({
    idStore,
    signer: { kind: 'client', updateKeys: firstSeeds },
    unlockKeys: {
      keyAgreement: {
        commitment: await keyAgreementCommitment({
          keyAgreementKeyMultibase:
            CANONICAL_CLIENT_KEYS[9].keyAgreementKeyMultibase
        })
      },
      updateKeyMultibase: rung0.keyMultibase
    },
    ladderSeed
  })
  const enrolled = await mintedNewClient(3)
  await selfEnrollWebvhClient({
    store: idStore,
    ladderSeed,
    newClientKeys: enrolled.keys,
    newClientUpdateSeeds: enrolled.seeds,
    onCommitted: async () => {},
    expectedDid: did
  })
  return { idStore, log, didDocument, did, firstSeeds, ladderSeed, enrolled }
}

/**
 * A two-client account plus a third client brought in by a recovery-code
 * continuation, whose reveal-and-commit entry likewise commits three hashes
 * (the recovered client's update- and staged-key hashes plus the replacement
 * code's latent hash).
 *
 * @returns {Promise<object>}
 */
async function accountWithRecoveryEnrolledClient() {
  const { idStore, log, firstSeeds } = await accountWithTwoClients()
  const spentLadderSeed = generateLadderSeed()
  const spent = {
    keyAgreementKeyMultibase: 'z6LSSpentCodeAgreementKey55555',
    updateKeyMultibase: await updateKeyMultibase({
      seed: ladderRungSeed({ ladderSeed: spentLadderSeed, index: 0 })
    })
  }
  await publishRecoveryKey({
    idStore,
    signer: { kind: 'client', updateKeys: firstSeeds },
    recovery: spent,
    ladderSeed: spentLadderSeed
  })
  const recovered = await mintedNewClient(3)
  const replacementSeeds = await mintClientWebvhUpdateKeys()
  const replacementLadderSeed = generateLadderSeed()
  const replacement = {
    keyAgreementKeyMultibase: 'z6LSReplacementCodeAgreement66',
    updateKeyMultibase: await updateKeyMultibase({
      seed: replacementSeeds.updateSeed
    }),
    ladderVmKeyMultibase: await ladderVmKeyMultibase({
      ladderSeed: replacementLadderSeed
    })
  }
  await recoverWebvhClient({
    store: idStore,
    recovery: {
      ...spent,
      updateSeed: ladderRungSeed({ ladderSeed: spentLadderSeed, index: 0 })
    },
    newClientKeys: recovered.keys,
    newClientUpdateSeeds: recovered.seeds,
    replacement,
    onCommitted: async () => {}
  })
  return {
    idStore,
    log,
    firstSeeds,
    recoveredClient: recovered.keys,
    replacement
  }
}

/**
 * Resolves the store's current log with full verification.
 *
 * @param log {function}
 * @returns {Promise<object>}
 */
async function resolved(log: () => string | undefined) {
  const result = await resolveDIDFromLog(readLogFromString(log()!), {
    verifier: defaultWebvhLogVerifier
  })
  expect(result.meta.error).toBeUndefined()
  return result
}

describe('revokeWebvhClient', () => {
  it('removes the client in ONE verifying entry: VMs, relations, update key, and BOTH commitments', async () => {
    const { idStore, log, did, firstSeeds, secondClient } =
      await accountWithTwoClients()
    const entriesBefore = log()!.trim().split('\n').length

    const result = await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: secondClient
    })
    expect(result.did).toBe(did)
    expect(log()!.trim().split('\n')).toHaveLength(entriesBefore + 1)

    const state = await resolved(log)
    const doc = state.doc!
    const multibases = (doc.verificationMethod ?? []).map(
      (method: { publicKeyMultibase?: string }) => method.publicKeyMultibase
    )
    expect(multibases).not.toContain(secondClient.signingKeyMultibase)
    expect(multibases).not.toContain(secondClient.keyAgreementKeyMultibase)
    const signingVmId = `${did}#${secondClient.signingKeyMultibase}`
    const keyAgreementVmId = `${did}#${secondClient.keyAgreementKeyMultibase}`
    for (const relation of [
      doc.authentication,
      doc.assertionMethod,
      doc.capabilityInvocation,
      doc.capabilityDelegation
    ]) {
      expect(relationIds(relation)).not.toContain(signingVmId)
    }
    expect(relationIds(doc.keyAgreement)).not.toContain(keyAgreementVmId)

    const updateKeys = state.meta.updateKeys ?? []
    expect(updateKeys).not.toContain(secondClient.updateKeyMultibase)
    expect(updateKeys).toContain(
      await updateKeyMultibase({ seed: firstSeeds.updateSeed })
    )
    const nextKeyHashes = state.meta.nextKeyHashes ?? []
    expect(nextKeyHashes).not.toContain(
      await deriveNextKeyHash(secondClient.updateKeyMultibase)
    )
    expect(nextKeyHashes).not.toContain(
      await deriveNextKeyHash(secondClient.stagedUpdateKeyMultibase)
    )
    // The revoking client's own commitments survive untouched.
    expect(nextKeyHashes).toContain(
      await deriveNextKeyHash(
        await updateKeyMultibase({ seed: firstSeeds.updateSeed })
      )
    )
    expect(nextKeyHashes).toContain(
      await deriveNextKeyHash(
        await updateKeyMultibase({ seed: firstSeeds.stagedSeed })
      )
    )
  })

  it('removes EVERY key-agreement method the marker claims, and only those', async () => {
    const { idStore, log, did, firstSeeds, secondClient } =
      await accountWithTwoClients()
    // A second key-agreement key published for the same client: the marker
    // claims both, so the removal must be a set filter, not a first match.
    const extraAgreementKey = 'z6LSSecondClientExtraAgreem22'
    await publishMarkedKeyAgreement({
      idStore,
      updateKeys: firstSeeds,
      signingKeyMultibase: secondClient.signingKeyMultibase,
      keyAgreementKeyMultibase: extraAgreementKey
    })
    const enrolled = (await resolved(log)).doc!
    expect(relationIds(enrolled.keyAgreement)).toEqual(
      expect.arrayContaining([
        `${did}#${secondClient.keyAgreementKeyMultibase}`,
        `${did}#${extraAgreementKey}`
      ])
    )

    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      // Deliberately without a key-agreement key: the removal reads the
      // marked methods off the document, never off the caller's snapshot.
      revokedClient: {
        signingKeyMultibase: secondClient.signingKeyMultibase,
        updateKeyMultibase: secondClient.updateKeyMultibase
      }
    })

    const doc = (await resolved(log)).doc!
    const multibases = (doc.verificationMethod ?? []).map(
      (method: { publicKeyMultibase?: string }) => method.publicKeyMultibase
    )
    expect(multibases).not.toContain(secondClient.keyAgreementKeyMultibase)
    expect(multibases).not.toContain(extraAgreementKey)
    expect(relationIds(doc.keyAgreement)).not.toContain(
      `${did}#${extraAgreementKey}`
    )
    // The revoking client's own (also marked) key-agreement method stands.
    expect(multibases).toContain(
      CANONICAL_CLIENT_KEYS[0].keyAgreementKeyMultibase
    )
  })

  it('is idempotent: a naive re-run appends nothing', async () => {
    const { idStore, log, firstSeeds, secondClient } =
      await accountWithTwoClients()
    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: secondClient
    })
    const entries = log()!.trim().split('\n').length
    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: secondClient
    })
    expect(log()!.trim().split('\n')).toHaveLength(entries)
  })

  it('refuses self-revocation (and with it, revoking the last client)', async () => {
    const { idStore, firstSeeds } = await accountWithTwoClients()
    await expect(
      revokeWebvhClient({
        idStore,
        signer: { kind: 'client', updateKeys: firstSeeds },
        revokedClient: {
          ...CANONICAL_CLIENT_KEYS[0],
          updateKeyMultibase: await updateKeyMultibase({
            seed: firstSeeds.updateSeed
          })
        }
      })
    ).rejects.toThrow(/cannot revoke itself/)
  })

  it('a revoked client cannot author log entries afterwards', async () => {
    const { idStore, firstSeeds, secondSeeds, secondClient } =
      await accountWithTwoClients()
    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: secondClient
    })
    const thirdSeeds = await mintClientWebvhUpdateKeys()
    await expect(
      enrollWebvhClient({
        idStore,
        signer: { kind: 'client', updateKeys: secondSeeds },
        newClient: {
          ...CANONICAL_CLIENT_KEYS[2],
          updateKeyMultibase: await updateKeyMultibase({
            seed: thirdSeeds.updateSeed
          }),
          stagedUpdateKeyMultibase: await updateKeyMultibase({
            seed: thirdSeeds.stagedSeed
          })
        }
      })
    ).rejects.toThrow(/does not authorize this client's active update key/)
  })

  it('attributes and removes the staged commitment across the revoked client rotating its key', async () => {
    const { idStore, log, firstSeeds, secondSeeds, secondClient } =
      await accountWithTwoClients()
    // The second client self-rotates: its staged key becomes active, a fresh
    // staged hash is committed.
    let rolled: ClientWebvhUpdateKeys = secondSeeds
    await rotateWebvhUpdateKey({
      idStore,
      updateKeys: secondSeeds,
      persistUpdateKeys: async next => {
        rolled = next
      }
    })
    const rotatedActive = await updateKeyMultibase({ seed: rolled.updateSeed })
    const rotatedStagedHash = await deriveNextKeyHash(
      await updateKeyMultibase({ seed: rolled.stagedSeed })
    )
    const before = await resolved(log)
    expect(before.meta.nextKeyHashes).toContain(rotatedStagedHash)

    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: { ...secondClient, updateKeyMultibase: rotatedActive }
    })
    const state = await resolved(log)
    expect(state.meta.updateKeys).not.toContain(rotatedActive)
    expect(state.meta.nextKeyHashes).not.toContain(rotatedStagedHash)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rotatedActive)
    )
  })

  it('revokes at the key the LOG states when the target rotated after the listing', async () => {
    const { idStore, log, firstSeeds, secondSeeds, secondClient } =
      await accountWithTwoClients()
    // The caller lists the roster (K1), and the target self-rotates K1 to K2
    // before the revocation lands -- so the supplied update key is stale.
    const staleClient = { ...secondClient }
    let rolled: ClientWebvhUpdateKeys = secondSeeds
    await rotateWebvhUpdateKey({
      idStore,
      updateKeys: secondSeeds,
      persistUpdateKeys: async next => {
        rolled = next
      }
    })
    const rotatedActive = await updateKeyMultibase({ seed: rolled.updateSeed })
    const before = await resolved(log)
    expect(before.meta.updateKeys).toContain(rotatedActive)
    expect(before.meta.updateKeys).not.toContain(staleClient.updateKeyMultibase)

    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: staleClient
    })

    // K2 is struck out of updateKeys, and both of its commitments with it, so
    // the revoked client holds no log-update authority.
    const state = await resolved(log)
    expect(state.meta.updateKeys).not.toContain(rotatedActive)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rotatedActive)
    )
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(
        await updateKeyMultibase({ seed: rolled.stagedSeed })
      )
    )
    // ... which the resolver agrees with: it can no longer author an entry.
    const thirdSeeds = await mintClientWebvhUpdateKeys()
    await expect(
      enrollWebvhClient({
        idStore,
        signer: { kind: 'client', updateKeys: rolled },
        newClient: {
          ...CANONICAL_CLIENT_KEYS[2],
          updateKeyMultibase: await updateKeyMultibase({
            seed: thirdSeeds.updateSeed
          }),
          stagedUpdateKeyMultibase: await updateKeyMultibase({
            seed: thirdSeeds.stagedSeed
          })
        }
      })
    ).rejects.toThrow(/does not authorize this client's active update key/)
  })

  it('revokes at the ACTIVE key when the caller supplies the staged one', async () => {
    const { idStore, log, did, firstSeeds, secondClient } =
      await accountWithTwoClients()
    const before = await resolved(log)
    // The shape: the staged key's hash stands committed, but the key itself is
    // not authorized -- acting on it verbatim would strike nothing.
    expect(before.meta.updateKeys).not.toContain(
      secondClient.stagedUpdateKeyMultibase
    )
    expect(before.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(secondClient.stagedUpdateKeyMultibase)
    )

    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: {
        ...secondClient,
        updateKeyMultibase: secondClient.stagedUpdateKeyMultibase
      }
    })

    const state = await resolved(log)
    // The active key, attributed from the log, is gone with both commitments.
    expect(state.meta.updateKeys).not.toContain(secondClient.updateKeyMultibase)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(secondClient.updateKeyMultibase)
    )
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(secondClient.stagedUpdateKeyMultibase)
    )
    const doc = state.doc!
    const multibases = (doc.verificationMethod ?? []).map(
      (method: { publicKeyMultibase?: string }) => method.publicKeyMultibase
    )
    expect(multibases).not.toContain(secondClient.signingKeyMultibase)
    expect(multibases).not.toContain(secondClient.keyAgreementKeyMultibase)
    expect(relationIds(doc.assertionMethod)).not.toContain(
      `${did}#${secondClient.signingKeyMultibase}`
    )
  })

  it('cleans up a torn enrollment: the committed hash goes with no methods published', async () => {
    const { idStore, log } = memoryIdStore()
    const firstSeeds = await mintClientWebvhUpdateKeys()
    await ensureDidWebvh({
      idStore,
      wasServerUrl: WAS_URL,
      spaceId: SPACE_ID,
      didWebKeys: {
        authentication: {
          vmId: `${DID_WEB}#z6MkAuth`,
          kmsKeyId: 'kms/keys/auth'
        }
      },
      clientKeys: {
        ...CANONICAL_CLIENT_KEYS[0]
      },
      updateKeys: firstSeeds
    })
    const secondSeeds = await mintClientWebvhUpdateKeys()
    const secondClient = {
      ...CANONICAL_CLIENT_KEYS[1],
      updateKeyMultibase: await updateKeyMultibase({
        seed: secondSeeds.updateSeed
      }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: secondSeeds.stagedSeed
      })
    }

    // Fault injection: the enrollment's add entry never lands, so only the
    // commit entry stands -- the client's hash in nextKeyHashes, no key in
    // updateKeys, no verification methods in the document.
    const originalPut = idStore.putIdResource.bind(idStore)
    let logWrites = 0
    idStore.putIdResource = async options => {
      if (options.resourceId === DID_LOG_RESOURCE) {
        logWrites++
        if (logWrites === 2) {
          throw new Error('injected: connection lost mid-ceremony')
        }
      }
      return originalPut(options)
    }
    await expect(
      enrollWebvhClient({
        idStore,
        signer: { kind: 'client', updateKeys: firstSeeds },
        newClient: secondClient
      })
    ).rejects.toThrow('injected')
    idStore.putIdResource = originalPut

    const torn = await resolved(log)
    expect(torn.meta.updateKeys).not.toContain(secondClient.updateKeyMultibase)
    expect(torn.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(secondClient.updateKeyMultibase)
    )

    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: secondClient
    })

    const state = await resolved(log)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(secondClient.updateKeyMultibase)
    )
  })

  it('revokes a SELF-ENROLLED client with no latent hashes supplied, striking the staged hash and not the ladder rung', async () => {
    const { idStore, log, did, firstSeeds, ladderSeed, enrolled } =
      await accountWithSelfEnrolledClient()
    // The credential's next standing commitment, committed beside the new
    // client's two hashes by the same reveal-and-commit entry: the wrong
    // candidate, which the append-order rule must not strike.
    const rung1Hash = await deriveNextKeyHash(
      (await ladderRung({ ladderSeed, index: 1 })).keyMultibase
    )
    const before = await resolved(log)
    expect(before.meta.nextKeyHashes).toContain(rung1Hash)

    // No knownLatentHashes: the caller has no registry entry for a ladder
    // rung, so the prune leaves two candidates and only the decision-0007
    // position resolves them.
    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: enrolled.keys
    })

    const state = await resolved(log)
    const doc = state.doc!
    const multibases = (doc.verificationMethod ?? []).map(
      (method: { publicKeyMultibase?: string }) => method.publicKeyMultibase
    )
    expect(multibases).not.toContain(enrolled.keys.signingKeyMultibase)
    expect(multibases).not.toContain(enrolled.keys.keyAgreementKeyMultibase)
    expect(relationIds(doc.capabilityInvocation)).not.toContain(
      `${did}#${enrolled.keys.signingKeyMultibase}`
    )
    expect(state.meta.updateKeys).not.toContain(
      enrolled.keys.updateKeyMultibase
    )
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(enrolled.keys.updateKeyMultibase)
    )
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(enrolled.keys.stagedUpdateKeyMultibase)
    )
    // The credential's ladder is untouched: its next rung stands committed.
    expect(state.meta.nextKeyHashes).toContain(rung1Hash)
  })

  it('revokes a RECOVERY-added client with no latent hashes supplied, leaving the replacement code committed', async () => {
    const { idStore, log, firstSeeds, recoveredClient, replacement } =
      await accountWithRecoveryEnrolledClient()
    const replacementHash = await deriveNextKeyHash(
      replacement.updateKeyMultibase
    )

    // The same three-hash commit shape, with the replacement code's latent
    // hash as the third: position resolves it without the registry.
    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: recoveredClient
    })

    const state = await resolved(log)
    expect(state.meta.updateKeys).not.toContain(
      recoveredClient.updateKeyMultibase
    )
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(recoveredClient.stagedUpdateKeyMultibase)
    )
    expect(state.meta.nextKeyHashes).toContain(replacementHash)
  })

  it('resolves a recovery-added client with the registry latent hashes too', async () => {
    const { idStore, log, firstSeeds, recoveredClient, replacement } =
      await accountWithRecoveryEnrolledClient()
    const replacementHash = await deriveNextKeyHash(
      replacement.updateKeyMultibase
    )

    // The prune path: with the replacement code's hash vouched for, one
    // candidate survives and the position is never consulted.
    await revokeWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      revokedClient: recoveredClient,
      knownLatentHashes: [replacementHash]
    })

    const state = await resolved(log)
    expect(state.meta.updateKeys).not.toContain(
      recoveredClient.updateKeyMultibase
    )
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(recoveredClient.stagedUpdateKeyMultibase)
    )
    expect(state.meta.nextKeyHashes).toContain(replacementHash)
  })

  it('refuses when the position cannot resolve either: the update-key hash is not followed by a candidate', async () => {
    const { idStore, log, firstSeeds } = await accountWithTwoClients()
    const third = await mintedNewClient(3)
    const foreignSeeds = await mintClientWebvhUpdateKeys()
    const foreignHash = await deriveNextKeyHash(
      await updateKeyMultibase({ seed: foreignSeeds.updateSeed })
    )
    const thirdStagedHash = await deriveNextKeyHash(
      third.keys.stagedUpdateKeyMultibase
    )
    const thirdUpdateHash = await deriveNextKeyHash(
      third.keys.updateKeyMultibase
    )

    // A commit entry in an order the shipped emitters never produce: the
    // client's own update-key hash is committed LAST, so no addition follows
    // it and the append-order rule has nothing to place.
    await publishHashCommitEntry({
      idStore,
      updateKeys: firstSeeds,
      addedHashes: [thirdStagedHash, foreignHash, thirdUpdateHash]
    })
    // The add entry alone (the commit above is what enrollWebvhClient's own
    // commit step would otherwise write).
    await enrollWebvhClient({
      idStore,
      signer: { kind: 'client', updateKeys: firstSeeds },
      newClient: third.keys
    })

    await expect(
      revokeWebvhClient({
        idStore,
        signer: { kind: 'client', updateKeys: firstSeeds },
        revokedClient: third.keys
      })
    ).rejects.toThrow(StagedCommitmentAmbiguousError)

    // Nothing was guessed at: the log is unchanged by the refusal.
    const state = await resolved(log)
    expect(state.meta.nextKeyHashes).toContain(thirdStagedHash)
    expect(state.meta.nextKeyHashes).toContain(foreignHash)
  })
})

describe('the pre-entry did:web projection', () => {
  /**
   * A recording wrapper around a store: every `putIdResource` resource id, in
   * order, so a test can see whether the projection preceded the entry.
   *
   * @param idStore {WebvhIdStore}
   * @returns {object}
   */
  function recordingStore(idStore: WebvhIdStore) {
    const writes: string[] = []
    const store: WebvhIdStore = {
      ...idStore,
      getIdResourceRaw: read => idStore.getIdResourceRaw(read),
      async putIdResource(write) {
        writes.push(write.resourceId)
        return idStore.putIdResource(write)
      }
    }
    return { store, writes }
  }

  it('publishes the post-removal projection before a ladder-signed entry', async () => {
    const { idStore, log, didDocument, did, ladderSeed, enrolled } =
      await accountWithSelfEnrolledClient()
    // The starting state: `did.json` current with the enrolled client in it,
    // as the controller-invoking ceremonies leave it.
    const before = await resolved(log)
    await ensureDidWebProjection({
      store: idStore,
      did,
      doc: before.doc!
    })
    expect(JSON.stringify(didDocument())).toContain(
      enrolled.keys.signingKeyMultibase
    )
    const { store, writes } = recordingStore(idStore)

    await revokeWebvhClient({
      idStore: store,
      signer: { kind: 'ladder', ladderSeed },
      projectionStore: store,
      revokedClient: enrolled.keys,
      expectedDid: did
    })

    // The ladder arm publishes `did.jsonl` alone, so the one projection PUT
    // is this seam's, and it precedes the entry.
    expect(writes.filter(id => id === 'did.json')).toHaveLength(1)
    expect(writes.indexOf('did.json')).toBeLessThan(
      writes.lastIndexOf(DID_LOG_RESOURCE)
    )
    // And it carries the POST-removal document.
    const served = JSON.stringify(didDocument())
    expect(served).not.toContain(enrolled.keys.signingKeyMultibase)
    expect(served).not.toContain(enrolled.keys.keyAgreementKeyMultibase)
  })

  it('publishes the removal entry even when the projection PUT throws', async () => {
    const { idStore, log, did, ladderSeed, enrolled } =
      await accountWithSelfEnrolledClient()
    const entriesBefore = readLogFromString(log()!).length
    const throwing = {
      getIdResourceRaw: (read: { resourceId: string }) =>
        idStore.getIdResourceRaw(read),
      async putIdResource() {
        throw new Error('the projection PUT was refused')
      }
    } as unknown as WebvhIdStore

    await revokeWebvhClient({
      idStore,
      signer: { kind: 'ladder', ladderSeed },
      projectionStore: throwing,
      revokedClient: enrolled.keys,
      expectedDid: did
    })

    // The entry stands: a projection this account's next visit mends is a
    // smaller residue than a client the log still lists.
    expect(readLogFromString(log()!).length).toBe(entriesBefore + 1)
    const state = await resolved(log)
    expect(relationIds(state.doc!.capabilityInvocation)).not.toContain(
      `${did}#${enrolled.keys.signingKeyMultibase}`
    )
  })
})
