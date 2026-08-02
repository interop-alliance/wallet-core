/**
 * Unit tests for client revocation's did:webvh half (`revokeWebvhClient`):
 * the one-entry roster edit against an in-memory store with full log
 * verification -- the verification methods and update key removed, BOTH
 * standing commitments removed (the carry-over hash and the log-attributed
 * staged hash), idempotence under a naive re-run, the self-revocation
 * refusal, attribution across a rotation, and the recovery-continuation
 * ambiguity (refused without the registry's latent hashes, resolved with
 * them).
 */
import { describe, expect, it } from 'vitest'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import {
  ensureDidWebvh,
  enrollWebvhClient,
  mintClientWebvhUpdateKeys,
  relationIds,
  rotateWebvhUpdateKey,
  updateKeyMultibase,
  type ClientWebvhUpdateKeys
} from '../../src/webvh/didWebvh.js'
import {
  revokeWebvhClient,
  StagedCommitmentAmbiguousError
} from '../../src/webvh/revokeClient.js'
import {
  publishRecoveryKey,
  recoverWebvhClient
} from '../../src/recovery/recoveryWebvh.js'
import {
  DID_DOCUMENT_RESOURCE,
  DID_KEYS_RESOURCE,
  DID_LOG_RESOURCE
} from '../../src/space/collections.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-revoke'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`

/**
 * The in-memory `WebvhIdStore` the ceremonies run against.
 *
 * @returns {object}
 */
function memoryIdStore() {
  let currentLog: string | undefined
  let currentDidDoc: object | undefined
  let currentKeys: object = {}
  const idStore = {
    async getKeyMap() {
      return currentKeys
    },
    async putKeyMap({ content }: { content: object }) {
      currentKeys = content
    },
    async getIdResource({ resourceId }: { resourceId: string }) {
      return resourceId === DID_DOCUMENT_RESOURCE ? currentDidDoc : undefined
    },
    async getIdResourceRaw({ resourceId }: { resourceId: string }) {
      return resourceId === DID_LOG_RESOURCE ? currentLog : undefined
    },
    async putIdResource({
      resourceId,
      content
    }: {
      resourceId: string
      content: object | string
      contentType?: string
    }) {
      if (resourceId === DID_LOG_RESOURCE && typeof content === 'string') {
        currentLog = content
      }
      if (resourceId === DID_DOCUMENT_RESOURCE && typeof content === 'object') {
        currentDidDoc = content
      }
      if (resourceId === DID_KEYS_RESOURCE && typeof content === 'object') {
        currentKeys = content
      }
    }
  }
  return { idStore, log: () => currentLog }
}

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
      },
      assertionMethod: {
        vmId: `${DID_WEB}#z6MkAssert`,
        kmsKeyId: 'kms/keys/assert'
      },
      keyAgreement: { vmId: `${DID_WEB}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
    },
    clientKeys: {
      signingKeyMultibase: 'z6MkFirstClientSigningKey11111',
      keyAgreementKeyMultibase: 'z6LSFirstClientAgreementKey111'
    },
    updateKeys: firstSeeds
  })
  const secondSeeds = await mintClientWebvhUpdateKeys()
  const secondClient = {
    signingKeyMultibase: 'z6MkSecondClientSigningKey2222',
    keyAgreementKeyMultibase: 'z6LSSecondClientAgreementKey22',
    updateKeyMultibase: await updateKeyMultibase({
      seed: secondSeeds.updateSeed
    }),
    stagedUpdateKeyMultibase: await updateKeyMultibase({
      seed: secondSeeds.stagedSeed
    })
  }
  await enrollWebvhClient({
    idStore,
    updateKeys: firstSeeds,
    newClient: secondClient
  })
  return { idStore, log, did, firstSeeds, secondSeeds, secondClient }
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
      updateKeys: firstSeeds,
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

  it('is idempotent: a naive re-run appends nothing', async () => {
    const { idStore, log, firstSeeds, secondClient } =
      await accountWithTwoClients()
    await revokeWebvhClient({
      idStore,
      updateKeys: firstSeeds,
      revokedClient: secondClient
    })
    const entries = log()!.trim().split('\n').length
    await revokeWebvhClient({
      idStore,
      updateKeys: firstSeeds,
      revokedClient: secondClient
    })
    expect(log()!.trim().split('\n')).toHaveLength(entries)
  })

  it('refuses self-revocation (and with it, revoking the last client)', async () => {
    const { idStore, firstSeeds } = await accountWithTwoClients()
    await expect(
      revokeWebvhClient({
        idStore,
        updateKeys: firstSeeds,
        revokedClient: {
          signingKeyMultibase: 'z6MkFirstClientSigningKey11111',
          keyAgreementKeyMultibase: 'z6LSFirstClientAgreementKey111',
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
      updateKeys: firstSeeds,
      revokedClient: secondClient
    })
    const thirdSeeds = await mintClientWebvhUpdateKeys()
    await expect(
      enrollWebvhClient({
        idStore,
        updateKeys: secondSeeds,
        newClient: {
          signingKeyMultibase: 'z6MkThirdClientSigningKey33333',
          keyAgreementKeyMultibase: 'z6LSThirdClientAgreementKey333',
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
      updateKeys: firstSeeds,
      revokedClient: { ...secondClient, updateKeyMultibase: rotatedActive }
    })
    const state = await resolved(log)
    expect(state.meta.updateKeys).not.toContain(rotatedActive)
    expect(state.meta.nextKeyHashes).not.toContain(rotatedStagedHash)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rotatedActive)
    )
  })

  it('refuses a recovery-added client without the latent hashes, succeeds with them', async () => {
    const { idStore, log, firstSeeds } = await accountWithTwoClients()

    // Issue a recovery code's posture, then run the continuation that adds a
    // client through it (the shape whose commit entry also carries the
    // replacement code's latent hash).
    const spentSeeds = await mintClientWebvhUpdateKeys()
    const spent = {
      keyAgreementKeyMultibase: 'z6LSSpentCodeAgreementKey55555',
      updateKeyMultibase: await updateKeyMultibase({
        seed: spentSeeds.updateSeed
      })
    }
    await publishRecoveryKey({
      idStore,
      updateKeys: firstSeeds,
      recovery: spent
    })
    const recoveredSeeds = await mintClientWebvhUpdateKeys()
    const recoveredClient = {
      signingKeyMultibase: 'z6MkRecoveredClientSigning4444',
      keyAgreementKeyMultibase: 'z6LSRecoveredClientAgreement44',
      updateKeyMultibase: await updateKeyMultibase({
        seed: recoveredSeeds.updateSeed
      }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: recoveredSeeds.stagedSeed
      })
    }
    const replacementSeeds = await mintClientWebvhUpdateKeys()
    const replacement = {
      keyAgreementKeyMultibase: 'z6LSReplacementCodeAgreement66',
      updateKeyMultibase: await updateKeyMultibase({
        seed: replacementSeeds.updateSeed
      })
    }
    await recoverWebvhClient({
      store: idStore,
      recovery: { ...spent, updateSeed: spentSeeds.updateSeed },
      newClientKeys: recoveredClient,
      newClientUpdateSeeds: recoveredSeeds,
      replacement
    })

    // Without the registry's latent hashes the staged commitment cannot be
    // told apart from the replacement code's -- refused, not guessed.
    await expect(
      revokeWebvhClient({
        idStore,
        updateKeys: firstSeeds,
        revokedClient: recoveredClient
      })
    ).rejects.toThrow(StagedCommitmentAmbiguousError)

    const replacementHash = await deriveNextKeyHash(
      replacement.updateKeyMultibase
    )
    await revokeWebvhClient({
      idStore,
      updateKeys: firstSeeds,
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
    // The replacement code's latent commitment survives.
    expect(state.meta.nextKeyHashes).toContain(replacementHash)
  })
})
