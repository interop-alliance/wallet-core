/**
 * Unit tests for recovery codes on the roster identity model
 * (`src/recovery/`): the format layer (shape, display grouping, entry
 * normalization, malformed-code rejection), the deterministic
 * client-key derivation (same code, same key set -- across formatting
 * -- and its distinct unlock Space vs the passphrase KDF for identical
 * secret text), the recovery-record codec (pointer + delegation, never key
 * material), and the did:webvh lifecycle end to end against an in-memory
 * store: issuance's split posture, the self-enrolling recovery continuation
 * and its resumability, and revocation.
 */
import { describe, expect, it } from 'vitest'
import { base58 } from '@scure/base'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import {
  decodeRecoveryCode,
  formatRecoveryCode,
  generateRecoveryCode,
  normalizeRecoveryCode,
  RECOVERY_CODE_BYTES,
  RECOVERY_KDF,
  RecoveryCodeInvalidError,
  recoveryClientFromCode
} from '../../src/recovery/recoveryCode.js'
import {
  unwrapRecoveryRecord,
  wrapRecoveryRecord
} from '../../src/recovery/recoveryRecord.js'
import {
  publishRecoveryKey,
  recoverWebvhClient,
  RecoveryKeyNotCommittedError,
  recoveryVmId,
  removeRecoveryKey
} from '../../src/recovery/recoveryWebvh.js'
import { deriveUnlockIdentity, KEYRING_KDF } from '../../src/keyring/kdf.js'
import { unwrapKeyringRecord } from '../../src/keyring/record.js'
import {
  ensureDidWebvh,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-recovery'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`

describe('the recovery-code format layer', () => {
  it('mints unique base58 codes that decode to 16 bytes', () => {
    const code = generateRecoveryCode()
    expect(base58.decode(code)).toHaveLength(RECOVERY_CODE_BYTES)
    expect(generateRecoveryCode()).not.toBe(code)
  })

  it('round-trips a code through display grouping', () => {
    const code = generateRecoveryCode()
    const formatted = formatRecoveryCode({ code })
    expect(formatted).toMatch(
      /^[1-9A-HJ-NP-Za-km-z]{4}(-[1-9A-HJ-NP-Za-km-z]{1,4})+$/
    )
    expect(normalizeRecoveryCode({ input: formatted })).toBe(code)
  })

  it('strips whitespace on entry but preserves case', () => {
    expect(normalizeRecoveryCode({ input: '  aB3d \n eF4g ' })).toBe('aB3deF4g')
  })

  it('rejects text that is not a well-formed code', () => {
    // '0', 'O', 'I', 'l' are outside the base58 alphabet.
    expect(() => decodeRecoveryCode({ code: '0OIl' })).toThrow(
      RecoveryCodeInvalidError
    )
    // Valid base58 of the wrong length.
    expect(() => decodeRecoveryCode({ code: 'abc' })).toThrow(
      RecoveryCodeInvalidError
    )
    expect(() => decodeRecoveryCode({ code: '' })).toThrow(
      RecoveryCodeInvalidError
    )
  })
})

describe('recoveryClientFromCode', () => {
  it('derives the same full key set from the same code, formatted or not', async () => {
    const code = generateRecoveryCode()
    const client = await recoveryClientFromCode({ code })
    const again = await recoveryClientFromCode({
      code: formatRecoveryCode({ code })
    })
    expect(client.clientDid.startsWith('did:key:z6Mk')).toBe(true)
    expect(client.keyAgreementKeyMultibase.startsWith('z6LS')).toBe(true)
    expect(client.updateKeyMultibase.startsWith('z6Mk')).toBe(true)
    expect(again.clientDid).toBe(client.clientDid)
    expect(again.keyAgreementKeyMultibase).toBe(client.keyAgreementKeyMultibase)
    expect(again.updateKeyMultibase).toBe(client.updateKeyMultibase)
    expect(again.recipientKid).toBe(client.recipientKid)
    // The roster kid is exactly the key-agreement key's own id, so the wrap
    // minted at issuance is the one the recovery read looks for.
    expect(client.recipientKid).toBe(client.agents.keyAgreementKey.id)
  })

  it('derives unrelated key sets from different codes', async () => {
    const client = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    const other = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    expect(other.clientDid).not.toBe(client.clientDid)
    expect(other.updateKeyMultibase).not.toBe(client.updateKeyMultibase)
  })

  it('derives a DIFFERENT unlock Space than the passphrase KDF for identical secret text', async () => {
    // A code and a passphrase that stringify alike must never collide: each
    // method's KDF pins its own salt.
    const text = generateRecoveryCode()
    const asCode = await deriveUnlockIdentity({
      secret: decodeRecoveryCode({ code: text }),
      kdf: RECOVERY_KDF
    })
    const asPassphrase = await deriveUnlockIdentity({
      secret: text,
      kdf: KEYRING_KDF
    })
    expect(asCode.spaceId).not.toBe(asPassphrase.spaceId)
  })
})

describe('the recovery record codec', () => {
  const pointer = {
    did: 'did:webvh:z6MkScid:localhost%3A8080:space:space-recovery:id',
    spaceId: SPACE_ID,
    host: WAS_URL
  }
  const delegation = {
    id: 'urn:zcap:delegated:example',
    controller: 'did:key:z6MkRecoveryClient',
    invocationTarget: `${WAS_URL}/space/${SPACE_ID}/id/did.jsonl`,
    allowedAction: ['PUT'],
    parentCapability: 'urn:zcap:root:example'
  } as unknown as IZcap

  it('round-trips pointer + delegation and never carries key material', async () => {
    const unlock = await deriveUnlockIdentity({
      secret: decodeRecoveryCode({ code: generateRecoveryCode() }),
      kdf: RECOVERY_KDF
    })
    const record = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      email: 'user@example.com',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver
    })
    const contents = await unwrapRecoveryRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver
    })
    expect(contents.controller).toBe('did:key:z6MkAccountController')
    expect(contents.email).toBe('user@example.com')
    expect(contents.pointer).toEqual(pointer)
    expect(contents.delegation).toEqual(delegation)

    // A recovery record IS a keyring record to the generic codec: an
    // ordinary unwrap recovers the pointer and ignores the delegation.
    const generic = await unwrapKeyringRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver
    })
    expect(generic.pointer).toEqual(pointer)
  })

  it('refuses a record without a delegation', async () => {
    const unlock = await deriveUnlockIdentity({
      secret: decodeRecoveryCode({ code: generateRecoveryCode() }),
      kdf: RECOVERY_KDF
    })
    const record = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver
    })
    const otherUnlock = await deriveUnlockIdentity({
      secret: decodeRecoveryCode({ code: generateRecoveryCode() }),
      kdf: RECOVERY_KDF
    })
    // A different code's unlock KAK cannot unwrap it at all.
    await expect(
      unwrapRecoveryRecord({
        record,
        keyAgreementKey: otherUnlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: otherUnlock.keyResolver
      })
    ).rejects.toThrow()
  })
})

/**
 * Provisions a fresh in-memory did:webvh log for one enrolled client and
 * returns the store, the client's update-key seeds, and the DID.
 */
async function provisionedLog(): Promise<{
  idStore: WebvhIdStore
  log: () => string | undefined
  updateKeys: ClientWebvhUpdateKeys
  did: string
}> {
  const { idStore, log } = memoryIdStore()
  const updateKeys = await mintClientWebvhUpdateKeys()
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    didWebKeys: {
      authentication: {
        vmId: `${DID_WEB}#z6MkAuth`,
        kmsKeyId: 'kms/keys/auth'
      },
      keyAgreement: { vmId: `${DID_WEB}#z6LSAgree`, kmsKeyId: 'kms/keys/agree' }
    },
    clientKeys: {
      signingKeyMultibase: 'z6MkFirstClientSigningKeyExample',
      keyAgreementKeyMultibase: 'z6LSFirstClientAgreementKeyExample'
    },
    updateKeys
  })
  return { idStore, log, updateKeys, did }
}

/**
 * Resolves the store's current log with full verification.
 */
async function resolved(log: () => string | undefined) {
  const result = await resolveDIDFromLog(readLogFromString(log()!), {
    verifier: defaultWebvhLogVerifier
  })
  expect(result.meta.error).toBeUndefined()
  return result
}

describe('the recovery did:webvh lifecycle', () => {
  it('publishes the split posture, runs the continuation, and retires the spent code', async () => {
    const { idStore, log, updateKeys, did } = await provisionedLog()

    // Issuance: the code's keyAgreement VM (recovery-marked) and its
    // update-key hash -- and nothing else: updateKeys untouched.
    const code = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    await publishRecoveryKey({
      idStore,
      updateKeys,
      recovery: {
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      }
    })
    let state = await resolved(log)
    const vmId = recoveryVmId({
      did,
      keyAgreementKeyMultibase: code.keyAgreementKeyMultibase
    })
    expect(
      state.doc?.verificationMethod?.some(method => method.id === vmId)
    ).toBe(true)
    expect(state.doc?.keyAgreement).toContain(vmId)
    expect(state.meta.updateKeys).not.toContain(code.updateKeyMultibase)
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(code.updateKeyMultibase)
    )
    const entriesAfterIssuance = readLogFromString(log()!).length

    // Idempotent: a re-run publishes nothing.
    await publishRecoveryKey({
      idStore,
      updateKeys,
      recovery: {
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      }
    })
    expect(readLogFromString(log()!).length).toBe(entriesAfterIssuance)

    // The continuation: reveal-and-commit, then add-and-retire.
    const newClientUpdateSeeds = await mintClientWebvhUpdateKeys()
    const newClientKeys = {
      signingKeyMultibase: 'z6MkRecoveredClientSigningKeyExampl',
      keyAgreementKeyMultibase: 'z6LSRecoveredClientAgreementKeyExpl',
      updateKeyMultibase: await updateKeyMultibase({
        seed: newClientUpdateSeeds.updateSeed
      }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: newClientUpdateSeeds.stagedSeed
      })
    }
    const replacement = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    const outcome = await recoverWebvhClient({
      store: idStore,
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      newClientKeys,
      newClientUpdateSeeds,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase
      }
    })
    expect(outcome.did).toBe(did)
    expect(outcome.webDoc).toBeDefined()
    expect(readLogFromString(log()!).length).toBe(entriesAfterIssuance + 2)

    state = await resolved(log)
    // The new client is an ordinary enrolled client: both VMs, all four
    // signing relations, its update key authorized, its staged key committed.
    expect(state.meta.updateKeys).toContain(newClientKeys.updateKeyMultibase)
    expect(state.doc?.capabilityInvocation).toContain(
      `${did}#${newClientKeys.signingKeyMultibase}`
    )
    expect(state.doc?.keyAgreement).toContain(
      `${did}#${newClientKeys.keyAgreementKeyMultibase}`
    )
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(newClientKeys.stagedUpdateKeyMultibase)
    )
    // The spent code is fully retired: VM gone, update key gone, hash gone.
    expect(state.doc?.keyAgreement).not.toContain(vmId)
    expect(state.meta.updateKeys).not.toContain(code.updateKeyMultibase)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(code.updateKeyMultibase)
    )
    // The replacement code's posture stands: VM published, hash committed,
    // no standing authority.
    const replacementVm = recoveryVmId({
      did,
      keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase
    })
    expect(state.doc?.keyAgreement).toContain(replacementVm)
    expect(state.meta.updateKeys).not.toContain(replacement.updateKeyMultibase)
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(replacement.updateKeyMultibase)
    )

    // Resumable: a re-run with the same key material is a no-op.
    const rerun = await recoverWebvhClient({
      store: idStore,
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      newClientKeys,
      newClientUpdateSeeds,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase
      }
    })
    expect(rerun.did).toBe(did)
    expect(readLogFromString(log()!).length).toBe(entriesAfterIssuance + 2)
  })

  it('refuses a continuation for a code the log no longer commits', async () => {
    const { idStore, updateKeys } = await provisionedLog()
    const code = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    // Never issued: no VM, no committed hash.
    const newClientUpdateSeeds = await mintClientWebvhUpdateKeys()
    await expect(
      recoverWebvhClient({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: {
          signingKeyMultibase: 'z6MkRecoveredClientSigningKeyExampl',
          keyAgreementKeyMultibase: 'z6LSRecoveredClientAgreementKeyExpl',
          updateKeyMultibase: await updateKeyMultibase({
            seed: newClientUpdateSeeds.updateSeed
          }),
          stagedUpdateKeyMultibase: await updateKeyMultibase({
            seed: newClientUpdateSeeds.stagedSeed
          })
        },
        newClientUpdateSeeds,
        replacement: {
          keyAgreementKeyMultibase: 'z6LSReplacementAgreementKeyExample',
          updateKeyMultibase: 'z6MkReplacementUpdateKeyExample'
        }
      })
    ).rejects.toThrow(RecoveryKeyNotCommittedError)

    // Issue then revoke: the posture is removed and the same refusal holds.
    await publishRecoveryKey({
      idStore,
      updateKeys,
      recovery: {
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      }
    })
    await removeRecoveryKey({
      idStore,
      updateKeys,
      recovery: {
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      }
    })
    // Idempotent removal.
    await removeRecoveryKey({
      idStore,
      updateKeys,
      recovery: {
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      }
    })
    await expect(
      recoverWebvhClient({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: {
          signingKeyMultibase: 'z6MkRecoveredClientSigningKeyExampl',
          keyAgreementKeyMultibase: 'z6LSRecoveredClientAgreementKeyExpl',
          updateKeyMultibase: await updateKeyMultibase({
            seed: newClientUpdateSeeds.updateSeed
          }),
          stagedUpdateKeyMultibase: await updateKeyMultibase({
            seed: newClientUpdateSeeds.stagedSeed
          })
        },
        newClientUpdateSeeds,
        replacement: {
          keyAgreementKeyMultibase: 'z6LSReplacementAgreementKeyExample',
          updateKeyMultibase: 'z6MkReplacementUpdateKeyExample'
        }
      })
    ).rejects.toThrow(RecoveryKeyNotCommittedError)
  })
})
