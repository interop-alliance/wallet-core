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
  RecoveryBindingError,
  recoveryRecordBinding,
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
import {
  RecordProofError,
  unwrapKeyringRecord,
  verifyRecordProof
} from '../../src/keyring/record.js'
import {
  ensureDidWebvh,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

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
    expect(again.bindingMacKey).toEqual(client.bindingMacKey)
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
    expect(other.bindingMacKey).not.toEqual(client.bindingMacKey)
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

  /**
   * A code's unlock identity and binding MAC key, as issuance and recovery
   * both derive them from the typed code.
   */
  async function codeUnlock() {
    const code = generateRecoveryCode()
    const { bindingMacKey } = await recoveryClientFromCode({ code })
    const unlock = await deriveUnlockIdentity({
      secret: decodeRecoveryCode({ code }),
      kdf: RECOVERY_KDF
    })
    return { ...unlock, bindingMacKey }
  }

  it('round-trips pointer + delegation and never carries key material', async () => {
    const unlock = await codeUnlock()
    const record = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const { contents, proofState } = await unwrapRecoveryRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      bindingMacKey: unlock.bindingMacKey
    })
    // An issuance-signed record is verified before it is decrypted.
    expect(proofState).toBe('verified')
    expect(contents.controller).toBe('did:key:z6MkAccountController')
    expect(contents.pointer).toEqual(pointer)
    expect(contents.delegation).toEqual(delegation)
    expect(Number.isNaN(Date.parse(contents.createdAt))).toBe(false)

    // A recovery record IS a keyring record to the generic codec: an
    // ordinary unwrap recovers the pointer and ignores the delegation.
    const generic = await unwrapKeyringRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase
    })
    expect(generic.pointer).toEqual(pointer)
  })

  it('stamps a supplied createdAt', async () => {
    const unlock = await codeUnlock()
    const createdAt = '2026-08-14T12:00:00.000Z'
    const record = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey,
      createdAt
    })
    const { contents } = await unwrapRecoveryRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      bindingMacKey: unlock.bindingMacKey
    })
    expect(contents.createdAt).toBe(createdAt)
  })

  it('returns the pending proof state for a re-minted record', async () => {
    // The revocation cascade's re-mint path holds only the code's KAK public
    // half, so an enrolled client signs the record with its account key. The
    // signer is unknowable before decryption, so the contents come back
    // marked pending and the caller finishes the check against the account's
    // verified document.
    const unlock = await codeUnlock()
    const client = await deriveUnlockIdentity({
      secret: 'an enrolled client key',
      kdf: RECOVERY_KDF
    })
    // Issuance writes the code-authenticated binding; the re-mint cannot
    // recompute it and carries it forward verbatim off the standing record.
    const issued = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const record = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: client.recordSigner,
      binding: recoveryRecordBinding({ record: issued })
    })

    const { contents, proofState } = await unwrapRecoveryRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.recordSigner.keyMultibase,
      bindingMacKey: unlock.bindingMacKey
    })
    expect(contents.pointer).toEqual(pointer)
    expect(proofState).toEqual({
      pending: {
        verificationMethod: `did:key:${client.recordSigner.keyMultibase}#${client.recordSigner.keyMultibase}`,
        keyMultibase: client.recordSigner.keyMultibase
      }
    })

    // The second phase: the same standalone verification against the keys the
    // verified did:webvh document lists.
    await expect(
      verifyRecordProof({
        record,
        allowedKeyMultibases: [
          `${pointer.did}#${client.recordSigner.keyMultibase}`
        ],
        label: 'recovery'
      })
    ).resolves.toBe(client.recordSigner.keyMultibase)

    // A signer in neither class ends in the typed proof refusal.
    await expect(
      verifyRecordProof({
        record,
        allowedKeyMultibases: [`${pointer.did}#z6MkSomeOtherClientKey`],
        label: 'recovery'
      })
    ).rejects.toThrow(RecordProofError)
  })

  it('refuses a record whose proof does not verify', async () => {
    const unlock = await codeUnlock()
    const record = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })

    // A frame the host tampered with, keeping the original proof: the
    // signature no longer covers what is served, and the refusal lands before
    // anything is decrypted.
    await expect(
      unwrapRecoveryRecord({
        record: {
          ...record,
          wrapped: { ...(record.wrapped as object), extra: 'x' }
        },
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.recordSigner.keyMultibase,
        bindingMacKey: unlock.bindingMacKey
      })
    ).rejects.toThrow(RecordProofError)
  })

  it('refuses a record another code cannot unwrap', async () => {
    const unlock = await codeUnlock()
    const record = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const otherUnlock = await codeUnlock()
    // A different code's unlock KAK cannot unwrap it at all -- and its proof
    // is by neither the expected key nor an account key, so the unwrap comes
    // back pending and the decrypt fails.
    await expect(
      unwrapRecoveryRecord({
        record,
        keyAgreementKey: otherUnlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: otherUnlock.keyResolver,
        expectedKeyMultibase: otherUnlock.recordSigner.keyMultibase,
        bindingMacKey: otherUnlock.bindingMacKey
      })
    ).rejects.toThrow()
  })

  it('refuses a forged record whose binding another code (or no code) wrote', async () => {
    // The host-forgery redirect FW-160 closes: the attacker re-encrypts a
    // record of its own to the code's unlock KAK (its public half is in the
    // stored frame), points it at an attacker-controlled account, and signs
    // with that account's enrolled client key -- the pending-proof path. It
    // never holds the code bytes, so the best it can do for the binding is a
    // tag under some other key; the unwrap refuses before the pointer is
    // trusted.
    const unlock = await codeUnlock()
    const attacker = await codeUnlock()
    const attackerSigner = (
      await deriveUnlockIdentity({
        secret: 'an attacker account client key',
        kdf: RECOVERY_KDF
      })
    ).recordSigner
    const forged = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAttackerController',
      pointer: {
        did: 'did:webvh:z6MkAttackerScid:evil.example:space:stolen:id',
        spaceId: 'stolen',
        host: 'https://evil.example'
      },
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: attackerSigner,
      bindingMacKey: attacker.bindingMacKey
    })
    await expect(
      unwrapRecoveryRecord({
        record: forged,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.recordSigner.keyMultibase,
        bindingMacKey: unlock.bindingMacKey
      })
    ).rejects.toThrow(RecoveryBindingError)

    // Copying the victim record's genuine binding does not help either: the
    // tag covers the binding values, so it does not verify over the
    // attacker's pointer.
    const genuine = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const redirected = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAttackerController',
      pointer: {
        did: 'did:webvh:z6MkAttackerScid:evil.example:space:stolen:id',
        spaceId: 'stolen',
        host: 'https://evil.example'
      },
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: attackerSigner,
      binding: recoveryRecordBinding({ record: genuine })
    })
    await expect(
      unwrapRecoveryRecord({
        record: redirected,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.recordSigner.keyMultibase,
        bindingMacKey: unlock.bindingMacKey
      })
    ).rejects.toThrow(RecoveryBindingError)
  })

  it('refuses a record with no binding, and requires exactly one binding input to wrap', async () => {
    const unlock = await codeUnlock()
    const record = await wrapRecoveryRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const { binding, ...stripped } = record
    expect(typeof binding).toBe('string')
    expect(() => recoveryRecordBinding({ record: stripped })).toThrow(
      RecoveryBindingError
    )
    await expect(
      unwrapRecoveryRecord({
        record: stripped,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.recordSigner.keyMultibase,
        bindingMacKey: unlock.bindingMacKey
      })
    ).rejects.toThrow(RecoveryBindingError)

    await expect(
      wrapRecoveryRecord({
        controller: 'did:key:z6MkAccountController',
        pointer,
        delegation,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        signer: unlock.recordSigner
      })
    ).rejects.toThrow(/Exactly one/)
    await expect(
      wrapRecoveryRecord({
        controller: 'did:key:z6MkAccountController',
        pointer,
        delegation,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        signer: unlock.recordSigner,
        bindingMacKey: unlock.bindingMacKey,
        binding: 'both'
      })
    ).rejects.toThrow(/Exactly one/)
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
      ...CANONICAL_CLIENT_KEYS[0]
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
  it('refuses a continuation whose new client is not a canonical key pair', async () => {
    const { idStore, updateKeys } = await provisionedLog()
    const code = await recoveryClientFromCode({ code: generateRecoveryCode() })
    await publishRecoveryKey({
      idStore,
      updateKeys,
      recovery: {
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      }
    })
    const newClientUpdateSeeds = await mintClientWebvhUpdateKeys()
    const replacement = await recoveryClientFromCode({
      code: generateRecoveryCode()
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
          signingKeyMultibase: CANONICAL_CLIENT_KEYS[3].signingKeyMultibase,
          keyAgreementKeyMultibase:
            CANONICAL_CLIENT_KEYS[4].keyAgreementKeyMultibase,
          updateKeyMultibase: await updateKeyMultibase({
            seed: newClientUpdateSeeds.updateSeed
          }),
          stagedUpdateKeyMultibase: await updateKeyMultibase({
            seed: newClientUpdateSeeds.stagedSeed
          })
        },
        newClientUpdateSeeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        }
      })
    ).rejects.toThrow(/canonical X25519 twin/)
  })

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
      ...CANONICAL_CLIENT_KEYS[3],
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

    // The entry's three-way controller split, which is what tells the two
    // simultaneously published keyAgreement methods apart: the new client's
    // signing key is controlled by the account, its key-agreement key carries
    // the client's controller marker, and the replacement code's key stays
    // deliberately unmarked so no listing or removal ever matches it.
    const controllerOf = (methodId: string) =>
      (state.doc?.verificationMethod ?? []).find(
        (method: { id?: string }) => method.id === methodId
      )?.controller
    expect(controllerOf(`${did}#${newClientKeys.signingKeyMultibase}`)).toBe(
      did
    )
    expect(
      controllerOf(`${did}#${newClientKeys.keyAgreementKeyMultibase}`)
    ).toBe(`did:key:${newClientKeys.signingKeyMultibase}`)
    expect(controllerOf(replacementVm)).toBe(did)

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
          ...CANONICAL_CLIENT_KEYS[3],
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
          ...CANONICAL_CLIENT_KEYS[3],
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
