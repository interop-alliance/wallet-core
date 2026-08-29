/**
 * Unit tests for recovery codes on the roster identity model
 * (`src/recovery/`): the format layer (shape, display grouping, entry
 * normalization, malformed-code rejection), the deterministic
 * client-key derivation (same code, same key set -- across formatting
 * -- and its distinct unlock Space vs the passphrase KDF for identical
 * secret text), the recovery-record codec (pointer + delegation, never key
 * material), and the did:webvh lifecycle end to end against an in-memory
 * store: issuance's split configuration, the self-enrolling recovery continuation
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
  remintUnlockRecordDelegations,
  UnlockBindingError,
  unlockRecordBinding,
  unwrapUnlockRecord,
  wrapUnlockRecord
} from '../../src/unlock/unlockRecord.js'
import {
  publishRecoveryKey,
  recoverWebvhClient,
  RecoveryKeyNotCommittedError,
  recoveryVmId,
  removeRecoveryKey,
  type RecoveryLogStore
} from '../../src/recovery/recoveryWebvh.js'
import { recoverWebvhLadderAnchored } from '../../src/clientAnnex/recoveryLadderAnchored.js'
import { delegatedClientsPointer } from '../../src/clientAnnex/log.js'
import {
  attributeLadderInventory,
  generateLadderSeed,
  ladderRung,
  ladderVmKeyMultibase
} from '../../src/clientAnnex/ladder.js'
import { ladderVmIds } from '../../src/webvh/listClients.js'
import {
  publishUnlockKey,
  removeUnlockKey,
  unlockKeyVmId
} from '../../src/unlock/standingWebvh.js'
import { deriveUnlockIdentity, KEYRING_KDF } from '../../src/keyring/kdf.js'
import {
  RecordProofError,
  unwrapKeyringRecord,
  verifyRecordProof
} from '../../src/keyring/record.js'
import {
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  pinOfLog,
  updateKeyMultibase,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { accountLogPinId } from '../../src/webvh/verifyLog.js'
import {
  memoryResourceLogPinStore,
  ResourceLogContinuityError
} from '@interop/vh-resource-log'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { truncatingLogStore } from './fixtures/truncatingLogStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-recovery'
const DID_WEB = `did:web:localhost%3A8080:space:${SPACE_ID}:id`

/**
 * The account log's pin slot for this suite's fixtures.
 */
const LOG_ID = accountLogPinId({ spaceId: SPACE_ID })

/**
 * A no-op `onCommitted` seam for call sites where the persist-before-publish
 * pivot itself is not under test.
 */
async function noopCommitted(): Promise<void> {}

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
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const { contents, proofState } = await unwrapUnlockRecord({
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
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey,
      createdAt
    })
    const { contents } = await unwrapUnlockRecord({
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
    // recompute it and carries shell and binding forward verbatim, replacing
    // only the bridge.
    const issued = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const record = await remintUnlockRecordDelegations({
      record: issued,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: client.recordSigner
    })

    const { contents, proofState } = await unwrapUnlockRecord({
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
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })

    // A frame the host tampered with, keeping the original proof: the
    // signature no longer covers what is served, and the refusal lands before
    // anything is decrypted.
    await expect(
      unwrapUnlockRecord({
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
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const otherUnlock = await codeUnlock()
    // A different code's unlock KAK cannot unwrap it at all -- and its proof
    // is by neither the expected key nor an account key, so the unwrap comes
    // back pending and the decrypt fails.
    await expect(
      unwrapUnlockRecord({
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
    const forged = await wrapUnlockRecord({
      controller: 'did:key:z6MkAttackerController',
      pointer: {
        did: 'did:webvh:z6MkAttackerScid:evil.example:space:stolen:id',
        spaceId: 'stolen',
        host: 'https://evil.example'
      },
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: attackerSigner,
      bindingMacKey: attacker.bindingMacKey
    })
    await expect(
      unwrapUnlockRecord({
        record: forged,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.recordSigner.keyMultibase,
        bindingMacKey: unlock.bindingMacKey
      })
    ).rejects.toThrow(UnlockBindingError)

    // Splicing the victim record's genuine binding onto the forged record
    // does not help either: the tag covers the binding values, so it does not
    // verify over the attacker's pointer.
    const genuine = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const redirected = {
      ...forged,
      binding: unlockRecordBinding({ record: genuine })
    }
    await expect(
      unwrapUnlockRecord({
        record: redirected,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.recordSigner.keyMultibase,
        bindingMacKey: unlock.bindingMacKey
      })
    ).rejects.toThrow(UnlockBindingError)
  })

  it('refuses a record with no binding, on unwrap and on re-mint alike', async () => {
    const unlock = await codeUnlock()
    const record = await wrapUnlockRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      delegation,
      keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
      signer: unlock.recordSigner,
      bindingMacKey: unlock.bindingMacKey
    })
    const { binding, ...stripped } = record
    expect(typeof binding).toBe('string')
    expect(() => unlockRecordBinding({ record: stripped })).toThrow(
      UnlockBindingError
    )
    await expect(
      unwrapUnlockRecord({
        record: stripped,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.recordSigner.keyMultibase,
        bindingMacKey: unlock.bindingMacKey
      })
    ).rejects.toThrow(UnlockBindingError)
    await expect(
      remintUnlockRecordDelegations({
        record: stripped,
        delegation,
        keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
        signer: unlock.recordSigner
      })
    ).rejects.toThrow(UnlockBindingError)
  })
})

/**
 * Provisions a fresh in-memory did:webvh log for one enrolled client and
 * returns the store, the client's update-key seeds, and the DID.
 *
 * @param [options] {object}
 * @param [options.updateKeys] {ClientWebvhUpdateKeys}   the founding client's
 *   update-key seeds, where a caller needs two separately provisioned
 *   accounts to agree on everything except the account DID itself (defaults
 *   to a fresh mint)
 */
async function provisionedLog(options?: {
  updateKeys?: ClientWebvhUpdateKeys
}): Promise<{
  idStore: WebvhIdStore
  log: () => string | undefined
  updateKeys: ClientWebvhUpdateKeys
  did: string
}> {
  const { idStore, log } = memoryIdStore()
  const updateKeys = options?.updateKeys ?? (await mintClientWebvhUpdateKeys())
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

/**
 * A freshly minted ordinary client's public halves plus its update seeds --
 * what a continuation enrolls.
 */
async function mintedClient(index: number) {
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
 * The resolved log's final state with the account DID replaced by a stable
 * label, so a torn-and-resumed run can be compared against an untorn run on
 * a DIFFERENT account (necessarily a different SCID, since `ensureDidWebvh`
 * mints a fresh genesis each call) once the DID is factored out. Valid only
 * when both runs spend the SAME recovery code, the SAME new client keys, and
 * the SAME replacement code -- otherwise the hashes and multibases embedded
 * in the document would differ for reasons unrelated to the tear itself.
 */
async function recoveryConvergenceShape({
  log,
  did
}: {
  log: () => string | undefined
  did: string
}): Promise<object> {
  const state = await resolved(log)
  const label = (text: string) => text.split(did).join('<account>')
  return {
    updateKeys: (state.meta.updateKeys ?? []).map(label).sort(),
    nextKeyHashes: [...(state.meta.nextKeyHashes ?? [])].sort(),
    doc: JSON.parse(label(JSON.stringify(state.doc))) as object
  }
}

/**
 * A store wrapper serving a STALE ETag validator (the live log text
 * unchanged) from the given 1-based `did.jsonl` read onwards -- the
 * interleave a concurrent ceremony produces, which makes the entry built on
 * that read lose its compare-and-swap.
 *
 * @param options {object}
 * @param options.idStore {WebvhIdStore}
 * @param options.fromRead {number}
 * @param [options.reads] {number}   how many reads keep serving the stale
 *   validator (default: every read from `fromRead` on)
 * @returns {WebvhIdStore}
 */
function staleEtagFromRead({
  idStore,
  fromRead,
  reads = Number.POSITIVE_INFINITY
}: {
  idStore: WebvhIdStore
  fromRead: number
  reads?: number
}): WebvhIdStore {
  let count = 0
  return {
    ...idStore,
    async getIdResourceRaw(options: { resourceId: string }) {
      const served = await idStore.getIdResourceRaw(options)
      if (served === undefined) {
        return served
      }
      count += 1
      const staled = count >= fromRead && count < fromRead + reads
      return staled ? { ...served, etag: '"stale"' } : served
    }
  }
}

describe('the recovery did:webvh lifecycle', () => {
  it('refuses a continuation whose new client is not a canonical key pair, before any read', async () => {
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
    // The refusal must land before the first read: past it, the reveal entry
    // would publish and the persist seam would fire for a continuation that
    // can only ever throw at the add-and-retire build.
    let reads = 0
    const store: RecoveryLogStore = {
      ...idStore,
      async getIdResourceRaw(options: { resourceId: string }) {
        reads += 1
        return idStore.getIdResourceRaw(options)
      }
    }
    let seamFired = false

    await expect(
      recoverWebvhClient({
        store,
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
        },
        onCommitted: async () => {
          seamFired = true
        }
      })
    ).rejects.toThrow(/canonical X25519 twin/)
    expect(reads).toBe(0)
    expect(seamFired).toBe(false)
  })

  it('publishes the split configuration, runs the continuation, and retires the spent code', async () => {
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
      },
      onCommitted: noopCommitted
    })
    expect(outcome.did).toBe(did)
    expect(outcome.webDoc).toBeDefined()
    expect(outcome.committed).toBe(true)
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
    // The replacement code's inventory stands: VM published, hash committed,
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
      },
      onCommitted: noopCommitted
    })
    expect(rerun.did).toBe(did)
    expect(rerun.committed).toBe(false)
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
        },
        onCommitted: noopCommitted
      })
    ).rejects.toThrow(RecoveryKeyNotCommittedError)

    // Issue then revoke: the inventory is removed and the same refusal holds.
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
        },
        onCommitted: noopCommitted
      })
    ).rejects.toThrow(RecoveryKeyNotCommittedError)
  })

  /**
   * Issues a code on a provisioned log and spends it: the continuation
   * commits THREE hashes under the code's own authority -- the new client's
   * update- and staged-key hashes and the replacement code's, which belongs
   * to the successor rather than to the spent code.
   */
  async function spentCode() {
    const provisioned = await provisionedLog()
    const { idStore, updateKeys, did } = provisioned
    const code = await recoveryClientFromCode({ code: generateRecoveryCode() })
    await publishRecoveryKey({
      idStore,
      updateKeys,
      recovery: {
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      }
    })
    const recovered = await mintedClient(3)
    const replacement = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    await recoverWebvhClient({
      store: idStore,
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      newClientKeys: recovered.keys,
      newClientUpdateSeeds: recovered.seeds,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase
      },
      onCommitted: noopCommitted
    })
    return {
      ...provisioned,
      code,
      recovered,
      replacement,
      replacementHash: await deriveNextKeyHash(replacement.updateKeyMultibase),
      replacementVmId: recoveryVmId({
        did,
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase
      }),
      spentVmId: recoveryVmId({
        did,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase
      })
    }
  }

  it("attributes a spend's third committed hash to the successor", async () => {
    const { log, code, recovered, replacementHash, spentVmId } =
      await spentCode()
    const inventory = async (options: { credentialVmId?: string }) =>
      attributeLadderInventory({
        log: readLogFromString(log()!),
        anchorKeyMultibase: code.updateKeyMultibase,
        ...options
      })

    // The spend's own entry retires the code's verification method, so the
    // hash left over after the new client's pair is its SUCCESSOR's, not a
    // rung this credential ever climbs to.
    const attributed = await inventory({ credentialVmId: spentVmId })
    expect(attributed.committedHashes).not.toContain(replacementHash)
    expect(attributed.committedHashes).toEqual([])
    expect(attributed.revealedKeys).toEqual([])
    // The recovered client's own hashes transferred to it, as before.
    expect(attributed.committedHashes).not.toContain(
      await deriveNextKeyHash(recovered.keys.stagedUpdateKeyMultibase)
    )
    // Without the credential's verification-method id nothing can be
    // attributed positively, and the walk releases rather than over-claims.
    expect((await inventory({})).committedHashes).not.toContain(replacementHash)
  })

  it(
    "leaves the replacement code's commitment standing when the spent code " +
      'is retired',
    async () => {
      const {
        idStore,
        log,
        updateKeys,
        code,
        replacement,
        replacementHash,
        replacementVmId
      } = await spentCode()

      // Retiring the spent code from the registry: everything of the code
      // itself is already gone, so this is the residue-only case.
      await removeRecoveryKey({
        idStore,
        updateKeys,
        recovery: {
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        }
      })
      const state = await resolved(log)
      expect(state.doc?.keyAgreement).toContain(replacementVmId)
      expect(state.meta.nextKeyHashes).toContain(replacementHash)

      // The whole point: the replacement code is still spendable. A struck
      // commitment fails closed here, and nothing would ever heal it.
      const second = await mintedClient(5)
      const secondReplacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      await recoverWebvhClient({
        store: idStore,
        recovery: {
          updateSeed: replacement.updateSeed,
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        newClientKeys: second.keys,
        newClientUpdateSeeds: second.seeds,
        replacement: {
          keyAgreementKeyMultibase: secondReplacement.keyAgreementKeyMultibase,
          updateKeyMultibase: secondReplacement.updateKeyMultibase
        },
        onCommitted: noopCommitted
      })
      expect((await resolved(log)).meta.updateKeys).toContain(
        second.keys.updateKeyMultibase
      )
    }
  )

  describe('the persist-before-publish seam', () => {
    it('fires between the reveal-and-commit entry and the add-and-retire entry', async () => {
      const { idStore, log, updateKeys } = await provisionedLog()
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
      const recovered = await mintedClient(3)
      const replacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      const entriesBeforeSpend = readLogFromString(log()!).length
      const observed: {
        updateKeysHasSpent?: boolean
        updateKeysHasNew?: boolean
        builtOnHead?: { scid: string; versionId: string }
      } = {}

      const outcome = await recoverWebvhClient({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async ({ builtOnHead }) => {
          const state = await resolved(log)
          observed.updateKeysHasSpent = state.meta.updateKeys.includes(
            code.updateKeyMultibase
          )
          observed.updateKeysHasNew = state.meta.updateKeys.includes(
            recovered.keys.updateKeyMultibase
          )
          observed.builtOnHead = builtOnHead
        }
      })

      expect(outcome.committed).toBe(true)
      // The reveal-and-commit entry stood at hook time: the spent code's
      // update key had joined `updateKeys`, but the new client's had not.
      expect(observed.updateKeysHasSpent).toBe(true)
      expect(observed.updateKeysHasNew).toBe(false)
      const entries = readLogFromString(log()!)
      expect(observed.builtOnHead).toEqual({
        scid: entries[0]!.parameters.scid,
        // Genesis, issuance, the reveal-and-commit entry: the head the hook
        // was handed IS the head the add-and-retire entry then built on.
        versionId: entries[entriesBeforeSpend]!.versionId
      })
      expect(entries).toHaveLength(entriesBeforeSpend + 2)
    })

    it('withholds the add-and-retire entry when the seam throws, and a re-run converges with an untorn run', async () => {
      const torn = await provisionedLog()
      const code = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      await publishRecoveryKey({
        idStore: torn.idStore,
        updateKeys: torn.updateKeys,
        recovery: {
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        }
      })
      const recovered = await mintedClient(3)
      const replacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      const entriesBeforeSpend = readLogFromString(torn.log()!).length
      const persistFailed = new Error('the pending record could not be saved')

      const caught = await recoverWebvhClient({
        store: torn.idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => {
          throw persistFailed
        }
      }).catch((err: unknown) => err)

      expect(caught).toBe(persistFailed)
      // Only the reveal-and-commit entry landed; the pivot is withheld, so
      // the spent code's VM still stands and the new client's update key
      // never joined `updateKeys`.
      expect(readLogFromString(torn.log()!).length).toBe(entriesBeforeSpend + 1)
      const spentVmId = recoveryVmId({
        did: torn.did,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase
      })
      let state = await resolved(torn.log)
      expect(state.doc?.keyAgreement).toContain(spentVmId)
      expect(state.meta.updateKeys).not.toContain(
        recovered.keys.updateKeyMultibase
      )

      const resumed = await recoverWebvhClient({
        store: torn.idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: noopCommitted
      })
      expect(resumed.committed).toBe(true)
      expect(readLogFromString(torn.log()!).length).toBe(entriesBeforeSpend + 2)
      state = await resolved(torn.log)
      expect(state.doc?.keyAgreement).not.toContain(spentVmId)
      expect(state.meta.updateKeys).toContain(recovered.keys.updateKeyMultibase)

      // An untorn run on a fresh account (SAME founding-client update keys,
      // so only the DID -- the SCID -- differs), spending the SAME code with
      // the SAME new client and replacement: the two final states agree once
      // the account-specific DID is labeled away.
      const untorn = await provisionedLog({ updateKeys: torn.updateKeys })
      await publishRecoveryKey({
        idStore: untorn.idStore,
        updateKeys: untorn.updateKeys,
        recovery: {
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        }
      })
      await recoverWebvhClient({
        store: untorn.idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: noopCommitted
      })

      expect(
        await recoveryConvergenceShape({ log: torn.log, did: torn.did })
      ).toEqual(
        await recoveryConvergenceShape({ log: untorn.log, did: untorn.did })
      )
    })

    it('skips the seam on the completed branch and reports committed: false', async () => {
      const { idStore, updateKeys, did } = await provisionedLog()
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
      const recovered = await mintedClient(3)
      const replacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      let calls = 0
      const options = {
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => {
          calls += 1
        }
      }

      const first = await recoverWebvhClient(options)
      const second = await recoverWebvhClient(options)

      expect(first.committed).toBe(true)
      expect(second.committed).toBe(false)
      expect(second.did).toBe(did)
      expect(calls).toBe(1)
    })

    it('refuses a call with no onCommitted, before any read', async () => {
      const { idStore } = await provisionedLog()
      let reads = 0
      const store: RecoveryLogStore = {
        ...idStore,
        async getIdResourceRaw(options: { resourceId: string }) {
          reads += 1
          return idStore.getIdResourceRaw(options)
        }
      }
      const recovered = await mintedClient(3)
      const replacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })

      const caught = await recoverWebvhClient({
        store,
        recovery: {
          updateSeed: new Uint8Array(32),
          keyAgreementKeyMultibase: 'z6LSPlaceholderAgreementKey',
          updateKeyMultibase: 'z6MkPlaceholderUpdateKey'
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        }
      } as unknown as Parameters<typeof recoverWebvhClient>[0]).catch(
        (err: unknown) => err
      )

      expect(caught).toBeInstanceOf(TypeError)
      expect((caught as TypeError).message).toMatch(/onCommitted/)
      expect(reads).toBe(0)
    })

    it('advances the pin to the head each entry publishes', async () => {
      const { idStore, log, updateKeys, did } = await provisionedLog()
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
      const recovered = await mintedClient(3)
      const replacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      const pinStore = memoryResourceLogPinStore()

      const outcome = await recoverWebvhClient({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: noopCommitted,
        expectedDid: did,
        pinStore,
        logId: LOG_ID
      })

      expect(outcome.committed).toBe(true)
      expect(await pinStore.read({ logId: LOG_ID })).toEqual(
        pinOfLog(readLogFromString(log()!))
      )
    })

    it('refuses a served prefix of the pinned log before any entry publishes', async () => {
      const { idStore, log, updateKeys, did } = await provisionedLog()
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
      const pinStore = memoryResourceLogPinStore()
      await pinStore.write({
        logId: LOG_ID,
        pin: pinOfLog(readLogFromString(log()!))
      })
      const { store } = truncatingLogStore({ idStore, dropEntries: 1 })
      const recovered = await mintedClient(3)
      const replacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      const logBefore = log()

      const caught = await recoverWebvhClient({
        store,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: noopCommitted,
        expectedDid: did,
        pinStore,
        logId: LOG_ID
      }).catch((err: unknown) => err)

      expect(caught).toBeInstanceOf(ResourceLogContinuityError)
      expect((caught as ResourceLogContinuityError).reason).toBe('rollback')
      expect(log()).toBe(logBefore)
    })

    it('re-fires the seam on a lost compare-and-swap, and the ceremony converges', async () => {
      const { idStore, log, updateKeys, did } = await provisionedLog()
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
      const recovered = await mintedClient(3)
      const replacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      const entriesBeforeSpend = readLogFromString(log()!).length
      // The post-reveal re-read of the first attempt alone serves a stale
      // validator, so that attempt's add-and-retire entry loses its CAS and
      // the whole attempt retries from the top.
      const store = staleEtagFromRead({ idStore, fromRead: 2, reads: 1 })
      const seen: Array<{ scid: string; versionId: string }> = []

      const outcome = await recoverWebvhClient({
        store,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async ({ builtOnHead }) => {
          seen.push(builtOnHead)
        },
        expectedDid: did
      })

      expect(outcome.committed).toBe(true)
      // Once per attempt: the first attempt's seam call precedes the add
      // entry that then loses its CAS; the retried attempt's reveal entry is
      // already standing, so it re-enters the seam once more before its own
      // (this time successful) add entry.
      expect(seen).toHaveLength(2)
      expect(seen[1]).toEqual(seen[0])
      expect(readLogFromString(log()!).length).toBe(entriesBeforeSpend + 2)
    })
  })
})

/**
 * A well-formed annex generation DID for the continuation's pointer seam;
 * these ceremony tests exercise the account log, never the annex Space.
 */
const FIXTURE_GENERATION =
  'did:webvh:QmAnnexScid:was.example:space:aux-space:gen-aaaaaaaaaaaaaaaa'

describe('the transient-recovery (ladder-anchored) continuation', () => {
  /**
   * Issues a code on a provisioned log and runs the ladder-anchored
   * continuation with a fresh credential ladder and replacement code,
   * returning everything the assertions need.
   */
  async function ladderRecoveryFixture() {
    const provisioned = await provisionedLog()
    const { idStore, log, updateKeys, did } = provisioned
    const code = await recoveryClientFromCode({ code: generateRecoveryCode() })
    await publishRecoveryKey({
      idStore,
      updateKeys,
      recovery: {
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      }
    })
    const ladderSeed = generateLadderSeed()
    const credentialKeyAgreement = {
      commitment: await keyAgreementCommitment({
        keyAgreementKeyMultibase:
          CANONICAL_CLIENT_KEYS[3]!.keyAgreementKeyMultibase
      })
    }
    const replacement = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    return {
      idStore,
      log,
      updateKeys,
      did,
      code,
      ladderSeed,
      credentialKeyAgreement,
      replacement
    }
  }

  it(
    "publishes the fresh credential's ladder VM in place of an enrolled " +
      'client, retires the spent code, and installs the replacement',
    async () => {
      const {
        idStore,
        log,
        updateKeys,
        did,
        code,
        ladderSeed,
        credentialKeyAgreement,
        replacement
      } = await ladderRecoveryFixture()
      const entriesAfterIssuance = readLogFromString(log()!).length
      const ladderVmKey = await ladderVmKeyMultibase({ ladderSeed })
      const ladderVmId = `${did}#${ladderVmKey}`

      // The persist-before-publish seam: at onCommitted time the reveal
      // entry stands and the ladder VM is NOT yet published.
      const observedAtCommit: { entries?: number; hasLadderVm?: boolean } = {}
      const outcome = await recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed,
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => {
          const entries = readLogFromString(log()!)
          observedAtCommit.entries = entries.length
          const state = await resolved(log)
          observedAtCommit.hasLadderVm = (
            state.doc?.verificationMethod ?? []
          ).some((method: { id?: string }) => method.id === ladderVmId)
          return { clientAnnexDid: FIXTURE_GENERATION }
        }
      })
      expect(outcome.did).toBe(did)
      expect(outcome.webDoc).toBeDefined()
      expect(observedAtCommit.entries).toBe(entriesAfterIssuance + 1)
      expect(observedAtCommit.hasLadderVm).toBe(false)
      expect(readLogFromString(log()!).length).toBe(entriesAfterIssuance + 2)

      const state = await resolved(log)
      const rung0 = await ladderRung({ ladderSeed, index: 0 })
      const rung1 = await ladderRung({ ladderSeed, index: 1 })

      // The ladder VM stands under the relation asymmetry: assertionMethod
      // and capabilityDelegation only.
      expect(
        state.doc?.verificationMethod?.some(
          (method: { id?: string }) => method.id === ladderVmId
        )
      ).toBe(true)
      expect(state.doc?.assertionMethod).toContain(ladderVmId)
      expect(state.doc?.capabilityDelegation).toContain(ladderVmId)
      expect(state.doc?.capabilityInvocation).not.toContain(ladderVmId)
      expect(state.doc?.authentication).not.toContain(ladderVmId)
      expect(ladderVmIds({ doc: state.doc! })).toEqual([ladderVmId])

      // Rung 0 replaces the spent code's key in the update authority; the
      // enrolled client's own update key survives untouched.
      expect(state.meta.updateKeys).toContain(rung0.keyMultibase)
      expect(state.meta.updateKeys).not.toContain(code.updateKeyMultibase)
      expect(state.meta.updateKeys).toContain(
        await updateKeyMultibase({ seed: updateKeys.updateSeed })
      )
      // Rung 0's carry-over hash and rung 1's staged hash stand; the spent
      // code's hash is gone; the replacement's is committed.
      expect(state.meta.nextKeyHashes).toContain(
        await deriveNextKeyHash(rung0.keyMultibase)
      )
      expect(state.meta.nextKeyHashes).toContain(
        await deriveNextKeyHash(rung1.keyMultibase)
      )
      expect(state.meta.nextKeyHashes).not.toContain(
        await deriveNextKeyHash(code.updateKeyMultibase)
      )
      expect(state.meta.nextKeyHashes).toContain(
        await deriveNextKeyHash(replacement.updateKeyMultibase)
      )

      // The fresh credential's keyAgreement entry (the commitment)
      // is folded into the same atomic entry -- the mandatory rotation's
      // recipient resolver backs its standing wrap with it.
      const commitmentVmId = `${did}#${credentialKeyAgreement.commitment}`
      expect(state.doc?.keyAgreement).toContain(commitmentVmId)
      const commitmentVm = (state.doc?.verificationMethod ?? []).find(
        (method: { id?: string }) => method.id === commitmentVmId
      ) as { type?: string; controller?: string; publicKeyCommitment?: string }
      expect(commitmentVm?.type).toBe('MultikeyCommitment')
      expect(commitmentVm?.controller).toBe(did)
      expect(commitmentVm?.publicKeyCommitment).toBe(
        credentialKeyAgreement.commitment
      )

      // The spent code's VM is gone; the replacement's stands, unmarked.
      const spentVmId = recoveryVmId({
        did,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase
      })
      const replacementVmId = recoveryVmId({
        did,
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase
      })
      expect(state.doc?.keyAgreement).not.toContain(spentVmId)
      expect(state.doc?.keyAgreement).toContain(replacementVmId)
      expect(state.meta.updateKeys).not.toContain(
        replacement.updateKeyMultibase
      )

      // Resumable: a re-run with the same key material is a no-op, and the
      // persist seam is not re-entered.
      let reentered = false
      const rerun = await recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed,
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => {
          reentered = true
          return { clientAnnexDid: FIXTURE_GENERATION }
        }
      })
      expect(rerun.did).toBe(did)
      expect(reentered).toBe(false)
      expect(readLogFromString(log()!).length).toBe(entriesAfterIssuance + 2)
    }
  )

  it(
    "retiring the spent code leaves the replacement's commitment and the " +
      "fresh credential's ladder standing",
    async () => {
      const {
        idStore,
        log,
        updateKeys,
        did,
        code,
        ladderSeed,
        credentialKeyAgreement,
        replacement
      } = await ladderRecoveryFixture()
      await recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed,
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION })
      })

      // This continuation's reveal entry commits three hashes under the spent
      // code's authority and NONE of them is the code's own: the fresh
      // credential's rung 0 and rung 1, and the replacement code's.
      const rung0 = await ladderRung({ ladderSeed, index: 0 })
      const rung1 = await ladderRung({ ladderSeed, index: 1 })
      await removeRecoveryKey({
        idStore,
        updateKeys,
        recovery: {
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        }
      })

      let state = await resolved(log)
      expect(state.meta.nextKeyHashes).toContain(
        await deriveNextKeyHash(replacement.updateKeyMultibase)
      )
      expect(state.doc?.keyAgreement).toContain(
        recoveryVmId({
          did,
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase
        })
      )
      // The fresh credential the continuation installed is untouched too:
      // rung 0 authorized, rung 1 committed, its ladder VM standing.
      expect(state.meta.updateKeys).toContain(rung0.keyMultibase)
      expect(state.meta.nextKeyHashes).toContain(
        await deriveNextKeyHash(rung1.keyMultibase)
      )
      expect(ladderVmIds({ doc: state.doc! })).toEqual([
        `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
      ])

      // And the replacement code is still spendable.
      const recovered = await mintedClient(5)
      const secondReplacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      await recoverWebvhClient({
        store: idStore,
        recovery: {
          updateSeed: replacement.updateSeed,
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: secondReplacement.keyAgreementKeyMultibase,
          updateKeyMultibase: secondReplacement.updateKeyMultibase
        },
        onCommitted: noopCommitted
      })
      state = await resolved(log)
      expect(state.meta.updateKeys).toContain(recovered.keys.updateKeyMultibase)
    }
  )

  it(
    "strikes the fresh credential's rung 1 on a seed-less retirement, as " +
      'the seeded walk does',
    async () => {
      const {
        idStore,
        log,
        updateKeys,
        did,
        code,
        ladderSeed,
        credentialKeyAgreement,
        replacement
      } = await ladderRecoveryFixture()
      await recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed,
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION })
      })
      const rung0 = await ladderRung({ ladderSeed, index: 0 })
      const rung1 = await ladderRung({ ladderSeed, index: 1 })
      const rung0Hash = await deriveNextKeyHash(rung0.keyMultibase)
      const rung1Hash = await deriveNextKeyHash(rung1.keyMultibase)
      const replacementHash = await deriveNextKeyHash(
        replacement.updateKeyMultibase
      )
      const credentialVmId = unlockKeyVmId({
        did,
        keyAgreement: credentialKeyAgreement
      })

      // The continuation commits the fresh ladder's rung pair in the SPENT
      // code's reveal entry, and reveals rung 0 only in the add-and-retire
      // entry that strikes the code -- so a walk without the seed sees no
      // ladder-signed commit of `hash(rung 1)`. The handover rule reads it
      // back: the seeded and seed-less walks agree on the inventory, and
      // neither claims the replacement code's hash.
      for (const seed of [ladderSeed, undefined]) {
        const inventory = await attributeLadderInventory({
          log: readLogFromString(log()!),
          anchorKeyMultibase: rung0.keyMultibase,
          credentialVmId,
          ...(seed ? { ladderSeed: seed } : {})
        })
        expect(inventory.revealedKeys).toEqual([rung0.keyMultibase])
        expect(new Set(inventory.committedHashes)).toEqual(
          new Set([rung0Hash, rung1Hash])
        )
        expect(inventory.committedHashes).not.toContain(replacementHash)
      }

      // A enrolled client retiring the credential holds no ladder seed for it
      // (the seed is sealed inside the credential's own record): the removal
      // runs seed-less, and rung 1 must leave with the rest, or the retired
      // credential's holder could still reveal it and seize update authority.
      await removeUnlockKey({
        idStore,
        updateKeys,
        unlockKeys: {
          keyAgreement: credentialKeyAgreement,
          updateKeyMultibase: rung0.keyMultibase
        }
      })
      const state = await resolved(log)
      expect(state.meta.updateKeys).not.toContain(rung0.keyMultibase)
      expect(state.meta.nextKeyHashes).not.toContain(rung0Hash)
      expect(state.meta.nextKeyHashes).not.toContain(rung1Hash)
      expect(state.doc?.keyAgreement).not.toContain(credentialVmId)
      // The replacement code's inventory and the enrolled client survive.
      expect(state.meta.nextKeyHashes).toContain(replacementHash)
      expect(state.meta.updateKeys).toContain(
        await updateKeyMultibase({ seed: updateKeys.updateSeed })
      )
      // The seed-less walk now finds nothing of the ladder left standing.
      const after = await attributeLadderInventory({
        log: readLogFromString(log()!),
        anchorKeyMultibase: rung0.keyMultibase,
        credentialVmId
      })
      expect(after.revealedKeys).toEqual([])
      expect(after.committedHashes).toEqual([])
    }
  )

  it(
    'retires a stale third-party ladder VM when the replacement code is ' +
      'spent',
    async () => {
      const {
        idStore,
        log,
        did,
        code,
        ladderSeed,
        credentialKeyAgreement,
        replacement
      } = await ladderRecoveryFixture()
      await recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed,
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION })
      })
      const firstLadderVmId = `${did}#${await ladderVmKeyMultibase({
        ladderSeed
      })}`
      const firstRung0 = await ladderRung({ ladderSeed, index: 0 })

      // The second recovery spends the replacement code with a second fresh
      // ladder: the first ladder's VM is now the stale third-party entry the
      // add-and-retire must remove.
      const secondLadderSeed = generateLadderSeed()
      const secondKeyAgreement = {
        commitment: await keyAgreementCommitment({
          keyAgreementKeyMultibase:
            CANONICAL_CLIENT_KEYS[4]!.keyAgreementKeyMultibase
        })
      }
      const secondReplacement = await recoveryClientFromCode({
        code: generateRecoveryCode()
      })
      await recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: replacement.updateSeed,
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        ladderSeed: secondLadderSeed,
        credentialKeyAgreement: secondKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: secondReplacement.keyAgreementKeyMultibase,
          updateKeyMultibase: secondReplacement.updateKeyMultibase
        },
        onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION })
      })

      const state = await resolved(log)
      const secondLadderVmId = `${did}#${await ladderVmKeyMultibase({
        ladderSeed: secondLadderSeed
      })}`
      // The stale ladder VM is out of the document and every relation; the
      // fresh one is the only ladder VM standing.
      expect(
        state.doc?.verificationMethod?.some(
          (method: { id?: string }) => method.id === firstLadderVmId
        )
      ).toBe(false)
      expect(state.doc?.assertionMethod).not.toContain(firstLadderVmId)
      expect(state.doc?.capabilityDelegation).not.toContain(firstLadderVmId)
      expect(ladderVmIds({ doc: state.doc! })).toEqual([secondLadderVmId])
      // The first credential's account-ladder update authority survives: it
      // is still a standing credential, and an unattributable committed hash
      // could not be named without its seed anyway.
      expect(state.meta.updateKeys).toContain(firstRung0.keyMultibase)
    }
  )

  it(
    'points `#DelegatedClients` at the fresh generation in the SAME entry ' +
      'that retires the standing ladder VMs',
    async () => {
      const {
        idStore,
        log,
        did,
        code,
        ladderSeed,
        credentialKeyAgreement,
        replacement
      } = await ladderRecoveryFixture()
      const entriesAfterIssuance = readLogFromString(log()!).length
      const freshGeneration = FIXTURE_GENERATION

      // A tear anywhere after the add entry must still leave the pointer
      // correct, so the pointer is observed at commit time (not yet moved)
      // and again after the single entry that retires the ladder VMs.
      let pointedAtCommit: string | undefined
      await recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed,
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => {
          const state = await resolved(log)
          pointedAtCommit = delegatedClientsPointer({ doc: state.doc! })
          return { clientAnnexDid: freshGeneration }
        }
      })
      expect(pointedAtCommit).not.toBe(freshGeneration)

      // No extra entry: the pointer rode into the add-and-retire entry.
      expect(readLogFromString(log()!).length).toBe(entriesAfterIssuance + 2)
      const state = await resolved(log)
      expect(delegatedClientsPointer({ doc: state.doc! })).toBe(freshGeneration)
      const ladderVmId = `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
      expect(ladderVmIds({ doc: state.doc! })).toEqual([ladderVmId])
    }
  )

  it('refuses a malformed annex DID before the add entry is built', async () => {
    const {
      idStore,
      log,
      code,
      ladderSeed,
      credentialKeyAgreement,
      replacement
    } = await ladderRecoveryFixture()
    const entriesBeforeAdd = readLogFromString(log()!).length
    await expect(
      recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed,
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => ({ clientAnnexDid: 'did:key:z6MkNotAnAnnex' })
      })
    ).rejects.toThrow(/client annex/)
    // The reveal entry stands; the add entry never ran.
    expect(readLogFromString(log()!).length).toBe(entriesBeforeAdd + 1)
  })

  it('refuses a continuation for a code the log no longer commits', async () => {
    const { idStore } = await provisionedLog()
    const code = await recoveryClientFromCode({ code: generateRecoveryCode() })
    await expect(
      recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed: generateLadderSeed(),
        credentialKeyAgreement: {
          commitment: await keyAgreementCommitment({
            keyAgreementKeyMultibase:
              CANONICAL_CLIENT_KEYS[3]!.keyAgreementKeyMultibase
          })
        },
        replacement: {
          keyAgreementKeyMultibase: 'z6LSReplacementAgreementKeyExample',
          updateKeyMultibase: 'z6MkReplacementUpdateKeyExample'
        },
        onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION })
      })
    ).rejects.toThrow(RecoveryKeyNotCommittedError)
  })

  it('advances the pin to the head each entry publishes', async () => {
    const {
      idStore,
      log,
      did,
      code,
      ladderSeed,
      credentialKeyAgreement,
      replacement
    } = await ladderRecoveryFixture()
    const pinStore = memoryResourceLogPinStore()

    const outcome = await recoverWebvhLadderAnchored({
      store: idStore,
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      ladderSeed,
      credentialKeyAgreement,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase
      },
      onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION }),
      expectedDid: did,
      pinStore,
      logId: LOG_ID
    })

    expect(outcome.did).toBe(did)
    expect(await pinStore.read({ logId: LOG_ID })).toEqual(
      pinOfLog(readLogFromString(log()!))
    )
  })

  it('refuses a served prefix of the pinned log before any entry publishes', async () => {
    const {
      idStore,
      log,
      did,
      code,
      ladderSeed,
      credentialKeyAgreement,
      replacement
    } = await ladderRecoveryFixture()
    const pinStore = memoryResourceLogPinStore()
    await pinStore.write({
      logId: LOG_ID,
      pin: pinOfLog(readLogFromString(log()!))
    })
    const { store } = truncatingLogStore({ idStore, dropEntries: 1 })
    const logBefore = log()

    const caught = await recoverWebvhLadderAnchored({
      store,
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      ladderSeed,
      credentialKeyAgreement,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase
      },
      onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION }),
      expectedDid: did,
      pinStore,
      logId: LOG_ID
    }).catch((err: unknown) => err)

    expect(caught).toBeInstanceOf(ResourceLogContinuityError)
    expect((caught as ResourceLogContinuityError).reason).toBe('rollback')
    expect(log()).toBe(logBefore)
  })

  it('refuses a call with no onCommitted, before any read', async () => {
    const { idStore, code, ladderSeed, credentialKeyAgreement, replacement } =
      await ladderRecoveryFixture()
    let reads = 0
    const store: RecoveryLogStore = {
      ...idStore,
      async getIdResourceRaw(options: { resourceId: string }) {
        reads += 1
        return idStore.getIdResourceRaw(options)
      }
    }

    const caught = await recoverWebvhLadderAnchored({
      store,
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      ladderSeed,
      credentialKeyAgreement,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase
      }
    } as unknown as Parameters<typeof recoverWebvhLadderAnchored>[0]).catch(
      (err: unknown) => err
    )

    expect(caught).toBeInstanceOf(TypeError)
    expect((caught as TypeError).message).toMatch(/onCommitted/)
    expect(reads).toBe(0)
  })
  it(
    "retires a standing passkey's whole inventory, and reports it -- on a " +
      "resume too -- while the enrolled client's marked pair survives",
    async () => {
      const {
        idStore,
        log,
        updateKeys,
        did,
        code,
        ladderSeed,
        credentialKeyAgreement,
        replacement
      } = await ladderRecoveryFixture()

      // A standing passkey beside the spent code: its key-agreement key
      // published verbatim (high entropy needs no commitment), its own ladder
      // VM installed by the same bind entry.
      const passkeySeed = generateLadderSeed()
      const passkeyRung0 = await ladderRung({
        ladderSeed: passkeySeed,
        index: 0
      })
      const passkeyKeyAgreement =
        CANONICAL_CLIENT_KEYS[6]!.keyAgreementKeyMultibase
      await publishUnlockKey({
        idStore,
        updateKeys,
        unlockKeys: {
          keyAgreement: { publicKeyMultibase: passkeyKeyAgreement },
          updateKeyMultibase: passkeyRung0.keyMultibase
        },
        ladderSeed: passkeySeed
      })
      const passkeyVmId = unlockKeyVmId({
        did,
        keyAgreement: { publicKeyMultibase: passkeyKeyAgreement }
      })
      const passkeyLadderVmId = `${did}#${await ladderVmKeyMultibase({
        ladderSeed: passkeySeed
      })}`
      const beforeSpend = await resolved(log)
      expect(beforeSpend.doc?.keyAgreement).toContain(passkeyVmId)
      expect(ladderVmIds({ doc: beforeSpend.doc! })).toContain(
        passkeyLadderVmId
      )

      const outcome = await recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed,
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION }),
        expectedDid: did
      })

      const state = await resolved(log)
      // The passkey is fully retired: keyAgreement member, verification
      // method, and ladder VM.
      expect(state.doc?.keyAgreement).not.toContain(passkeyVmId)
      expect(
        state.doc?.verificationMethod?.some(
          (method: { id?: string }) => method.id === passkeyVmId
        )
      ).toBe(false)
      expect(ladderVmIds({ doc: state.doc! })).not.toContain(passkeyLadderVmId)
      // Reported to the caller, which drops the registry entry and deletes
      // the unlock Space. The spent code is the caller's own business and is
      // not listed.
      expect(outcome.retiredCredentialVmIds).toContain(passkeyVmId)
      expect(outcome.retiredCredentialVmIds).not.toContain(
        recoveryVmId({
          did,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase
        })
      )
      // The enrolled client's marked pair is untouched -- its key-agreement
      // method carries the client marker, not the account DID.
      const client = CANONICAL_CLIENT_KEYS[0]!
      expect(state.doc?.capabilityInvocation).toContain(
        `${did}#${client.signingKeyMultibase}`
      )
      expect(state.doc?.keyAgreement).toContain(
        `${did}#${client.keyAgreementKeyMultibase}`
      )
      // The fresh credential and the replacement code stand.
      expect(state.doc?.keyAgreement).toContain(
        recoveryVmId({
          did,
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase
        })
      )
      expect(state.doc?.keyAgreement).toContain(
        unlockKeyVmId({ did, keyAgreement: credentialKeyAgreement })
      )

      // The resume: a run torn after the add-and-retire entry but before the
      // caller's registry and unlock-Space teardown re-runs into the
      // already-complete branch. It publishes nothing and reports the same
      // list, derived from the log rather than from the document it no
      // longer edits.
      const entries = readLogFromString(log()!).length
      const resumed = await recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed,
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION }),
        expectedDid: did
      })
      expect(readLogFromString(log()!).length).toBe(entries)
      expect(resumed.retiredCredentialVmIds).toEqual(
        outcome.retiredCredentialVmIds
      )
      expect(resumed.retiredCredentialVmIds).toContain(passkeyVmId)
    }
  )

  it('keeps its own fresh ladder VM when that VM already stands', async () => {
    const {
      idStore,
      log,
      updateKeys,
      did,
      code,
      ladderSeed,
      credentialKeyAgreement,
      replacement
    } = await ladderRecoveryFixture()

    // The fresh credential's inventory is already published (a resumed run's
    // shape): its ladder VM stands in `capabilityDelegation` before the
    // add-and-retire entry, where the retirement filter would meet it.
    const rung0 = await ladderRung({ ladderSeed, index: 0 })
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: {
        keyAgreement: credentialKeyAgreement,
        updateKeyMultibase: rung0.keyMultibase
      },
      ladderSeed
    })
    const ladderVmId = `${did}#${await ladderVmKeyMultibase({ ladderSeed })}`
    const before = await resolved(log)
    expect(ladderVmIds({ doc: before.doc! })).toContain(ladderVmId)

    await recoverWebvhLadderAnchored({
      store: idStore,
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      ladderSeed,
      credentialKeyAgreement,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase
      },
      onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION }),
      expectedDid: did
    })

    const state = await resolved(log)
    expect(state.doc?.assertionMethod).toContain(ladderVmId)
    expect(state.doc?.capabilityDelegation).toContain(ladderVmId)
    expect(ladderVmIds({ doc: state.doc! })).toEqual([ladderVmId])
  })
})

describe('the remembered continuation retires pre-recovery credentials', () => {
  it(
    "strikes a standing passkey's keyAgreement and ladder VM, reports it -- " +
      "on a resume too -- and leaves the enrolled clients' marked pairs alone",
    async () => {
      const { idStore, log, updateKeys, did } = await provisionedLog()
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

      // The standing passkey: verbatim key-agreement key, its own ladder VM.
      const passkeySeed = generateLadderSeed()
      const passkeyRung0 = await ladderRung({
        ladderSeed: passkeySeed,
        index: 0
      })
      const passkeyKeyAgreement =
        CANONICAL_CLIENT_KEYS[7]!.keyAgreementKeyMultibase
      await publishUnlockKey({
        idStore,
        updateKeys,
        unlockKeys: {
          keyAgreement: { publicKeyMultibase: passkeyKeyAgreement },
          updateKeyMultibase: passkeyRung0.keyMultibase
        },
        ladderSeed: passkeySeed
      })
      const passkeyVmId = unlockKeyVmId({
        did,
        keyAgreement: { publicKeyMultibase: passkeyKeyAgreement }
      })
      const passkeyLadderVmId = `${did}#${await ladderVmKeyMultibase({
        ladderSeed: passkeySeed
      })}`

      const recovered = await mintedClient(8)
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
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: noopCommitted,
        expectedDid: did
      })

      expect(outcome.committed).toBe(true)
      expect(outcome.retiredCredentialVmIds).toContain(passkeyVmId)
      expect(outcome.retiredCredentialVmIds).not.toContain(
        recoveryVmId({
          did,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase
        })
      )

      const state = await resolved(log)
      expect(state.doc?.keyAgreement).not.toContain(passkeyVmId)
      expect(
        state.doc?.verificationMethod?.some(
          (method: { id?: string }) => method.id === passkeyVmId
        )
      ).toBe(false)
      expect(state.doc?.assertionMethod).not.toContain(passkeyLadderVmId)
      expect(state.doc?.capabilityDelegation).not.toContain(passkeyLadderVmId)
      expect(ladderVmIds({ doc: state.doc! })).toEqual([])
      // The spent code is gone; the replacement and both clients stand.
      expect(state.doc?.keyAgreement).not.toContain(
        recoveryVmId({
          did,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase
        })
      )
      expect(state.doc?.keyAgreement).toContain(
        recoveryVmId({
          did,
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase
        })
      )

      // The resume: the same call after the add-and-retire entry landed
      // publishes nothing and reports the same retirement, derived from the
      // log.
      const entries = readLogFromString(log()!).length
      const resumed = await recoverWebvhClient({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase
        },
        onCommitted: noopCommitted,
        expectedDid: did
      })
      expect(resumed.committed).toBe(false)
      expect(readLogFromString(log()!).length).toBe(entries)
      expect(resumed.retiredCredentialVmIds).toEqual(
        outcome.retiredCredentialVmIds
      )
      expect(resumed.retiredCredentialVmIds).toContain(passkeyVmId)
      for (const client of [CANONICAL_CLIENT_KEYS[0]!, recovered.keys]) {
        expect(state.doc?.capabilityInvocation).toContain(
          `${did}#${client.signingKeyMultibase}`
        )
        expect(state.doc?.keyAgreement).toContain(
          `${did}#${client.keyAgreementKeyMultibase}`
        )
      }
    }
  )
})
