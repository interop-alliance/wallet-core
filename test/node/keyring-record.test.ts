/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Coverage for the record-own-epoch envelope construction the keyring record
 * seals with, exported for app-side record kinds: `mintRecordEncryption` (a
 * one-epoch descriptor wrapped to a KAK alone) and `recordCipher` (the EDV
 * cipher over that descriptor, labeled with a per-record-kind cipher
 * context). Pins the round-trip, the recipient roster, the per-wrap epoch
 * independence, and the fact that the context is a label only -- swap
 * protection between record kinds lives in each kind's contents validation,
 * and this file documents that so nobody re-assumes a cryptographic binding.
 *
 * Also covers `parseRecordFrame`, the frame validation the unwrap paths open
 * with: every refusal it makes before a cipher is ever built, including the
 * two retired version-1 shapes (the pre-extraction data-seed wrap and the
 * unsigned envelope the signed frame replaced).
 *
 * And the authenticity layer the signed frame added: the signed round-trip,
 * the refusal of a record whose frame members were tampered with, of one
 * signed by a key the client does not accept, and of one carrying no usable
 * proof at all -- plus the fact that no unwrap path decrypts without
 * verifying first.
 */
import { describe, expect, it } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'

import {
  deriveUnlockIdentity,
  KEYRING_KDF,
  KEYRING_RECORD_VERSION,
  mintRecordEncryption,
  parseRecordFrame,
  recordCipher,
  RecordProofError,
  signRecordFrame,
  unwrapKeyringRecord,
  verifyRecordProof,
  wrapKeyringRecord,
  type SignedRecord
} from '../../src/keyring/index.js'
import { KEYRING_COLLECTION } from '../../src/space/collections.js'

/**
 * A generated wrapping key pair (an unlock KAK, or an app session's vault KAK
 * -- structurally the same thing) plus its single-key resolver.
 */
async function generateWrappingKey(): Promise<{
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}> {
  const key = await X25519KeyAgreementKey2020.generate({
    controller: 'did:key:z6MkTestUnlockController'
  })
  const keyResolver: IKeyResolver = async () => ({
    id: key.id!,
    type: key.type,
    publicKeyMultibase: key.publicKeyMultibase
  })
  return { keyAgreementKey: key as IKeyAgreementKey, keyResolver }
}

describe('mintRecordEncryption', () => {
  it('mints a one-epoch descriptor wrapped to the given KAK alone', async () => {
    const { keyAgreementKey } = await generateWrappingKey()

    const encryption = await mintRecordEncryption({ keyAgreementKey })

    expect(encryption.epochs).toHaveLength(1)
    expect(encryption.currentEpoch).toBe(encryption.epochs![0]!.id)
    const recipients = encryption.epochs![0]!.recipients.map(
      recipient => recipient.header.kid
    )
    expect(recipients).toEqual([keyAgreementKey.id])
  })

  it('mints an independent epoch per record (no shared key across wraps)', async () => {
    const { keyAgreementKey } = await generateWrappingKey()

    const first = await mintRecordEncryption({ keyAgreementKey })
    const second = await mintRecordEncryption({ keyAgreementKey })

    expect(first.currentEpoch).not.toBe(second.currentEpoch)
  })
})

describe('recordCipher', () => {
  it('round-trips a record body under the default keyring context', async () => {
    const { keyAgreementKey, keyResolver } = await generateWrappingKey()
    const encryption = await mintRecordEncryption({ keyAgreementKey })
    const cipher = await recordCipher({
      keyAgreementKey,
      keyResolver,
      encryption
    })

    const body = { controller: 'did:key:z6MkExample', createdAt: 'now' }
    const { envelope } = await cipher.encrypt({ data: body })
    const decrypted = await cipher.decrypt({ envelope })

    expect(decrypted).toEqual(body)
  })

  it('round-trips under a caller-supplied cipher context', async () => {
    const { keyAgreementKey, keyResolver } = await generateWrappingKey()
    const encryption = await mintRecordEncryption({ keyAgreementKey })
    const cipher = await recordCipher({
      keyAgreementKey,
      keyResolver,
      encryption,
      collectionId: 'client-keys'
    })

    const body = { clientSeed: 'AAAA' }
    const { envelope } = await cipher.encrypt({ data: body })
    await expect(cipher.decrypt({ envelope })).resolves.toEqual(body)
  })

  it('treats the cipher context as a label only (documented, not a binding)', async () => {
    const { keyAgreementKey, keyResolver } = await generateWrappingKey()
    const encryption = await mintRecordEncryption({ keyAgreementKey })
    const clientKeysCipher = await recordCipher({
      keyAgreementKey,
      keyResolver,
      encryption,
      collectionId: 'client-keys'
    })
    const keyringCipher = await recordCipher({
      keyAgreementKey,
      keyResolver,
      encryption
    })

    // The codec is agnostic to `collectionId` (it labels errors), so an
    // envelope decrypts under a cipher built with a different context. Swap
    // protection between record kinds is each kind's contents validation on
    // unwrap -- pinned here so nobody re-assumes a cryptographic binding.
    const { envelope } = await clientKeysCipher.encrypt({
      data: { clientSeed: 'AAAA' }
    })
    await expect(keyringCipher.decrypt({ envelope })).resolves.toEqual({
      clientSeed: 'AAAA'
    })
  })

  it('defaults its context to the keyring collection', async () => {
    const { keyAgreementKey, keyResolver } = await generateWrappingKey()
    const encryption = await mintRecordEncryption({ keyAgreementKey })
    const defaulted = await recordCipher({
      keyAgreementKey,
      keyResolver,
      encryption
    })
    const explicit = await recordCipher({
      keyAgreementKey,
      keyResolver,
      encryption,
      collectionId: KEYRING_COLLECTION.id
    })

    const body = { pointer: { spaceId: 'space-123' } }
    const { envelope } = await explicit.encrypt({ data: body })
    await expect(defaulted.decrypt({ envelope })).resolves.toEqual(body)
  })
})

describe('parseRecordFrame', () => {
  const encryption = { currentEpoch: 'epoch-0', epochs: [] }
  const proof = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: 'did:key:z6MkSigner#z6MkSigner',
    proofPurpose: 'assertionMethod',
    created: '2026-08-14T00:00:00Z',
    proofValue: 'z3signature'
  }

  it('returns the frame members of a well-formed record', () => {
    const frame = parseRecordFrame({
      record: {
        version: KEYRING_RECORD_VERSION,
        encryption,
        wrapped: { jwe: 'envelope' },
        proof
      },
      label: 'keyring'
    })

    expect(frame.encryption).toEqual(encryption)
    expect(frame.wrapped).toEqual({ jwe: 'envelope' })
    expect(frame.proof).toEqual(proof)
  })

  it('refuses a non-object record', () => {
    expect(() => parseRecordFrame({ record: null, label: 'keyring' })).toThrow(
      'Malformed keyring record.'
    )
    expect(() =>
      parseRecordFrame({ record: 'not a record', label: 'recovery' })
    ).toThrow('Malformed recovery record.')
  })

  it('refuses an unsupported version', () => {
    expect(() =>
      parseRecordFrame({
        record: { version: 9, encryption, wrapped: {} },
        label: 'keyring'
      })
    ).toThrow('Unsupported keyring record version "9".')
  })

  it('accepts a caller-supplied version for an app record kind, unsigned', () => {
    // A record kind stamping its own version carries its own authenticity
    // story, so the frame validation does not demand a proof of it.
    const record = { version: 5, encryption, wrapped: { jwe: 'envelope' } }

    const frame = parseRecordFrame({ record, label: 'client-key', version: 5 })
    expect(frame.wrapped).toEqual({ jwe: 'envelope' })
    expect(frame.proof).toBeUndefined()
  })

  it('refuses a frame with no wrap before building a cipher', () => {
    expect(() =>
      parseRecordFrame({
        record: { version: KEYRING_RECORD_VERSION, encryption },
        label: 'keyring'
      })
    ).toThrow('Malformed keyring record.')
  })

  it('names the retired pre-extraction version 1 shape', () => {
    expect(() =>
      parseRecordFrame({
        record: { version: 1, wrapped: { jwe: 'data-seed envelope' } },
        label: 'keyring'
      })
    ).toThrow(/retired pre-extraction version 1 shape/)
  })

  it('names the retired unsigned version 1 shape', () => {
    expect(() =>
      parseRecordFrame({
        record: { version: 1, encryption, wrapped: { jwe: 'envelope' } },
        label: 'keyring'
      })
    ).toThrow(/retired unsigned version 1 shape/)
    expect(() =>
      parseRecordFrame({
        record: { version: 1, encryption, wrapped: { jwe: 'envelope' } },
        label: 'keyring'
      })
    ).toThrow(/re-provisioned, not migrated/)
  })

  it('refuses a malformed encryption descriptor', () => {
    expect(() =>
      parseRecordFrame({
        record: {
          version: KEYRING_RECORD_VERSION,
          encryption: 'nope',
          wrapped: {}
        },
        label: 'recovery'
      })
    ).toThrow('The recovery record is missing its encryption descriptor.')
  })

  it('refuses a current-version frame with no proof', () => {
    expect(() =>
      parseRecordFrame({
        record: {
          version: KEYRING_RECORD_VERSION,
          encryption,
          wrapped: { jwe: 'envelope' }
        },
        label: 'keyring'
      })
    ).toThrow(RecordProofError)
  })

  it('refuses a proof outside the fixed shape', () => {
    for (const malformed of [
      { ...proof, type: 'Ed25519Signature2020' },
      { ...proof, cryptosuite: 'ecdsa-jcs-2019' },
      { ...proof, proofPurpose: 'authentication' },
      { ...proof, proofValue: 42 },
      { ...proof, verificationMethod: undefined },
      'not a proof'
    ]) {
      expect(() =>
        parseRecordFrame({
          record: {
            version: KEYRING_RECORD_VERSION,
            encryption,
            wrapped: { jwe: 'envelope' },
            proof: malformed
          },
          label: 'keyring'
        })
      ).toThrow(RecordProofError)
    }
  })
})

/**
 * A cheap stand-in for the passphrase parameter set: the derivation under test
 * here is the record's, not the KDF's (`keyring-kdf.test.ts` pins that one),
 * so these cases expand a secret instead of stretching it 600k times.
 */
const FAST_KDF: typeof KEYRING_KDF = {
  version: 1,
  algorithm: 'HKDF',
  hash: 'SHA-256',
  salt: 'wallet-core/test/keyring-record',
  info: 'unlock-seed'
}

/**
 * An unlock identity derived from a secret, exactly as login derives it: the
 * KAK the record is sealed to, the resolver, and the record signer whose key
 * multibase is the verification prior a returning client re-derives.
 */
async function unlockFor(secret: string) {
  const unlock = await deriveUnlockIdentity({ secret, kdf: FAST_KDF })
  return {
    keyAgreementKey: unlock.keyAgreementKey as IKeyAgreementKey,
    keyResolver: unlock.keyResolver,
    signer: unlock.recordSigner
  }
}

describe('the signed keyring record', () => {
  const pointer = {
    did: 'did:webvh:z6MkScid:localhost%3A8080:space:space-1:id',
    spaceId: 'space-1',
    host: 'http://localhost:8080'
  }

  it('round-trips a signed record and returns its bind timestamp', async () => {
    const unlock = await unlockFor('correct horse battery staple')
    const record = await wrapKeyringRecord({
      controller: 'did:key:z6MkAccountController',
      email: 'user@example.com',
      pointer,
      keyAgreementKey: unlock.keyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.signer
    })

    expect(record.version).toBe(KEYRING_RECORD_VERSION)
    expect(record.proof.type).toBe('DataIntegrityProof')
    expect(record.proof.cryptosuite).toBe('eddsa-jcs-2022')
    expect(record.proof.proofPurpose).toBe('assertionMethod')
    expect(record.proof.verificationMethod).toBe(
      `did:key:${unlock.signer.keyMultibase}#${unlock.signer.keyMultibase}`
    )

    const contents = await unwrapKeyringRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.signer.keyMultibase
    })
    expect(contents.controller).toBe('did:key:z6MkAccountController')
    expect(contents.email).toBe('user@example.com')
    expect(contents.pointer).toEqual(pointer)
    expect(Number.isNaN(Date.parse(contents.createdAt))).toBe(false)
  })

  it('stamps a supplied createdAt, and refuses an unparseable one', async () => {
    const unlock = await unlockFor('correct horse battery staple')
    const createdAt = '2026-08-14T12:00:00.000Z'
    const record = await wrapKeyringRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      keyAgreementKey: unlock.keyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.signer,
      createdAt
    })
    const contents = await unwrapKeyringRecord({
      record,
      keyAgreementKey: unlock.keyAgreementKey,
      keyResolver: unlock.keyResolver,
      expectedKeyMultibase: unlock.signer.keyMultibase
    })
    expect(contents.createdAt).toBe(createdAt)

    await expect(
      wrapKeyringRecord({
        controller: 'did:key:z6MkAccountController',
        pointer,
        keyAgreementKey: unlock.keyAgreementKey,
        keyResolver: unlock.keyResolver,
        signer: unlock.signer,
        createdAt: 'whenever'
      })
    ).rejects.toThrow('Invalid record createdAt timestamp')
  })

  it('verifies the proof over every sibling member', async () => {
    const unlock = await unlockFor('correct horse battery staple')
    const record = await wrapKeyringRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      keyAgreementKey: unlock.keyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.signer
    })

    const tampered: SignedRecord[] = [
      { ...record, version: 5 },
      {
        ...record,
        encryption: await mintRecordEncryption({
          keyAgreementKey: unlock.keyAgreementKey
        })
      },
      { ...record, wrapped: { ...(record.wrapped as object), extra: 'x' } }
    ]

    for (const candidate of tampered) {
      await expect(
        verifyRecordProof({
          record: candidate,
          allowedKeyMultibases: unlock.signer.keyMultibase
        })
      ).rejects.toThrow(RecordProofError)
    }
  })

  it('refuses a record signed by another key', async () => {
    const unlock = await unlockFor('correct horse battery staple')
    const attacker = await unlockFor('the storage host is hostile')
    // A hostile host derives the unlock KAK's public half from the Space
    // controller and seals a record that decrypts perfectly -- and it is
    // still refused, because it cannot sign as the unlock identity.
    const forged = await wrapKeyringRecord({
      controller: 'did:key:z6MkAttackerController',
      pointer,
      keyAgreementKey: unlock.keyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: attacker.signer
    })

    await expect(
      unwrapKeyringRecord({
        record: forged,
        keyAgreementKey: unlock.keyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.signer.keyMultibase
      })
    ).rejects.toThrow(RecordProofError)
  })

  it('refuses a record whose proof was stripped or replaced', async () => {
    const unlock = await unlockFor('correct horse battery staple')
    const record = await wrapKeyringRecord({
      controller: 'did:key:z6MkAccountController',
      pointer,
      keyAgreementKey: unlock.keyAgreementKey,
      keyResolver: unlock.keyResolver,
      signer: unlock.signer
    })
    const { proof: _proof, ...unsigned } = record

    await expect(
      unwrapKeyringRecord({
        record: unsigned,
        keyAgreementKey: unlock.keyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.signer.keyMultibase
      })
    ).rejects.toThrow(RecordProofError)

    await expect(
      unwrapKeyringRecord({
        record: {
          ...record,
          proof: { ...record.proof, proofValue: 'z3bogus' }
        },
        keyAgreementKey: unlock.keyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.signer.keyMultibase
      })
    ).rejects.toThrow(RecordProofError)
  })

  it('requires a parseable createdAt in the plaintext', async () => {
    const unlock = await unlockFor('correct horse battery staple')
    const encryption = await mintRecordEncryption({
      keyAgreementKey: unlock.keyAgreementKey
    })
    const cipher = await recordCipher({
      keyAgreementKey: unlock.keyAgreementKey,
      keyResolver: unlock.keyResolver,
      encryption
    })
    const { envelope } = await cipher.encrypt({
      data: { controller: 'did:key:z6MkAccountController', createdAt: 'soon' }
    })
    const record = await signRecordFrame({
      version: KEYRING_RECORD_VERSION,
      encryption,
      wrapped: envelope,
      signer: unlock.signer
    })

    await expect(
      unwrapKeyringRecord({
        record,
        keyAgreementKey: unlock.keyAgreementKey,
        keyResolver: unlock.keyResolver,
        expectedKeyMultibase: unlock.signer.keyMultibase
      })
    ).rejects.toThrow('Keyring record has no valid createdAt timestamp.')
  })
})
