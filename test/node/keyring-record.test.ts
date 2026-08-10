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
 * retired pre-extraction version-1 shape that shipped under the current
 * version number.
 */
import { describe, expect, it } from 'vitest'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'

import {
  KEYRING_RECORD_VERSION,
  mintRecordEncryption,
  parseRecordFrame,
  recordCipher
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

  it('returns the frame members of a well-formed record', () => {
    const frame = parseRecordFrame({
      record: {
        version: KEYRING_RECORD_VERSION,
        encryption,
        wrapped: { jwe: 'envelope' }
      },
      label: 'keyring'
    })

    expect(frame.encryption).toEqual(encryption)
    expect(frame.wrapped).toEqual({ jwe: 'envelope' })
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
        record: { version: 2, encryption, wrapped: {} },
        label: 'keyring'
      })
    ).toThrow('Unsupported keyring record version "2".')
  })

  it('accepts a caller-supplied version for an app record kind', () => {
    const record = { version: 2, encryption, wrapped: { jwe: 'envelope' } }

    expect(
      parseRecordFrame({ record, label: 'client-key', version: 2 }).wrapped
    ).toEqual({ jwe: 'envelope' })
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
})
