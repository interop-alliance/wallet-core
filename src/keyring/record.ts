/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The keyring record codec: the `{ version, encryption, wrapped }` envelope
 * stored as the one resource of an account's unlock Space. Its plaintext
 * carries the account controller, the email captured at bind time, and the
 * account pointer -- and deliberately no key material of any kind, so the
 * record locates an account without authorizing anything against it.
 *
 * The wrap is an EDV document envelope sealed under the record's own key
 * epoch: every EDV envelope seals to an epoch key, so the record carries its
 * one-epoch descriptor in its `encryption` member, epoch[0] wrapped to the
 * unlock key-agreement key. The record stays self-contained -- unlock KAK in,
 * contents out. The cipher's `keyring` collection context labels errors only
 * (the codec is agnostic to it); what keeps a swapped-in foreign record from
 * being accepted is the contents validation on unwrap, not the cipher.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  createEdvDocCipher,
  initRecipients,
  ownerRecipient,
  type DocCipher,
  type EncryptionDescriptorStore
} from '@interop/was-client/edv'
import { KEYRING_COLLECTION } from '../space/collections.js'

/**
 * The version stamped on the stored `{ version, encryption, wrapped }` keyring
 * envelope: the record whose envelope seals under the record's own key epoch
 * (the `encryption` member). Any other version is refused as unusable -- such
 * accounts are re-provisioned, not migrated.
 */
export const KEYRING_RECORD_VERSION = 1

/**
 * Mints the one-epoch descriptor a fresh record is sealed under: epoch[0]
 * wrapped to the given KAK alone, built through `initRecipients` against a
 * throwaway in-memory store (the descriptor's home is the record itself).
 * Exported for any consumer sealing a self-contained
 * `{ version, encryption, wrapped }` record -- the keyring and recovery
 * records here, and a wallet app's own locally stored records (e.g.
 * freewallet's client-key record and unlock-methods registry).
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the wrapping KAK (for
 *   the keyring record, the unlock KAK)
 * @returns {Promise<CollectionEncryption>}
 */
export async function mintRecordEncryption({
  keyAgreementKey
}: {
  keyAgreementKey: IKeyAgreementKey
}): Promise<CollectionEncryption> {
  let stored: CollectionEncryption | null = null
  const store: EncryptionDescriptorStore = {
    async read() {
      return stored ? { descriptor: stored } : null
    },
    async replace(next) {
      stored = next
    },
    async create(next) {
      stored = next
    }
  }
  return initRecipients({
    store,
    recipients: [ownerRecipient({ keyAgreementKey })]
  })
}

/**
 * Builds the record cipher: an EDV cipher over the record's own descriptor.
 * Shared by the wrap and unwrap paths (and by the recovery record, which
 * reuses the keyring cipher context verbatim); an app's own record kind
 * passes its own `collectionId` so its failures name the record kind. The
 * context labels errors only -- the codec is agnostic to it, so a record
 * kind's real swap protection is its contents validation on unwrap.
 *
 * @param options {object}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the wrapping KAK (for
 *   the keyring record, the unlock KAK)
 * @param options.keyResolver {IKeyResolver}
 * @param options.encryption {CollectionEncryption}   the record's descriptor
 * @param [options.collectionId] {string}   the cipher context failures are
 *   labeled with; defaults to the keyring context
 * @returns {Promise<DocCipher>}
 */
export async function recordCipher({
  keyAgreementKey,
  keyResolver,
  encryption,
  collectionId = KEYRING_COLLECTION.id
}: {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
  encryption: CollectionEncryption
  collectionId?: string
}): Promise<DocCipher> {
  return createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId,
    encryption
  })
}

/**
 * Validates the common `{ version, encryption, wrapped }` frame of a stored
 * record (keyring or recovery -- `label` names the refusals) and returns its
 * members. Exported so an app's own record kinds open their records through
 * the same frame validation the codec here seals with, rather than re-deriving
 * the version and shape checks.
 *
 * @param options {object}
 * @param options.record {unknown}
 * @param options.label {string}   `'keyring'`, `'recovery'`, or an app record
 *   kind's own label
 * @param [options.version] {number}   the version the frame must carry;
 *   defaults to the keyring record version
 * @returns {{ encryption: CollectionEncryption, wrapped: unknown }}
 */
export function parseRecordFrame({
  record,
  label,
  version = KEYRING_RECORD_VERSION
}: {
  record: unknown
  label: string
  version?: number
}): { encryption: CollectionEncryption; wrapped: unknown } {
  if (record === null || typeof record !== 'object') {
    throw new Error(`Malformed ${label} record.`)
  }
  const {
    version: recordVersion,
    encryption,
    wrapped
  } = record as {
    version?: unknown
    encryption?: unknown
    wrapped?: unknown
  }
  if (recordVersion !== version) {
    throw new Error(
      `Unsupported ${label} record version "${String(recordVersion)}".`
    )
  }
  if (wrapped === undefined || wrapped === null) {
    throw new Error(`Malformed ${label} record.`)
  }
  // A version-1 frame carrying a wrap but no descriptor is the retired
  // pre-extraction record shape, which shipped under this same version number
  // and wrapped a data seed. It is unusable, not merely damaged -- name the
  // shape so the refusal is not read as corruption.
  if (encryption === undefined && version === KEYRING_RECORD_VERSION) {
    throw new Error(
      `The ${label} record uses the retired pre-extraction version 1 shape ` +
        '(a data-seed wrap with no encryption descriptor); such accounts are ' +
        're-provisioned, not migrated.'
    )
  }
  if (encryption === null || typeof encryption !== 'object') {
    throw new Error(`The ${label} record is missing its encryption descriptor.`)
  }
  return { encryption: encryption as CollectionEncryption, wrapped }
}

/**
 * The account pointer a keyring record carries in place of the retired data
 * seed: where the account lives (`spaceId` + `host`, the WAS server origin)
 * and, once provisioning has published it, the account's stable did:webvh id.
 * Discovery only -- holding the pointer authorizes nothing.
 */
export interface AccountPointer {
  did?: string
  spaceId: string
  host: string
}

/**
 * The unwrapped contents of a keyring record: the account controller (the
 * first enrolled client's did:key today), the account email captured at bind
 * time (when one was given -- carried so any unlock method recovers it; a
 * passkey login has no login form to ask on), and the account pointer (absent
 * only on no-WAS deployments, where there is no Space to point at).
 */
export interface KeyringRecordContents {
  controller: string
  email?: string
  pointer?: AccountPointer
}

/**
 * Wraps the account-pointer contents into a keyring record: the controller,
 * email, and pointer (+ timestamp) sealed under a freshly minted record epoch
 * whose key is wrapped to the unlock KAK. Deliberately carries no key material
 * of any kind.
 *
 * @param options {object}
 * @param options.controller {string}   the account did:key
 * @param [options.email] {string}   the account email, when known
 * @param [options.pointer] {AccountPointer}   the account pointer (absent on
 *   no-WAS deployments)
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<{ version: number, encryption: CollectionEncryption,
 *   wrapped: unknown }>}
 */
export async function wrapKeyringRecord({
  controller,
  email,
  pointer,
  keyAgreementKey,
  keyResolver
}: {
  controller: string
  email?: string
  pointer?: AccountPointer
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<{
  version: number
  encryption: CollectionEncryption
  wrapped: unknown
}> {
  const encryption = await mintRecordEncryption({ keyAgreementKey })
  const cipher = await recordCipher({
    keyAgreementKey,
    keyResolver,
    encryption
  })
  const { envelope } = await cipher.encrypt({
    data: {
      controller,
      ...(email ? { email } : {}),
      ...(pointer
        ? {
            pointer: {
              ...(pointer.did ? { did: pointer.did } : {}),
              spaceId: pointer.spaceId,
              host: pointer.host
            }
          }
        : {}),
      createdAt: new Date().toISOString()
    }
  })
  return { version: KEYRING_RECORD_VERSION, encryption, wrapped: envelope }
}

/**
 * Unwraps and validates a keyring record. Rejects a record whose `version` is
 * not the current one (accounts are re-provisioned, not migrated), and
 * sanity-checks the decrypted plaintext (non-empty controller, well-formed
 * pointer when present).
 *
 * @param options {object}
 * @param options.record {unknown}
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<KeyringRecordContents>}
 */
export async function unwrapKeyringRecord({
  record,
  keyAgreementKey,
  keyResolver
}: {
  record: unknown
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<KeyringRecordContents> {
  const { encryption, wrapped } = parseRecordFrame({
    record,
    label: 'keyring'
  })
  const cipher = await recordCipher({
    keyAgreementKey,
    keyResolver,
    encryption
  })
  const plaintext = (await cipher.decrypt({
    envelope: wrapped as never
  })) as {
    controller?: unknown
    email?: unknown
    pointer?: unknown
  }

  if (typeof plaintext.controller !== 'string' || !plaintext.controller) {
    throw new Error('Keyring record is missing a controller.')
  }
  const pointer = parseRecordPointer(plaintext.pointer)

  return {
    controller: plaintext.controller,
    // A record bound without an email simply has no email; anything
    // non-string is ignored, not fatal.
    ...(typeof plaintext.email === 'string' && plaintext.email
      ? { email: plaintext.email }
      : {}),
    ...(pointer ? { pointer } : {})
  }
}

/**
 * Parses and validates the optional `pointer` member of a keyring record
 * plaintext. An absent member is a no-WAS record (returns undefined); a
 * present-but-malformed one throws -- a record that claims a pointer but
 * cannot state where the account lives is unusable.
 *
 * @param value {unknown}   the record's `pointer` member
 * @returns {AccountPointer | undefined}
 */
export function parseRecordPointer(value: unknown): AccountPointer | undefined {
  if (value === undefined) {
    return undefined
  }
  if (value === null || typeof value !== 'object') {
    throw new Error('Keyring record has a malformed account pointer.')
  }
  const { did, spaceId, host } = value as {
    did?: unknown
    spaceId?: unknown
    host?: unknown
  }
  if (typeof spaceId !== 'string' || !spaceId) {
    throw new Error('Keyring record account pointer is missing its spaceId.')
  }
  if (typeof host !== 'string' || !host) {
    throw new Error('Keyring record account pointer is missing its host.')
  }
  if (did !== undefined && (typeof did !== 'string' || !did)) {
    throw new Error('Keyring record account pointer has a malformed did.')
  }
  return { ...(did ? { did } : {}), spaceId, host }
}
