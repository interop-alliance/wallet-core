/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The keyring record codec: the `{ version, wrapped }` envelope stored as the
 * one resource of an account's unlock Space. Its plaintext carries the account
 * controller, the email captured at bind time, and the account pointer -- and
 * deliberately no key material of any kind, so the record locates an account
 * without authorizing anything against it.
 *
 * The wrap is an EDV document envelope under the unlock key-agreement key,
 * bound to the `keyring` cipher context, so a keyring envelope can never be
 * mistaken for (or swapped with) any other wrapped record.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { createEdvDocCipher } from '@interop/was-client/edv'
import { KEYRING_COLLECTION } from '../space/collections.js'

/**
 * The version stamped on the stored `{ version, wrapped }` keyring envelope.
 * Version 2 is the account-pointer record; version-1 records (which carried a
 * wrapped account-wide data seed) are refused as unusable -- such accounts are
 * re-provisioned, not migrated.
 */
export const KEYRING_RECORD_VERSION = 2

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
 * email, and pointer (+ timestamp) encrypted under the unlock KAK via the EDV
 * cipher. Deliberately carries no key material of any kind.
 *
 * @param options {object}
 * @param options.controller {string}   the account did:key
 * @param [options.email] {string}   the account email, when known
 * @param [options.pointer] {AccountPointer}   the account pointer (absent on
 *   no-WAS deployments)
 * @param options.keyAgreementKey {IKeyAgreementKey}   the unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<{ version: number, wrapped: unknown }>}
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
}): Promise<{ version: number; wrapped: unknown }> {
  const cipher = await createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId: KEYRING_COLLECTION.id
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
  return { version: KEYRING_RECORD_VERSION, wrapped: envelope }
}

/**
 * Unwraps and validates a keyring record. Rejects a record whose `version` is
 * not the current one (version-1 records carried the retired wrapped data
 * seed and are refused -- accounts are re-provisioned, not migrated), and
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
  if (record === null || typeof record !== 'object') {
    throw new Error('Malformed keyring record.')
  }
  const { version, wrapped } = record as {
    version?: unknown
    wrapped?: unknown
  }
  if (version !== KEYRING_RECORD_VERSION) {
    throw new Error(`Unsupported keyring record version "${String(version)}".`)
  }
  const cipher = await createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId: KEYRING_COLLECTION.id
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
