/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The recovery keyring record codec: the `{ version, wrapped }` envelope
 * stored as the one resource of a recovery code's unlock Space. Its plaintext
 * is the ordinary keyring record's (controller, email, account pointer) PLUS
 * the pre-minted PUT-on-`did.jsonl` delegation -- the narrow zcap bridge that
 * lets the code-derived client write its self-enrolling log continuation. It
 * carries **no key material of any kind**: never a seed, never a user key wrap
 * (wraps live doc-and-roster only), so the record stays a pure pointer.
 *
 * The wrap reuses the keyring cipher context verbatim, so a recovery record
 * IS a keyring record to every generic consumer (an ordinary
 * `unwrapKeyringRecord` recovers its pointer and ignores the extra member) --
 * only the recovery flow demands the delegation.
 */
import type {
  IKeyAgreementKey,
  IKeyResolver,
  IZcap
} from '@interop/data-integrity-core'
import { createEdvDocCipher } from '@interop/was-client/edv'
import { KEYRING_COLLECTION } from '../space/collections.js'
import {
  KEYRING_RECORD_VERSION,
  parseRecordPointer
} from '../keyring/record.js'
import type { AccountPointer } from '../keyring/record.js'

/**
 * The unwrapped contents of a recovery keyring record: the ordinary record
 * members plus the required delegation. `pointer` is required -- a recovery
 * record exists only on WAS deployments (there is nothing to recover toward
 * without a Space).
 */
export interface RecoveryRecordContents {
  controller: string
  email?: string
  pointer: AccountPointer
  delegation: IZcap
}

/**
 * Wraps the recovery record: controller, email, pointer, and the pre-minted
 * `did.jsonl` PUT delegation, encrypted under the code's unlock KAK via the
 * keyring EDV cipher context.
 *
 * @param options {object}
 * @param options.controller {string}   the account did:key
 * @param [options.email] {string}   the account email, when known
 * @param options.pointer {AccountPointer}   the account pointer
 * @param options.delegation {IZcap}   the PUT-on-`did.jsonl` delegation to the
 *   code-derived signing DID
 * @param options.keyAgreementKey {IKeyAgreementKey}   the code's unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<{ version: number, wrapped: unknown }>}
 */
export async function wrapRecoveryRecord({
  controller,
  email,
  pointer,
  delegation,
  keyAgreementKey,
  keyResolver
}: {
  controller: string
  email?: string
  pointer: AccountPointer
  delegation: IZcap
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<{ version: number; wrapped: unknown }> {
  const cipher = await createEdvDocCipher({
    keyAgreementKey,
    keyResolver,
    collectionId: KEYRING_COLLECTION.id
  })
  const data = {
    controller,
    ...(email ? { email } : {}),
    pointer: {
      ...(pointer.did ? { did: pointer.did } : {}),
      spaceId: pointer.spaceId,
      host: pointer.host
    },
    delegation,
    createdAt: new Date().toISOString()
  }
  const { envelope } = await cipher.encrypt({
    data: data as unknown as Parameters<typeof cipher.encrypt>[0]['data']
  })
  return { version: KEYRING_RECORD_VERSION, wrapped: envelope }
}

/**
 * Unwraps and validates a recovery record: the ordinary keyring-record checks
 * plus the required pointer and delegation. A record without a delegation is
 * not a recovery record (an ordinary keyring record found under a code's
 * unlock Space would mean a corrupted issuance) and is refused.
 *
 * @param options {object}
 * @param options.record {unknown}   the stored `{ version, wrapped }` envelope
 * @param options.keyAgreementKey {IKeyAgreementKey}   the code's unlock KAK
 * @param options.keyResolver {IKeyResolver}
 * @returns {Promise<RecoveryRecordContents>}
 */
export async function unwrapRecoveryRecord({
  record,
  keyAgreementKey,
  keyResolver
}: {
  record: unknown
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
}): Promise<RecoveryRecordContents> {
  if (record === null || typeof record !== 'object') {
    throw new Error('Malformed recovery record.')
  }
  const { version, wrapped } = record as {
    version?: unknown
    wrapped?: unknown
  }
  if (version !== KEYRING_RECORD_VERSION) {
    throw new Error(`Unsupported recovery record version "${String(version)}".`)
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
    delegation?: unknown
  }

  if (typeof plaintext.controller !== 'string' || !plaintext.controller) {
    throw new Error('Recovery record is missing a controller.')
  }
  const pointer = parseRecordPointer(plaintext.pointer)
  if (!pointer) {
    throw new Error('Recovery record is missing its account pointer.')
  }
  if (
    plaintext.delegation === null ||
    typeof plaintext.delegation !== 'object'
  ) {
    throw new Error('Recovery record is missing its did.jsonl delegation.')
  }

  return {
    controller: plaintext.controller,
    ...(typeof plaintext.email === 'string' && plaintext.email
      ? { email: plaintext.email }
      : {}),
    pointer,
    delegation: plaintext.delegation as IZcap
  }
}
