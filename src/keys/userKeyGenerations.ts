/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The pure readers over user key generations: a user key presented as an
 * epoch-roster recipient, and the unwrap of every generation a roster
 * descriptor carries. Both run offline over data already in hand, so this file
 * imports the epoch primitives alone and stays clear of the rotation cascade's
 * store and log graph.
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import type { CollectionEncryption } from '@interop/was-client'
import {
  epochKeyIdFor,
  unwrapEpochSecret,
  type RecipientPublicKey
} from '@interop/was-client/edv/cipher'
import type { UserKey } from './userKey.js'

/**
 * A user key presented as an epoch-roster recipient: the kid is the
 * self-describing `<did:key>#<fingerprint>` form every collection epoch names
 * the user under, and the public key is the did:key's own multibase.
 *
 * @param options {object}
 * @param options.userKey {UserKey}
 * @returns {RecipientPublicKey}
 */
export function userKeyAsRecipient({
  userKey
}: {
  userKey: UserKey
}): RecipientPublicKey {
  return {
    id: epochKeyIdFor(userKey.id),
    publicKeyMultibase: userKey.id.split(':')[2]!
  }
}

/**
 * Recovers every user key generation from the roster descriptor: each roster
 * epoch is one generation (its id the generation's did:key, its wrapped secret
 * the generation's raw key), escrow-wrapped to every enrolled client -- so this
 * client's key-agreement key unwraps them all, in roster (chronological) order.
 * A generation whose wrap is missing or fails to unwrap is skipped rather than
 * fatal (the cascade then simply cannot recognize or escrow that generation;
 * the current epoch always unwraps or the roster read itself would have
 * refused).
 *
 * @param options {object}
 * @param options.descriptor {CollectionEncryption}   the roster descriptor
 * @param options.clientKeyAgreementKey {IKeyAgreementKey}   this client's own
 *   (identity) key-agreement key
 * @returns {Promise<UserKey[]>}   the generations, oldest first
 */
export async function unwrapUserKeyGenerations({
  descriptor,
  clientKeyAgreementKey
}: {
  descriptor: CollectionEncryption
  clientKeyAgreementKey: IKeyAgreementKey
}): Promise<UserKey[]> {
  const generations: UserKey[] = []
  for (const epoch of descriptor.epochs ?? []) {
    const entry = epoch.recipients.find(
      recipient => recipient.header.kid === clientKeyAgreementKey.id
    )
    if (!entry) {
      continue
    }
    const secret = await unwrapEpochSecret({
      entry,
      keyAgreementKey: clientKeyAgreementKey
    })
    if (secret) {
      generations.push({ id: epoch.id, secret })
    }
  }
  return generations
}
