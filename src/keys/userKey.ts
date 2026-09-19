/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The user key: the user's single roster identity for encrypted
 * collections, standing in as "recipient zero" of every key-epoch roster. It is
 * minted at wallet provisioning -- random, client-side, never server-held, and
 * never derivable from any passphrase or seed -- and delivered to each enrolled
 * client through the wrap-set roster, which each client caches in its own local
 * state under the unlock layer.
 *
 * The key-agreement half is exactly what `@interop/was-client`'s epoch
 * construction mints: a fresh X25519 pair whose did:key is the key's id and
 * whose raw 32-byte secret is what gets wrapped to recipients -- so the roster
 * machinery consumes the user key unchanged. The Ed25519 signing half DERIVES
 * from that same secret (`userKeySigningSeed`), so it needs no storage
 * and no delivery channel of its own: every holder of the user key holds it,
 * an enrolled session, a transient one, and a session-less signup or recovery
 * writer alike, and a roster rotation that hands a client the fresh
 * key-agreement secret hands it the fresh signing half with it.
 *
 * Its consumer is record authenticity. An app-side record sealed to the vault
 * KAK is not authenticated by being decryptable -- a storage host that knows
 * the epoch's public half can seal a body of its own that decrypts perfectly,
 * which is the property the keyring record's `proof` member exists to defeat.
 * So such a record carries the same proof, signed by `userKeyRecordSigner`
 * and verified against `userKeySigningKeyMultibase` before it is decrypted.
 */
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { epochKeyIdFor, mintEpoch } from '@interop/was-client/edv/cipher'
import { singleKeyResolver } from '@interop/was-client/identity'

/**
 * The HKDF salt for the user key's client-side expansions; the one info label
 * under it lives with the signing half (`./userKeySigning.js`). Both
 * permanent: two wallet apps must expand the same user key to byte-identical
 * output, or a record one of them signs is a record the other refuses.
 */
export const USER_KEY_SALT = 'freewallet/keys/user-key/v1'

/**
 * The user key material: the X25519 key-agreement half as minted by the epoch
 * construction (`id` is the key's own did:key; `secret` its raw 32-byte private
 * key). Random per account; held in memory for the life of a session and
 * persisted only inside a wrapped client-key record. The Ed25519 signing half
 * is not a member: it derives from `secret`, so a user key adopted from a
 * roster rotation is as complete an identity as a freshly minted one.
 */
export interface UserKey {
  id: string
  secret: Uint8Array
}

/**
 * Mints a fresh user key: the X25519 key-agreement pair via the was-client
 * epoch construction (its did:key is the key id, its raw secret is what wraps).
 * The signing half needs no minting -- it derives from the same secret.
 *
 * @returns {Promise<UserKey>}
 */
export async function mintUserKey(): Promise<UserKey> {
  const { epochId, secret } = await mintEpoch()
  return { id: epochId, secret }
}

/**
 * Reconstructs the user key's key-agreement key and its single-key resolver
 * from the stored material -- the vault-key pair a session supplies to the
 * storage layer, making the user key recipient zero of every encrypted
 * collection. The key id is the self-describing `<did:key>#<fingerprint>` form,
 * so grantee-side did:key recipient resolution routes it like any other roster
 * entry.
 *
 * @param options {object}
 * @param options.userKey {UserKey}
 * @returns {{ keyAgreementKey: IKeyAgreementKey, keyResolver: IKeyResolver }}
 */
export function userKeyVaultKeys({ userKey }: { userKey: UserKey }): {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
} {
  const keyAgreementKey = X25519KeyAgreementKey2020.fromRawSecret({
    secret: userKey.secret,
    controller: userKey.id,
    id: epochKeyIdFor(userKey.id)
  }) as IKeyAgreementKey
  const keyResolver = singleKeyResolver({ keyAgreementKey })
  return { keyAgreementKey, keyResolver }
}
