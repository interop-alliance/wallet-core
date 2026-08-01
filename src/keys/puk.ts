/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The per-user key (PUK): the user's single roster identity for encrypted
 * collections, standing in as "recipient zero" of every key-epoch roster. It is
 * minted at wallet provisioning -- random, client-side, never server-held, and
 * never derivable from any passphrase or seed -- and delivered to each enrolled
 * client through the wrap-set roster, which each client caches in its own local
 * state under the unlock layer.
 *
 * The key-agreement half is exactly what `@interop/was-client`'s epoch
 * construction mints: a fresh X25519 pair whose did:key is the key's id and
 * whose raw 32-byte secret is what gets wrapped to recipients -- so the roster
 * machinery consumes the PUK unchanged. The Ed25519 signing half is a second
 * independent 32-byte seed, minted now so the PUK is a complete identity, with
 * no consumer yet (the pair derives from the seed on demand once one lands).
 */
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type {
  IKeyAgreementKey,
  IKeyResolver
} from '@interop/data-integrity-core'
import { epochKeyIdFor, mintEpoch } from '@interop/was-client/edv'
import { singleKeyResolver } from '../identity/keyResolver.js'

/**
 * The per-user key material: the X25519 key-agreement half as minted by the
 * epoch construction (`id` is the key's own did:key; `secret` its raw 32-byte
 * private key), plus the 32-byte seed of the PUK's Ed25519 signing pair.
 * Random per account; held in memory for the life of a session and persisted
 * only inside a wrapped client-key record. The signing seed is absent on a PUK
 * adopted from a roster rotation -- the roster wraps the key-agreement secret
 * alone, and the signing half has no consumer yet.
 */
export interface Puk {
  id: string
  secret: Uint8Array
  signingSeed?: Uint8Array
}

/**
 * Mints a fresh PUK: the X25519 key-agreement pair via the was-client epoch
 * construction (its did:key is the key id, its raw secret is what wraps), plus
 * a random 32-byte Ed25519 signing seed -- a minted PUK is always a complete
 * identity (only a rotation-adopted one lacks the signing half).
 *
 * @returns {Promise<Required<Puk>>}
 */
export async function mintPuk(): Promise<Required<Puk>> {
  const { epochId, secret } = await mintEpoch()
  const signingSeed = new Uint8Array(32)
  crypto.getRandomValues(signingSeed)
  return { id: epochId, secret, signingSeed }
}

/**
 * Reconstructs the PUK's key-agreement key and its single-key resolver from
 * the stored material -- the vault-key pair a session supplies to the storage
 * layer, making the PUK recipient zero of every encrypted collection. The key
 * id is the self-describing `<did:key>#<fingerprint>` form, so grantee-side
 * did:key recipient resolution routes it like any other roster entry.
 *
 * @param options {object}
 * @param options.puk {Puk}
 * @returns {{ keyAgreementKey: IKeyAgreementKey, keyResolver: IKeyResolver }}
 */
export function pukVaultKeys({ puk }: { puk: Puk }): {
  keyAgreementKey: IKeyAgreementKey
  keyResolver: IKeyResolver
} {
  const keyAgreementKey = X25519KeyAgreementKey2020.fromRawSecret({
    secret: puk.secret,
    controller: puk.id,
    id: epochKeyIdFor(puk.id)
  }) as IKeyAgreementKey
  const keyResolver = singleKeyResolver({ keyAgreementKey })
  return { keyAgreementKey, keyResolver }
}
