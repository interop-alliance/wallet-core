/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The values a directory reader derives from a did:key rather than stores:
 * the signing-key multibase a wallet client's entry joins the account
 * document on, the key-epoch recipient kid a grantee is admitted under, and
 * the wallet's own pairwise did:key toward a party, derived from the seed on
 * the party's entry.
 *
 * A wallet client's entry `id` is its did:key, whose method-specific part is
 * the `publicKeyMultibase` the account document's verification method
 * carries. A grantee's recipient key is the X25519 twin was-client derives
 * from the same DID. The pairwise key comes from was-client's
 * `agentsFromSeed` under its pinned bootstrap names, so every client of the
 * account derives the same did:key from the same stored seed.
 */
import {
  isEd25519DidKey,
  x25519RecipientFromDidKey
} from '@interop/was-client/edv/cipher'
import { agentsFromSeed } from '@interop/was-client/identity'
import type { CapabilityAgent } from '@interop/capability-agent'
import type { ZcapClient } from '@interop/ezcap'
import { rosterRecipientKid } from '../keys/rosterRecipientKid.js'
import { decodeConnectionSeed } from './entry.js'
import { verifyConnectionSeedTag } from './resourceId.js'
import type { ConnectionIdKey } from './resourceId.js'

const DID_KEY_PREFIX = 'did:key:'

/**
 * The signing-key multibase an Ed25519 did:key carries, or `undefined` for any
 * other DID. The one join key between a wallet client's directory entry and
 * the account document's client listing.
 *
 * @param options {object}
 * @param options.did {string}
 * @returns {string | undefined}
 */
export function signingKeyMultibaseOfDid({
  did
}: {
  did: string
}): string | undefined {
  return isEd25519DidKey(did) ? did.slice(DID_KEY_PREFIX.length) : undefined
}

/**
 * The key-epoch recipient kid of a party named by an Ed25519 did:key: the
 * id of the X25519 twin was-client derives, formatted by the one roster kid
 * builder. `undefined` for any other DID, which no epoch can list.
 *
 * @param options {object}
 * @param options.did {string}
 * @returns {string | undefined}
 */
export function connectionRecipientKid({
  did
}: {
  did: string
}): string | undefined {
  const signingKeyMultibase = signingKeyMultibaseOfDid({ did })
  if (signingKeyMultibase === undefined) {
    return undefined
  }
  const { publicKeyMultibase } = x25519RecipientFromDidKey({ did })
  return rosterRecipientKid({
    signingKeyMultibase,
    keyAgreementKeyMultibase: publicKeyMultibase
  })
}

/**
 * The wallet's pairwise did:key toward a party, and the signer behind it:
 * was-client's `agentsFromSeed` over the entry's stored `seed`, after the
 * seed's tag verifies under the directory's blinded-index key. A seed whose
 * tag fails is refused with an `Error`, and the caller fails closed: a host
 * that planted a seed is misbehaving, so the seed is not read as absent.
 *
 * @param options {object}
 * @param options.hmacKey {ConnectionIdKey}   the collection's blinded-index
 *   key
 * @param options.seed {string}   the entry's `seed`
 * @param options.seedTag {string}   the entry's `seedTag`
 * @returns {Promise<object>}   the did:key, the `ZcapClient` that signs as
 *   it, and the `CapabilityAgent` behind both
 */
export async function connectionDidKey({
  hmacKey,
  seed,
  seedTag
}: {
  hmacKey: ConnectionIdKey
  seed: string
  seedTag: string
}): Promise<{
  did: string
  zcapClient: ZcapClient
  keyAgent: CapabilityAgent
}> {
  if (!(await verifyConnectionSeedTag({ hmacKey, seed, seedTag }))) {
    throw new Error(
      "The connections entry's seed tag does not verify under this " +
        "directory's key; the seed is refused."
    )
  }
  const seedBytes = decodeConnectionSeed(seed)
  if (seedBytes === undefined) {
    throw new TypeError('A connection seed decodes to 32 bytes.')
  }
  const { controllerDid, zcapClient, keyAgent } = await agentsFromSeed({
    seed: seedBytes
  })
  return { did: controllerDid, zcapClient, keyAgent }
}
