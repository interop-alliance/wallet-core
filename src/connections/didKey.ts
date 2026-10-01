/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The two values a directory reader derives from a party's Ed25519 did:key:
 * the signing-key multibase a wallet client's entry joins the account
 * document on, and the key-epoch recipient kid a grantee is admitted under.
 *
 * Both are derived rather than stored. A wallet client's entry `id` is its
 * did:key, whose method-specific part is the `publicKeyMultibase` the account
 * document's verification method carries. A grantee's recipient key is the
 * X25519 twin was-client derives from the same DID.
 */
import {
  isEd25519DidKey,
  x25519RecipientFromDidKey
} from '@interop/was-client/edv/cipher'
import { rosterRecipientKid } from '../keys/rosterRecipientKid.js'

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
