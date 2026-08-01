/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The did:web relationship map the did:webvh module round-trips: the durable
 * `keys.json` binding from DID relationship to KMS key, plus the fragment
 * helper both documents' verification-method ids are read through. A KMS key's
 * public alias expands `{publicKeyMultibase}` at generate time, so a
 * verification-method id already carries the key's `publicKeyMultibase` and no
 * separate key-description fetch is ever needed.
 */

/**
 * One verification method's durable binding: the verification-method id (the
 * did:web `#fragment` URL, which is also the KMS key's publicAlias) and the
 * KMS key id used to invoke signing.
 */
export interface DidWebKey {
  vmId: string
  kmsKeyId: string
}

/**
 * The key-id map persisted as `keys.json` in the private `key-map` collection:
 * the durable mapping from DID relationship to KMS key, since the KMS protocol
 * has no list-keys endpoint and key ids are server-generated.
 */
export interface DidWebKeyMap {
  authentication: DidWebKey
  assertionMethod: DidWebKey
  keyAgreement: DidWebKey
}

/**
 * The bare `publicKeyMultibase` a KMS key alias or verification-method id
 * carries in its fragment. The KMS expanded `#{publicKeyMultibase}` at generate
 * time, so the fragment IS the multibase key (no separate key-description fetch
 * needed).
 *
 * @param id {string}
 * @returns {string}
 */
export function multibaseOf(id: string): string {
  return id.slice(id.lastIndexOf('#') + 1)
}
