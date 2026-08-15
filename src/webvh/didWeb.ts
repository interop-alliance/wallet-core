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
import { vmFragmentOf } from '../resourceLog/vmFragment.js'

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
 *
 * The map carries no `assertionMethod` binding: the account document's
 * `assertionMethod` relation lists client keys only (membership there
 * authorizes appends to co-managed resource logs under the App Connect
 * Resource Log Profile), so no KMS-held assertion key exists.
 */
export interface DidWebKeyMap {
  authentication: DidWebKey
  keyAgreement: DidWebKey
}

/**
 * The bare `publicKeyMultibase` a KMS key alias or verification-method id
 * carries in its fragment. The KMS expanded `#{publicKeyMultibase}` at generate
 * time, so the fragment IS the multibase key (no separate key-description fetch
 * needed).
 *
 * A fragmentless id reads back whole, deliberately: a KMS key alias carrying
 * no `#` IS the bare multibase value.
 *
 * @param id {string}
 * @returns {string}
 */
export function multibaseOf(id: string): string {
  return vmFragmentOf(id) ?? id
}
