/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * ZCap signing under the ladder VM -- the document-visible key a standing
 * credential derives from its ladder seed. The enrolled clients' signing
 * wrappers stay in `webvh/zcap.ts`; these two live with the annex because
 * only the credential-anchored flows (a ladder-anchored account, a transient
 * session holding nothing but the unlock credential) ever sign as the ladder.
 */
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { ZcapClient } from '@interop/ezcap'
import type { ICapabilityAgent } from '../webvh/zcap.js'
import { ladderVmSeed } from './ladder.js'

/**
 * A ZcapClient signing with the account ladder's document-visible
 * verification method -- the ladder VM, derived from the credential's ladder
 * seed and published under `assertionMethod` and `capabilityDelegation` only.
 * Its keyId is `<accountDid>#<ladderVmMultibase>` (the flat Multikey shape
 * `ladderVerificationMethod` publishes, which `@interop/zcap`'s `isController`
 * check and the server's fragment resolver both depend on).
 *
 * Only DELEGATION is licensed for this client: the ladder VM carries no
 * `capabilityInvocation`, so an invocation signed with it fails the server's
 * current-key-set rule by construction. It exists so a ladder-anchored
 * account -- or a transient session holding nothing but the unlock credential
 * -- can mint the client annex generation delegation and the ladder-signed
 * renewals.
 *
 * That one-sided relation set is also how this library and the storage server
 * recognize a ladder VM. The annex's per-visit transient VM is the sibling
 * case and holds BOTH relations (decision 0013): it invokes the generation
 * delegation for the visit's own requests and delegates the visit's grants
 * onward, so it never matches the asymmetry.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account did:webvh
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed, from
 *   its unlock record
 * @returns {Promise<ZcapClient>}
 */
export async function ladderVmZcapClient({
  accountDid,
  ladderSeed
}: {
  accountDid: string
  ladderSeed: Uint8Array
}): Promise<ZcapClient> {
  const keyPair = await Ed25519VerificationKey.generate({
    seed: ladderVmSeed({ ladderSeed })
  })
  const { publicKeyMultibase } = keyPair
  // The key pair refuses to hand out a signer without an id; set the
  // document's verification-method id before asking.
  keyPair.id = `${accountDid}#${publicKeyMultibase}`
  const keySigner = keyPair.signer()
  const signer = {
    id: `${accountDid}#${publicKeyMultibase}`,
    type: 'Ed25519VerificationKey2020',
    sign: keySigner.sign.bind(keySigner) as (options: {
      data: Uint8Array
    }) => Promise<Uint8Array>
  }
  return new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: signer,
    delegationSigner: signer
  })
}

/**
 * The account ladder VM's key pair presented as a plain did:key agent -- the
 * ladder-anchored signup's BOOTSTRAP identity. The data Space (and the
 * auxiliary annex Space) of a credential-anchored signup are created
 * under this
 * did:key, exactly the role the founding client's persisted did:key plays in
 * the enrolled-client flow: any later login that decrypts the unlock record
 * re-derives the ladder seed and can finish (or unwind) a torn bootstrap --
 * the durability precondition restored by derivation instead of persistence.
 *
 * The derivation matches {@link ladderVmZcapClient}'s exactly
 * (`Ed25519VerificationKey.generate` over `ladderVmSeed`), so the bare
 * did:key controller and the document-published ladder VM are one key.
 *
 * @param options {object}
 * @param options.ladderSeed {Uint8Array}   the credential's ladder seed
 * @returns {Promise<ICapabilityAgent>}
 */
export async function ladderVmAgent({
  ladderSeed
}: {
  ladderSeed: Uint8Array
}): Promise<ICapabilityAgent> {
  const keyPair = await Ed25519VerificationKey.generate({
    seed: ladderVmSeed({ ladderSeed })
  })
  const { publicKeyMultibase } = keyPair
  const did = `did:key:${publicKeyMultibase}`
  // The key pair refuses to hand out a signer without an id; the did:key
  // verification-method form is what the server's did:key resolver expects.
  keyPair.id = `${did}#${publicKeyMultibase}`
  keyPair.controller = did
  const keySigner = keyPair.signer()
  const signer = {
    id: `${did}#${publicKeyMultibase}`,
    type: 'Ed25519VerificationKey2020',
    sign: keySigner.sign.bind(keySigner) as (options: {
      data: Uint8Array
    }) => Promise<Uint8Array>
  }
  return {
    id: did,
    handle: 'ladder-vm',
    getSigner: () => signer,
    getVerificationKeyPair: () => ({
      type: 'Ed25519VerificationKey2020',
      controller: did,
      publicKeyMultibase
    })
  }
}
