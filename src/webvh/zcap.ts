/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * ZCap signing under the account's did:webvh identity. After controller
 * promotion the data Space's controller is the did:webvh DID, whose document
 * carries a verification method per enrolled client -- so invocations and
 * delegations must be signed with a keyId of the form
 * `<did:webvh>#<publicKeyMultibase>` (this client's Ed25519 key, published
 * under `capabilityInvocation` / `capabilityDelegation`). The key material
 * is unchanged -- the client's own Ed25519 pair -- only the keyId names the
 * verification method in the did:webvh document instead of the did:key one.
 */
import { Ed25519Signature2020 } from '@interop/ed25519-signature'
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { ZcapClient } from '@interop/ezcap'
import type { ISigner } from '@interop/data-integrity-core'
import { ladderVmSeed } from '../unlock/ladder.js'

/**
 * The minimal shape of a signing key agent this module operates on -- what
 * `@interop/webkms-client`'s `CapabilityAgent` (and therefore the `keyAgent`
 * of `agentsFromSeed`) already provides: a did:key id, a signer, and the
 * underlying Ed25519 verification key descriptor the X25519 key-agreement twin
 * derives from.
 */
export interface ICapabilityAgent {
  id: string
  handle: string
  getSigner: () => ISigner
  getVerificationKeyPair: () => {
    type: string
    controller: string
    publicKeyMultibase: string
    privateKeyMultibase?: string
  }
}

/**
 * The client's Ed25519 public key multibase (`z6Mk...`), read out of its
 * did:key id (`did:key:<publicKeyMultibase>`).
 *
 * @param options {object}
 * @param options.keyAgent {ICapabilityAgent}
 * @returns {string}
 */
export function clientSigningKeyMultibase({
  keyAgent
}: {
  keyAgent: ICapabilityAgent
}): string {
  const [scheme, method, publicKeyMultibase] = keyAgent.id.split(':')
  if (scheme !== 'did' || method !== 'key' || !publicKeyMultibase) {
    throw new Error(`Not a did:key agent id: "${keyAgent.id}".`)
  }
  return publicKeyMultibase
}

/**
 * A signer over the client's Ed25519 key whose id names this client's
 * verification method in the did:webvh document
 * (`<did:webvh>#<publicKeyMultibase>`). The underlying signer's `sign` is
 * bound rather than spread, so a prototype-hosted method survives.
 *
 * @param options {object}
 * @param options.keyAgent {ICapabilityAgent}
 * @param options.did {string}   the account's did:webvh DID
 * @returns {object}   an ISigner-shaped `{ id, type, sign }`
 */
export function webvhSigner({
  keyAgent,
  did
}: {
  keyAgent: ICapabilityAgent
  did: string
}) {
  const base = keyAgent.getSigner() as {
    type?: string
    sign: (options: { data: Uint8Array }) => Promise<Uint8Array>
  }
  return {
    id: `${did}#${clientSigningKeyMultibase({ keyAgent })}`,
    type: base.type ?? 'Ed25519VerificationKey2020',
    sign: base.sign.bind(base)
  }
}

/**
 * A ZcapClient signing invocations and delegations with this client's key
 * under its did:webvh verification method id -- the client every data-Space
 * request uses once the Space controller is the did:webvh.
 *
 * @param options {object}
 * @param options.keyAgent {ICapabilityAgent}
 * @param options.did {string}   the account's did:webvh DID
 * @returns {ZcapClient}
 */
export function webvhZcapClient({
  keyAgent,
  did
}: {
  keyAgent: ICapabilityAgent
  did: string
}): ZcapClient {
  const signer = webvhSigner({ keyAgent, did })
  return new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: signer,
    delegationSigner: signer
  })
}

/**
 * A ZcapClient signing with the client's plain did:key identity -- the
 * pre-promotion form, reconstructable from the key agent alone. Used to
 * authorize the promotion itself (the PUT naming the did:webvh is signed by
 * the STORED controller, the did:key) and to heal a promotion that tore.
 *
 * @param options {object}
 * @param options.keyAgent {ICapabilityAgent}
 * @returns {ZcapClient}
 */
export function didKeyZcapClient({
  keyAgent
}: {
  keyAgent: ICapabilityAgent
}): ZcapClient {
  const signer = keyAgent.getSigner()
  return new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    invocationSigner: signer,
    delegationSigner: signer
  })
}

/**
 * A CapabilityAgent-shaped wrapper presenting the client's key under the
 * did:webvh identity, for consumers that take an agent rather than a signer
 * (the WebKMS `KeystoreAgent`, once the keystore's controller is promoted to
 * the did:webvh).
 *
 * @param options {object}
 * @param options.keyAgent {ICapabilityAgent}
 * @param options.did {string}   the account's did:webvh DID
 * @returns {object}   an ICapabilityAgent-shaped wrapper
 */
export function webvhCapabilityAgent({
  keyAgent,
  did
}: {
  keyAgent: ICapabilityAgent
  did: string
}): ICapabilityAgent {
  const signer = webvhSigner({ keyAgent, did })
  return {
    id: did,
    handle: keyAgent.handle,
    getSigner: () => signer,
    getVerificationKeyPair: () => keyAgent.getVerificationKeyPair()
  }
}

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
 * -- can
 * mint the client annex generation delegation and the ladder-signed renewals.
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
 * the durable flow: any later login that decrypts the unlock record
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

// `isWebvhDid` lives in the `did.ts` leaf so modules outside the signing graph
// can import the shape check alone; this remains its public home.
export { isWebvhDid } from './did.js'
