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
import type { ZcapClient } from '@interop/ezcap'
import type { ISigner } from '@interop/data-integrity-core'
import { zcapClientForSigner } from '../identity/agents.js'

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
  return zcapClientForSigner({ signer: webvhSigner({ keyAgent, did }) })
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
  return zcapClientForSigner({ signer: keyAgent.getSigner() })
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

// `isWebvhDid` lives in the `did.ts` leaf so modules outside the signing graph
// can import the shape check alone; this remains its public home.
export { isWebvhDid } from './did.js'
