/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The unlock identity: what an unlock seed (`kdf.ts`) expands into. The
 * identity's only jobs are addressing the minimal unlock Space and holding
 * the key-agreement key the keyring record is encrypted to.
 *
 * Kept apart from the KDF so a caller that only derives a seed loads a hash
 * library and nothing else. This file imports `kdf.ts`, and `kdf.ts` imports
 * nothing from here.
 */
import { deriveSpaceId } from '@interop/was-client/sync'
import { CapabilityAgent } from '@interop/capability-agent'
import { agentsFromKeyAgent } from '@interop/was-client/identity'
import type { ProfileAgents } from '@interop/was-client/identity'
import { deriveUnlockSeed } from './kdf.js'
import type { UnlockKdf } from './kdf.js'
import { recordSignerFromAgent } from './record.js'
import type { RecordSigner } from './record.js'

/**
 * The load-bearing `CapabilityAgent` derivation names for an unlock identity
 * (the counterpart of the data identity's bootstrap names): every unlock
 * derivation runs through these exact strings, so they can never change
 * without stranding existing accounts.
 */
export const UNLOCK_HANDLE = 'unlock'
export const UNLOCK_KEY_NAME = 'unlock-key'

/**
 * Derives the full unlock identity from an unlock secret: the unlock
 * CapabilityAgent, a ZcapClient that can both invoke and delegate (the
 * unlock agent delegates a management zcap on its own Space to the account
 * controller at bind time), the unlock KAK + resolver for wrap/unwrap, the
 * record signer that signs and verifies the keyring record's proof, and the
 * unlock Space id. Performs no I/O -- the derivation seam for tests and future
 * unlock methods.
 *
 * @param options {object}
 * @param options.secret {string | Uint8Array}
 * @param options.kdf {UnlockKdf}
 * @returns {Promise<UnlockIdentity>}
 */
export async function deriveUnlockIdentity({
  secret,
  kdf
}: {
  secret: string | Uint8Array
  kdf: UnlockKdf
}): Promise<UnlockIdentity> {
  const seed = await deriveUnlockSeed({ secret, kdf })
  return unlockIdentityFromSeed({ seed })
}

/**
 * Assembles the unlock identity from an already-derived 32-byte unlock seed.
 * The seam that lets an app run the expensive stretch once per typed secret:
 * `deriveUnlockSeed` yields the seed, and both this assembly and the
 * standing-credential expansion (`unlock/standingClient`) consume it.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   the method's 32-byte unlock seed
 * @returns {Promise<UnlockIdentity>}
 */
export async function unlockIdentityFromSeed({
  seed
}: {
  seed: Uint8Array
}): Promise<UnlockIdentity> {
  const agent = await CapabilityAgent.fromSeed({
    seed,
    handle: UNLOCK_HANDLE,
    keyName: UNLOCK_KEY_NAME
  })
  // The unlock KAK is the Montgomery form of the unlock signing key -- the same
  // derivation the client side uses (`agentsFromSeed`), so a returning user
  // reconstitutes the exact key that wrapped the keyring record.
  const { zcapClient, keyAgreementKey, keyResolver } = agentsFromKeyAgent({
    keyAgent: agent
  })

  // The record signer is the unlock signing key itself, named by its public
  // multibase: the keyring record's proof is made and checked against a key
  // that derives from the secret, so the storage host never holds it and a
  // fresh client holds the verification prior by construction.
  const recordSigner = recordSignerFromAgent({ keyAgent: agent })

  const spaceId = unlockSpaceIdFor({ did: agent.id })
  return {
    agent,
    zcapClient,
    keyAgreementKey,
    keyResolver,
    recordSigner,
    spaceId
  }
}

/**
 * The unlock Space id an unlock identity addresses: was-client's
 * `deriveSpaceId` over the unlock did:key (`base64url(SHA-256(did))`,
 * unpadded) -- a discovery convention, not an authorization one (holding the
 * id grants nothing). The address is wire-level (it is the one durable
 * locator a fresh client holds), so it comes from the one shared derivation
 * rather than a local restatement of it.
 *
 * @param options {object}
 * @param options.did {string}   the unlock identity's did:key
 * @returns {string}
 */
export function unlockSpaceIdFor({ did }: { did: string }): string {
  return deriveSpaceId(did)
}

/**
 * The derived unlock identity, as `deriveUnlockIdentity` returns it. Stated
 * explicitly rather than inferred from the return: the agent set's members
 * are named by `ProfileAgents`, so the emitted declaration references this
 * package's own copy of those types rather than whichever copy a linked
 * dependency happens to carry.
 */
export interface UnlockIdentity extends Pick<
  ProfileAgents,
  'zcapClient' | 'keyAgreementKey' | 'keyResolver'
> {
  agent: CapabilityAgent
  recordSigner: RecordSigner
  spaceId: string
}
