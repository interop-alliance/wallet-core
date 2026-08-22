/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The standing unlock credential's client identity: the deterministic key set
 * every unlock method (a passphrase, a passkey PRF output) derives from its
 * own unlock seed under the standing-credential configuration -- the recovery-code
 * configuration minus spend-on-use. The credential's key-agreement key holds a
 * standing wrap in the user key roster (escrowed into every epoch, kept alive
 * by rotation fan-out), and its binding MAC key authenticates the unlock
 * record's account core, so a fresh browser holding nothing but the
 * credential can locate the account, prove the record genuine, and decrypt.
 * Update authority stays latent and rides the record instead: the ladder seed
 * (`./ladder`) never derives from the secret.
 *
 * The derivations are wire-level: two wallet apps must produce byte-identical
 * output for the same secret and KDF, so every salt and info label below is
 * permanent. The HKDF input is the method's own 32-byte unlock seed
 * (`deriveUnlockSeed`), so the expensive passphrase stretch runs once per
 * typed secret and each unlock method's distinct KDF salt keeps two methods'
 * client identities from ever colliding.
 */
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { agentsFromSeed } from '../identity/agents.js'
import type { ProfileAgents } from '../identity/agents.js'

/**
 * The HKDF salt for a standing credential's client-side expansions, and the
 * per-key info labels. All permanent. The salt differs from the recovery
 * code's client salt (`freewallet/recovery/client-keys/v1`), so a code and a
 * standing method that somehow shared input material could still never derive
 * the same client identity.
 */
export const STANDING_CLIENT_SALT = 'freewallet/unlock/standing-client/v1'
const STANDING_CLIENT_SEED_INFO = 'client-seed'
const STANDING_BINDING_MAC_INFO = 'binding-mac'

/**
 * A credential-derived client identity, assembled from its 32-byte client
 * seed: the derived agents, the client did:key, the public multibases the
 * document and roster carry, and the roster recipient kid. The shared shape
 * of a standing credential's identity and a recovery code's (which extends it
 * with the code's single update key).
 */
export interface UnlockClientIdentity {
  clientSeed: Uint8Array
  agents: ProfileAgents
  clientDid: string
  signingKeyMultibase: string
  keyAgreementKeyMultibase: string
  /**
   * The kid of the credential's user-key-roster entry -- its key-agreement
   * key's id exactly as `agentsFromSeed` derives it (`did:key:<ed>#<x>`), so
   * the wrap minted at bind time is the one a fresh browser's roster read
   * looks for.
   */
  recipientKid: string
}

/**
 * Assembles a client identity from its 32-byte client seed: the one place the
 * agents, multibases, and roster kid are derived, shared by the standing
 * credential derivation here and the recovery code's
 * (`recoveryClientFromCode`), so the two derivations can never disagree on how a
 * seed becomes an identity.
 *
 * @param options {object}
 * @param options.clientSeed {Uint8Array}   the 32-byte client seed
 * @returns {Promise<UnlockClientIdentity>}
 */
export async function unlockClientIdentityFromSeed({
  clientSeed
}: {
  clientSeed: Uint8Array
}): Promise<UnlockClientIdentity> {
  const agents = await agentsFromSeed({ seed: clientSeed })
  const { publicKeyMultibase: keyAgreementKeyMultibase } =
    agents.keyAgreementKey as unknown as { publicKeyMultibase?: string }
  if (!keyAgreementKeyMultibase) {
    throw new Error('The derived key-agreement key has no public multibase.')
  }
  const [, , signingKeyMultibase] = agents.keyAgent.id.split(':')
  return {
    clientSeed,
    agents,
    clientDid: agents.keyAgent.id,
    signingKeyMultibase: signingKeyMultibase!,
    keyAgreementKeyMultibase,
    recipientKid: `${agents.keyAgent.id}#${keyAgreementKeyMultibase}`
  }
}

/**
 * A standing unlock credential's full client-side key set: the client
 * identity plus the binding MAC key that authenticates the unlock record's
 * account core (computed at bind time, verified before the pointer is
 * trusted -- the storage host never holds it).
 */
export interface StandingUnlockClient extends UnlockClientIdentity {
  bindingMacKey: Uint8Array
}

/**
 * Derives a standing credential's client key set from the method's 32-byte
 * unlock seed (the output of `deriveUnlockSeed` under the method's own KDF).
 * Deterministic: the same secret under the same KDF always yields the same
 * key set, which is what makes a fresh browser's self-enrollment possible
 * with nothing but the credential in hand.
 *
 * @param options {object}
 * @param options.unlockSeed {Uint8Array}   the method's 32-byte unlock seed
 * @returns {Promise<StandingUnlockClient>}
 */
export async function standingClientFromUnlockSeed({
  unlockSeed
}: {
  unlockSeed: Uint8Array
}): Promise<StandingUnlockClient> {
  const salt = new TextEncoder().encode(STANDING_CLIENT_SALT)
  const clientSeed = hkdf(
    sha256,
    unlockSeed,
    salt,
    new TextEncoder().encode(STANDING_CLIENT_SEED_INFO),
    32
  )
  const bindingMacKey = hkdf(
    sha256,
    unlockSeed,
    salt,
    new TextEncoder().encode(STANDING_BINDING_MAC_INFO),
    32
  )
  const identity = await unlockClientIdentityFromSeed({ clientSeed })
  return { ...identity, bindingMacKey }
}
