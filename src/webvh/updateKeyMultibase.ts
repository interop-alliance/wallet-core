/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The update-key public multibase derivation, kept in a file of its own. Its
 * one runtime import is the Ed25519 key library, so the pure ladder derivation
 * can take it without loading the did:webvh log code. `webvh/didWebvh.ts`
 * re-exports it and remains its public home.
 */
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'

/**
 * The `publicKeyMultibase` of the Ed25519 update key a seed derives, as it
 * appears in the log's `parameters.updateKeys`.
 *
 * @param options {object}
 * @param options.seed {Uint8Array}   a 32-byte Ed25519 seed
 * @returns {Promise<string>}
 */
export async function updateKeyMultibase({
  seed
}: {
  seed: Uint8Array
}): Promise<string> {
  const keyPair = await Ed25519VerificationKey.generate({ seed })
  return keyPair.publicKeyMultibase
}
