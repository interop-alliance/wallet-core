/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The roster recipient kid builder, in a leaf file with no imports: a caller
 * that only derives a client identity (`unlock/standingClient.ts`) takes it
 * from here without loading the roster store's did:webvh and resource-log
 * graph.
 */

/**
 * A wallet client's roster kid: its key-agreement key's id exactly as
 * `agentsFromSeed` derives it at the client's own logins
 * (`did:key:<ed-multibase>#<x-multibase>`). One builder for the whole
 * lifecycle -- the wrap the enrollment ceremony mints, the entry a roster read
 * looks for, and the recipient a rotation retires are the same string by
 * construction rather than by three copies agreeing.
 *
 * @param options {object}
 * @param options.signingKeyMultibase {string}   the client's Ed25519 signing
 *   key
 * @param options.keyAgreementKeyMultibase {string}   its X25519 twin
 * @returns {string}
 */
export function rosterRecipientKid({
  signingKeyMultibase,
  keyAgreementKeyMultibase
}: {
  signingKeyMultibase: string
  keyAgreementKeyMultibase: string
}): string {
  return `did:key:${signingKeyMultibase}#${keyAgreementKeyMultibase}`
}
