/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The DIDs an account document names, read off a verified log: one walk over
 * every entry, for a wallet that asks "is this DID one of mine". A revoked
 * client's did:key stays public in the log for good, so the sets cover it,
 * and a revision a since-revoked client made still reads as the account's.
 */
import type { DIDLog } from '@interop/did-method-webvh'
import {
  enrolledClientKeyMultibases,
  ladderVmKeyMultibases,
  type AccountDocument
} from '../resourceLog/document.js'
import { clientKeyAgreementController } from './didWebvh.js'

/**
 * A wallet client's did:key, from the signing-key multibase the account
 * document lists for it. For an Ed25519 did:key the method-specific id is
 * exactly that multibase, so this is the inverse of
 * `signingKeyMultibaseOfDid` on `/connections`: the id a wallet client's
 * `connections` entry is keyed by. It is the one string
 * {@link clientKeyAgreementController} writes as the controller marker, read
 * under the name a directory consumer asks for.
 *
 * @param options {object}
 * @param options.signingKeyMultibase {string}
 * @returns {string}
 */
export function walletClientDid({
  signingKeyMultibase
}: {
  signingKeyMultibase: string
}): string {
  return clientKeyAgreementController({ signingKeyMultibase })
}

/**
 * Every did:key the account log's documents name across every entry: each
 * enrolled client's ({@link enrolledClientKeyMultibases}) and each ladder
 * VM's ({@link ladderVmKeyMultibases}) bare did:key, from the key multibase
 * the shared readers name for the method. A member the readers name no key
 * for (one resolving to no method, or to a method publishing no
 * `publicKeyMultibase`) is skipped, the same answer the ladder-rung
 * attribution gives it. An entry carrying no document state is skipped too.
 *
 * @param options {object}
 * @param options.log {DIDLog}   the VERIFIED account log
 * @returns {{ clientDids: Set<string>; ladderDids: Set<string> }}
 */
export function accountLogDids({ log }: { log: DIDLog }): {
  clientDids: Set<string>
  ladderDids: Set<string>
} {
  const clientDids = new Set<string>()
  const ladderDids = new Set<string>()
  const addDids = (target: Set<string>, keys: Set<string>) => {
    for (const signingKeyMultibase of keys) {
      target.add(walletClientDid({ signingKeyMultibase }))
    }
  }
  for (const entry of log) {
    const doc = entry?.state as AccountDocument | undefined | null
    if (doc === undefined || doc === null) {
      continue
    }
    addDids(clientDids, enrolledClientKeyMultibases({ doc }))
    addDids(ladderDids, ladderVmKeyMultibases({ doc }))
  }
  return { clientDids, ladderDids }
}
