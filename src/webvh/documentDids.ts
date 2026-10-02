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
import { vmFragmentOf } from '@interop/vh-resource-log'
import { ladderVmIds } from '../resourceLog/document.js'
import { clientKeyAgreementController } from './didWebvh.js'
import { enrolledClientVmIds } from './listClients.js'

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
 * enrolled client's ({@link enrolledClientVmIds}) and each ladder VM's bare
 * did:key ({@link ladderVmIds}), both from the verification method's
 * fragment, which is the key's multibase. A verification method whose id
 * carries no fragment names no key and is skipped. An entry carrying no
 * document state is skipped too.
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
  const addDids = (target: Set<string>, vmIds: string[]) => {
    for (const vmId of vmIds) {
      const signingKeyMultibase = vmFragmentOf(vmId)
      if (signingKeyMultibase) {
        target.add(walletClientDid({ signingKeyMultibase }))
      }
    }
  }
  for (const entry of log) {
    const doc = entry?.state
    if (doc === undefined || doc === null) {
      continue
    }
    addDids(clientDids, enrolledClientVmIds({ doc }))
    addDids(ladderDids, ladderVmIds({ doc }))
  }
  return { clientDids, ladderDids }
}
