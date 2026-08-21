/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The self-enrollment completion core: what a fresh browser runs once its
 * typed credential has located the account, proven the unlock record genuine,
 * and handed over the bridge delegation and the ladder seed. One call turns
 * the credential's latent authority into an ordinary enrolled client, with no
 * second party involved:
 *
 * 1. Mint the new client's whole key set locally (client seed, did:webvh
 *    update-key seeds). Nothing is durable before the ceremony succeeds.
 * 2. Write the self-enrolling continuation through the delegated `did.jsonl`
 *    bridge ({@link selfEnrollWebvhClient}): the reveal-and-commit entry
 *    signed by the attributed ladder rung, then the add entry that publishes
 *    the new client and retires the rung. Loud by construction -- the
 *    world-readable, hash-chained log extends before a single byte can be
 *    read.
 * 3. Verify the account log locally and perform the first roster read,
 *    signed with the just-published `<did:webvh>#<multibase>` key and
 *    unwrapping the user key from the CREDENTIAL's standing wrap (escrowed
 *    into every epoch at bind time, kept alive by rotation fan-out).
 * 4. Escrow the new client into the roster as its own recipient
 *    (`addUserKeyRosterRecipient`, epochs unwrapped with the credential's
 *    key-agreement key), so later logins on this browser read the roster the
 *    ordinary enrolled way.
 *
 * Persisting the key set under the app's own unlock layer is the caller's
 * job, exactly as with the enrollment ceremony's completion: this module
 * hands back the key set, the user key, and the roster epoch to pin, and
 * stops there. Every stage is idempotent, so a torn run converges by
 * re-running with the same credential (step 2 resumes from the standing
 * commitments; a re-run after completion mints a fresh client, which is the
 * ordinary next self-enrollment).
 */
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { agentsFromSeed } from '../identity/agents.js'
import {
  addUserKeyRosterRecipient,
  readUserKeyRoster,
  rosterRecipientKid,
  userKeyRosterLogSigner
} from '../keys/userKeyRoster.js'
import { userKeyRosterDescriptorStore } from '../keys/rosterStore.js'
import type { UserKey } from '../keys/userKey.js'
import type { AccountPointer } from '../keyring/record.js'
import {
  memoryResourceLogPinStore,
  webvhResourceLogController,
  type ResourceLogPinStore
} from '../resourceLog/index.js'
import {
  mintClientWebvhUpdateKeys,
  updateKeyMultibase
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhEnrollmentKeys
} from '../webvh/didWebvh.js'
import { verifyAccountLog } from '../webvh/verifyLog.js'
import {
  clientSigningKeyMultibase,
  isWebvhDid,
  webvhZcapClient
} from '../webvh/zcap.js'
import { selfEnrollWebvhClient } from './ladderAnchored.js'
import type { UnlockLogStore } from '../unlock/standingWebvh.js'

/**
 * Runs the whole self-enrollment described in the module doc. The caller has
 * already unwrapped the credential's unlock record (so it holds the
 * credential-authenticated pointer, the bridge delegation behind `logStore`,
 * and the ladder seed) and derived the credential's client identity (so it
 * holds the key-agreement key with its secret half).
 *
 * @param options {object}
 * @param options.pointer {AccountPointer}   the credential-authenticated
 *   account pointer; must name a did:webvh
 * @param options.ladderSeed {Uint8Array}   the credential's update-key ladder
 *   seed, from its unlock record
 * @param options.credentialKeyAgreementKey {IKeyAgreementKey}   the
 *   credential's own key-agreement key (secret half included) -- its roster
 *   entry, which the user key is unwrapped from and every epoch re-wrapped
 *   with
 * @param options.logStore {UnlockLogStore}   the public log read plus the
 *   delegated `did.jsonl` PUT, built by the app around the record's bridge
 *   delegation
 * @param [options.accountLogPinStore] {ResourceLogPinStore}   this client's
 *   chain-head pin for the account log. A fresh browser normally has none
 *   (this is its first contact), which is exactly the pin's
 *   trust-on-first-use establishment
 * @returns {Promise<object>}   the new client's key set (for the caller to
 *   persist under its unlock layer), its did:key, the account DID, the user
 *   key, and the roster epoch to pin
 */
export async function selfEnrollClientCore({
  pointer,
  ladderSeed,
  credentialKeyAgreementKey,
  logStore,
  accountLogPinStore
}: {
  pointer: AccountPointer
  ladderSeed: Uint8Array
  credentialKeyAgreementKey: IKeyAgreementKey
  logStore: UnlockLogStore
  accountLogPinStore?: ResourceLogPinStore
}): Promise<{
  clientSeed: Uint8Array
  webvhUpdateKeys: ClientWebvhUpdateKeys
  clientDid: string
  did: string
  userKey: UserKey
  latestEpochId: string
}> {
  const expectedDid = pointer.did
  if (!expectedDid || !isWebvhDid(expectedDid)) {
    throw new Error(
      'The account pointer names no did:webvh; only a promoted account can ' +
        'self-enroll a client.'
    )
  }

  // The new client's whole key set, minted locally; nothing travels but the
  // public halves the log entries publish.
  const clientSeed = crypto.getRandomValues(new Uint8Array(32))
  const { keyAgent, keyAgreementKey } = await agentsFromSeed({
    seed: clientSeed
  })
  const { publicKeyMultibase: keyAgreementKeyMultibase } =
    keyAgreementKey as unknown as { publicKeyMultibase?: string }
  if (!keyAgreementKeyMultibase) {
    throw new Error('The minted key-agreement key has no public multibase.')
  }
  const signingKeyMultibase = clientSigningKeyMultibase({ keyAgent })
  const webvhUpdateKeys = await mintClientWebvhUpdateKeys()
  const newClientKeys: WebvhEnrollmentKeys = {
    signingKeyMultibase,
    keyAgreementKeyMultibase,
    updateKeyMultibase: await updateKeyMultibase({
      seed: webvhUpdateKeys.updateSeed
    }),
    stagedUpdateKeyMultibase: await updateKeyMultibase({
      seed: webvhUpdateKeys.stagedSeed
    })
  }

  // The loud half: two log entries through the delegated bridge.
  await selfEnrollWebvhClient({
    store: logStore,
    ladderSeed,
    newClientKeys,
    newClientUpdateSeeds: webvhUpdateKeys,
    expectedDid
  })

  // Verify the continuation from the world-readable log -- the same
  // first-contact read an enrollee's completion runs, and the controller the
  // roster log's entry proofs are checked against.
  const verified = await verifyAccountLog({
    did: expectedDid,
    spaceId: pointer.spaceId,
    host: pointer.host,
    ...(accountLogPinStore ? { pinStore: accountLogPinStore } : {})
  })

  // The first roster read: signed with the `<did:webvh>#<multibase>` keyId
  // the add entry just published, unwrapping the user key from the
  // CREDENTIAL's standing wrap. First contact: the chain-head pin this read
  // establishes is session-local here; the app's durable pin is established
  // by its own first login read.
  const zcapClient = webvhZcapClient({ keyAgent, did: expectedDid })
  const store = userKeyRosterDescriptorStore({
    storageServerUrl: pointer.host,
    zcapClient,
    spaceId: pointer.spaceId,
    resolveController: async () =>
      webvhResourceLogController({ did: expectedDid, log: verified.log }),
    pinStore: memoryResourceLogPinStore(),
    signer: userKeyRosterLogSigner({ keyAgent })
  })
  const read = await readUserKeyRoster({
    store,
    clientKeyAgreementKey: credentialKeyAgreementKey
  })
  if (!read) {
    throw new Error(
      'The account has no user key roster; it must finish provisioning ' +
        'before a client can self-enroll.'
    )
  }

  // Escrow the new client into the roster as its own recipient, so later
  // logins on this browser read the roster the ordinary enrolled way.
  // Idempotent: a wrap already standing is returned as-is.
  await addUserKeyRosterRecipient({
    store,
    recipient: {
      id: rosterRecipientKid({
        signingKeyMultibase,
        keyAgreementKeyMultibase
      }),
      publicKeyMultibase: keyAgreementKeyMultibase
    },
    ownerKeyAgreementKey: credentialKeyAgreementKey
  })

  return {
    clientSeed,
    webvhUpdateKeys,
    clientDid: keyAgent.id,
    did: expectedDid,
    userKey: read.userKey,
    latestEpochId: read.latestEpochId
  }
}
