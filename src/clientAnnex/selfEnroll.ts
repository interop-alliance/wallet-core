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
 * Between the two entries of step 2 sits the required `onCommitted` seam: the
 * caller writes the pending client-key record there, so the add entry -- the
 * ceremony's pivot -- never publishes a client whose seed only a live tab
 * holds (the post-pivot derivability rule, `decisions/0010`). What that record
 * carries is what `resume` replays: the same seeds, and the head the pivot
 * entry was built on.
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
  type ResourceLogPinStore
} from '@interop/vh-resource-log'
import { webvhResourceLogController } from '../resourceLog/index.js'
import {
  mintClientWebvhUpdateKeys,
  updateKeyMultibase
} from '../webvh/didWebvh.js'
import type {
  ClientWebvhUpdateKeys,
  WebvhEnrollmentKeys
} from '../webvh/didWebvh.js'
import { accountLogPinId, verifyAccountLog } from '../webvh/verifyLog.js'
import {
  clientSigningKeyMultibase,
  isWebvhDid,
  webvhZcapClient
} from '../webvh/zcap.js'
import {
  assertBuiltOnHeadShape,
  selfEnrollWebvhClient
} from './ladderAnchored.js'
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
 *   chain-head pin for the account log, checked on every read the two log
 *   entries are built on and advanced as each publishes, then checked again
 *   by the verify that follows. A fresh browser normally has none (this is
 *   its first contact), which is exactly the pin's trust-on-first-use
 *   establishment
 * @param options.onCommitted {function}
 *   `(committed: { builtOnHead, clientSeed, webvhUpdateKeys }) =>
 *   Promise<void>` -- the REQUIRED persist-before-publish seam. The caller
 *   writes the pending client-key record there -- the `pending` codec group
 *   of `keys/clientKeyRecord.ts`, ceremony `'self-enrollment'` -- so the add
 *   entry never publishes a client this browser cannot re-derive, per the
 *   post-pivot derivability rule (`decisions/0010`). The argument carries
 *   everything that record needs beyond what the caller already holds: the
 *   key set is minted INSIDE this call, so the seeds are handed over here,
 *   while the record's `controller` and pointer DID are the caller's own
 *   `pointer`. On a resume the seeds handed back are the resumed record's own,
 *   verbatim, so re-persisting is idempotent. The ceremony's own seam
 *   ({@link selfEnrollWebvhClient}'s) takes `{ builtOnHead }` alone -- its
 *   callers hold the key set already -- and this call passes it a wrapper.
 *   The rest of the contract is the ceremony's: it runs after the
 *   reveal-and-commit entry stands and before the add entry is built, once
 *   per attempt, a throw withholds the pivot, and the idempotent completed
 *   branch never enters it. A call omitting the seam is refused with a
 *   `TypeError` before any read
 * @param [options.resume] {object}   the pending record's contents, replayed:
 *   `{ clientSeed, webvhUpdateKeys, builtOnHead }`. Supplied, the local key
 *   mint is SKIPPED and the whole enrollment key set is re-derived from the
 *   recorded seeds, so the resumed run publishes the same client the torn run
 *   was publishing, and `builtOnHead` is passed through as the ceremony's
 *   resume marker (refusing a served log that never reached that head with
 *   `BuiltOnHeadNotReachedError`). Everything downstream is unchanged: the
 *   ceremony's own revealed / committed / completed detection publishes only
 *   what is missing
 * @returns {Promise<object>}   the new client's key set (for the caller to
 *   persist under its unlock layer), its did:key, the account DID, the user
 *   key, the roster epoch to pin, and `committed` -- whether THIS call
 *   published the ceremony's pivot entry, propagated verbatim from
 *   {@link selfEnrollWebvhClient}. A resume that met an already-complete
 *   continuation returns `committed: false` and is a full success: the clear
 *   condition for the pending record is that the call RETURNED, never
 *   `committed === true`, or a resumed-onto-completed record would never be
 *   cleared. The member exists so a build skew that dropped it surfaces
 *   instead of reading as `false`
 */
export async function selfEnrollClientCore({
  pointer,
  ladderSeed,
  credentialKeyAgreementKey,
  logStore,
  accountLogPinStore,
  onCommitted,
  resume
}: {
  pointer: AccountPointer
  ladderSeed: Uint8Array
  credentialKeyAgreementKey: IKeyAgreementKey
  logStore: UnlockLogStore
  accountLogPinStore?: ResourceLogPinStore
  onCommitted: (committed: {
    builtOnHead: { scid: string; versionId: string }
    clientSeed: Uint8Array
    webvhUpdateKeys: ClientWebvhUpdateKeys
  }) => Promise<void>
  resume?: {
    clientSeed: Uint8Array
    webvhUpdateKeys: ClientWebvhUpdateKeys
    builtOnHead: { scid: string; versionId: string }
  }
}): Promise<{
  clientSeed: Uint8Array
  webvhUpdateKeys: ClientWebvhUpdateKeys
  clientDid: string
  did: string
  userKey: UserKey
  latestEpochId: string
  committed: boolean
}> {
  // Refused before any read, on the ceremony's own rule: without the seam the
  // pivot entry can publish a client whose seed nothing persisted.
  if (typeof onCommitted !== 'function') {
    throw new TypeError(
      'selfEnrollClientCore requires onCommitted: the pending client-key ' +
        'record must be persisted before the add entry publishes the client.'
    )
  }
  // A resume skips the mint on the strength of the recorded seeds, so its
  // marker must be usable as the fork guard: refused here, before any read,
  // rather than silently resuming unguarded.
  if (resume) {
    assertBuiltOnHeadShape({ builtOnHead: resume.builtOnHead })
  }
  const expectedDid = pointer.did
  if (!expectedDid || !isWebvhDid(expectedDid)) {
    throw new Error(
      'The account pointer names no did:webvh; only a promoted account can ' +
        'self-enroll a client.'
    )
  }

  // The new client's whole key set, minted locally; nothing travels but the
  // public halves the log entries publish. A resume mints nothing: every
  // member below is a pure derivation of the recorded seeds, so the replayed
  // key set is the torn run's, byte for byte.
  const clientSeed = resume
    ? resume.clientSeed
    : crypto.getRandomValues(new Uint8Array(32))
  const { keyAgent, keyAgreementKey } = await agentsFromSeed({
    seed: clientSeed
  })
  const { publicKeyMultibase: keyAgreementKeyMultibase } =
    keyAgreementKey as unknown as { publicKeyMultibase?: string }
  if (!keyAgreementKeyMultibase) {
    throw new Error('The minted key-agreement key has no public multibase.')
  }
  const signingKeyMultibase = clientSigningKeyMultibase({ keyAgent })
  const webvhUpdateKeys = resume
    ? resume.webvhUpdateKeys
    : await mintClientWebvhUpdateKeys()
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

  // The loud half: two log entries through the delegated bridge, each built
  // on a pinned read -- a served prefix of the log is refused before the
  // reveal-and-commit entry lands, rather than being rebased under the new
  // client's entries and only then caught by the verify below.
  const enrolled = await selfEnrollWebvhClient({
    store: logStore,
    ladderSeed,
    newClientKeys,
    newClientUpdateSeeds: webvhUpdateKeys,
    // The ceremony's seam hands over the head alone; the key set it publishes
    // was minted here, so the wrapper adds it -- everything the caller's
    // pending record needs that the caller does not already hold. On a resume
    // these are the resumed record's own seeds, so the re-persist is a
    // rewrite of what already stands.
    onCommitted: async ({ builtOnHead }) =>
      onCommitted({ builtOnHead, clientSeed, webvhUpdateKeys }),
    ...(resume ? { builtOnHead: resume.builtOnHead } : {}),
    expectedDid,
    ...(accountLogPinStore
      ? {
          pinStore: accountLogPinStore,
          logId: accountLogPinId({ spaceId: pointer.spaceId })
        }
      : {})
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
    latestEpochId: read.latestEpochId,
    // Propagated verbatim: whether THIS call published the pivot entry. The
    // pending record is cleared because the call returned, not because this
    // reads `true`.
    committed: enrolled.committed
  }
}
