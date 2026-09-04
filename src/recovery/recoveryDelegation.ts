/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The recovery code's authorization bridge: the pre-minted PUT-on-`did.jsonl`
 * delegation and the revocation cascade's re-mint of it. The delegation is a
 * wire artifact both apps must mint byte-identically (issuance and every
 * re-mint produce the record another replica later recovers with), so its
 * builder lives here: PUT on the one `did.jsonl` resource, one-year TTL,
 * delegated to the code-derived signing DID. Its narrow scope is what keeps
 * recovery loud -- a stolen code must extend the world-readable log before it
 * can read anything.
 *
 * Beside the builder lives the re-mint core (`remintRecoveryDelegations`):
 * revoking a client kills, by the current-key-set rule, every `did.jsonl`
 * delegation that client signed, which would brick recovery exactly when it
 * is needed -- and a delegation left standing eventually reaches its own
 * expiry. For each registry entry whose recorded delegation no longer
 * chains (its signing verification method left `capabilityDelegation` in the
 * document) or is expired or inside the renewal window, the acting client
 * signs a fresh delegation to the code's signing DID, re-wraps the
 * record to the code's unlock KAK (the public half the registry records --
 * the record carries no secrets, so re-encryption needs none), re-PUTs it
 * through the entry's management zcap, and updates the registry's
 * `delegationKeyId` and `delegationExpires`. A standing credential's
 * client-annex Space sibling delegation rides the same pass (its scalar pair is
 * `delegatedClientsKeyId` / `delegatedClientsExpires`): either member going
 * stale reseals both, and the one registry rewrite records both fresh pairs
 * -- a re-mint handling only the bridge is incomplete. The skip policy is
 * cross-replica correctness and is
 * decided here once: an entry that predates the re-mint fields, or whose
 * standing record cannot be read or carries no binding, is skipped and stays
 * flagged by the login-time health check. Every entry's fate is reported
 * (`RecordRemintOutcome`), so a record the pass could not reach is named
 * rather than silently left with a rotted bridge. What stays app-side is the
 * seams: the management-zcap client factory, the storage server URL, and the
 * registry read/record halves.
 *
 * The same pass serves the last-client forget ceremony, whose acting signer
 * is the ladder VM rather than an enrolled client: there the rot check runs
 * against the post-install document, in which the client about to be removed
 * still stands, so the ceremony names it as retiring
 * (`retiringKeyMultibases`) and every delegation it signed counts as rotted
 * ahead of the removal entry.
 */
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { resourcePath, toUrl } from '@interop/was-client/paths'
import { log } from '../log.js'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '../space/collections.js'
import type { PublishedKeyDocument } from '../webvh/listClients.js'
import {
  getUnlockKeyringWithCapability,
  putUnlockKeyringWithCapability
} from '../keyring/unlockSpace.js'
import type { AccountPointer, RecordSigner } from '../keyring/record.js'
import {
  remintUnlockRecordDelegations,
  unlockRecordSealedTo
} from '../unlock/unlockRecord.js'
import {
  delegationProofKeyId,
  recordedZcapStale,
  STANDING_ZCAP_TTL_MS
} from '../webvh/standingZcap.js'

/**
 * The recovery delegation's lifetime: the house standing-zcap value
 * ({@link STANDING_ZCAP_TTL_MS} -- one year, per NIST SP 800-57's
 * cryptoperiod guidance; see `webvh/standingZcap.ts`, the policy's one
 * home). The delegation's scope stays narrow (PUT on the one world-readable
 * DID log resource, whose worst-case abuse is a log write that still has to
 * verify against the published hash chain and prerotation commitments to
 * resolve). A code must keep working past the year, so expiry is watched
 * rather than terminal: the registry entry records the delegation's
 * `expires`, {@link zcapExpiring} treats the renewal window before it as
 * stale, the re-mint refreshes a stale delegation, and the login-time
 * recovery health check flags one the same way it flags rot (the signing
 * client's verification method leaving the document).
 */
export const RECOVERY_DELEGATION_TTL_MS = STANDING_ZCAP_TTL_MS

// Re-exported from their shared home (`webvh/standingZcap.ts`), so this
// module's public surface predating the move is unchanged.
export { ZCAP_RENEWAL_WINDOW_MS, zcapExpiring } from '../webvh/standingZcap.js'

/**
 * The absolute URL of the account's `did.jsonl` log resource -- the
 * invocation target of the pre-minted recovery delegation. Built with
 * was-client's path builders, the one owner of the WAS path grammar, so the
 * path is joined onto the pointer host's base path (a sub-path deployment
 * keeps its prefix) and the minted target matches the URL the server checks
 * it against byte for byte.
 *
 * @param options {object}
 * @param options.pointer {AccountPointer}
 * @returns {string}
 */
function didLogUrl({ pointer }: { pointer: AccountPointer }): string {
  return toUrl({
    serverUrl: pointer.host,
    path: resourcePath(pointer.spaceId, ID_COLLECTION.id, DID_LOG_RESOURCE)
  })
}

/**
 * Delegates the narrow log-write bridge to a code-derived client: PUT on the
 * one `did.jsonl` resource, {@link RECOVERY_DELEGATION_TTL_MS} lifetime. The
 * delegation is what lets a latent-authority code write its self-enrolling
 * continuation without any standing invocation presence.
 *
 * @param options {object}
 * @param options.zcapClient {ZcapClient}   the delegating client (an enrolled
 *   client's promoted signer)
 * @param options.pointer {AccountPointer}
 * @param options.recoveryClientDid {string}
 * @param [options.now] {number}   epoch milliseconds the lifetime is measured
 *   from, for tests
 * @returns {Promise<IZcap>}
 */
export async function delegateLogWrite({
  zcapClient,
  pointer,
  recoveryClientDid,
  now = Date.now()
}: {
  zcapClient: ZcapClient
  pointer: AccountPointer
  recoveryClientDid: string
  now?: number
}): Promise<IZcap> {
  return zcapClient.delegate({
    invocationTarget: didLogUrl({ pointer }),
    controller: recoveryClientDid,
    allowedActions: ['PUT'],
    expires: new Date(now + RECOVERY_DELEGATION_TTL_MS)
  })
}

// Re-exported from its shared home (`webvh/standingZcap.ts`), so this
// module's public surface is unchanged.
export { delegationProofKeyId }

/**
 * The registry fields a record's delegations stand for -- which key signed
 * the bridge and the `delegatedClients` sibling, and when each expires --
 * built once here for the re-mint and for the credential-anchored
 * establishment's standing fields. A member is present iff its source is:
 * an absent delegation, a proof with no key id, or a caveat-less zcap
 * contributes nothing.
 *
 * @param options {object}
 * @param [options.delegation] {IZcap}   the record's bridge delegation
 * @param [options.delegatedClients] {IZcap}   the record's sibling
 * @returns {{ delegationKeyId?: string, delegationExpires?: string,
 *   delegatedClientsKeyId?: string, delegatedClientsExpires?: string }}
 */
export function recordedDelegationFields({
  delegation,
  delegatedClients
}: {
  delegation?: IZcap
  delegatedClients?: IZcap
}): {
  delegationKeyId?: string
  delegationExpires?: string
  delegatedClientsKeyId?: string
  delegatedClientsExpires?: string
} {
  const delegationKeyId = delegation
    ? delegationProofKeyId(delegation)
    : undefined
  const delegationExpires = delegation ? zcapExpires(delegation) : undefined
  const delegatedClientsKeyId = delegatedClients
    ? delegationProofKeyId(delegatedClients)
    : undefined
  const delegatedClientsExpires = delegatedClients
    ? zcapExpires(delegatedClients)
    : undefined
  return {
    ...(delegationKeyId ? { delegationKeyId } : {}),
    ...(delegationExpires ? { delegationExpires } : {}),
    ...(delegatedClientsKeyId ? { delegatedClientsKeyId } : {}),
    ...(delegatedClientsExpires ? { delegatedClientsExpires } : {})
  }
}

/**
 * A delegation's `expires` caveat, when it carries one.
 *
 * @param zcap {IZcap}
 * @returns {string | undefined}
 */
function zcapExpires(zcap: IZcap): string | undefined {
  return (zcap as { expires?: string }).expires
}

/**
 * The members of a recovery-code registry entry the re-mint reads: where the
 * code's unlock Space and record are (`unlockSpaceId`, `manageCapability`),
 * which key signed the recorded delegation and when it expires
 * (`delegationKeyId` / `delegationExpires` -- either absent on an entry
 * predating its field, which the staleness checks conservatively flag), and
 * the re-mint fields: the code-derived signing DID the fresh delegation names
 * and the unlock KAK public half the record is re-wrapped to. A standing
 * credential's entry additionally tracks its annex Space sibling
 * delegation as a second scalar pair (`delegatedClientsKeyId` /
 * `delegatedClientsExpires` -- absent for recovery codes, mirroring the
 * record member's optionality); the sibling rots on exactly the bridge's
 * axis, so one pass reseals both. Structural on
 * purpose -- an app's richer registry entry satisfies it, and the re-mint
 * hands the SAME entry back (with the fresh key ids and expiries) through the
 * record seam, extra members untouched.
 */
export interface RecoveryDelegationEntry {
  label: string
  unlockSpaceId: string
  manageCapability?: IZcap
  delegationKeyId?: string
  delegationExpires?: string
  delegatedClientsKeyId?: string
  delegatedClientsExpires?: string
  recoveryClientDid?: string
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}

/**
 * One registry entry's fate in a re-mint pass: `current` (both members stand
 * and are outside the renewal window -- nothing written), `reminted` (the
 * record re-sealed and the entry handed back fresh; `siblingCarriedVerbatim`
 * flags a recorded sibling the pass could not rebuild because the document
 * points at no generation, which stays flagged for the health check),
 * `incomplete-entry` (an entry predating the re-mint fields, skipped until
 * the credential is re-bound), `pending-entry` (the entry's recorded
 * unlock-key members do not match the credential the record at its unlock
 * Space is sealed to -- a passphrase change torn before its retirement; the
 * next passphrase login's repair finishes it, and re-minting here would
 * re-arm the retired credential into the new one's record), or `failed` (the record could not be read,
 * re-sealed, or re-PUT -- `error` carries the cause). A skipped or failed
 * entry is named here so no caller can lose it silently.
 */
export interface RecordRemintOutcome {
  label: string
  unlockSpaceId: string
  outcome:
    'current' | 'reminted' | 'incomplete-entry' | 'pending-entry' | 'failed'
  siblingCarriedVerbatim?: boolean
  error?: unknown
}

/**
 * Re-mints the recovery delegations the current document no longer backs --
 * the recovery-code delta riding the revocation cascade (see the module doc
 * for the mechanism and the skip policy).
 *
 * The record's credential-authenticated core is preserved verbatim: the
 * re-mint reads the standing record through the entry's management zcap and
 * replaces only its delegation members
 * ({@link remintUnlockRecordDelegations}) -- the bridge always, and the
 * annex Space sibling where the entry records one (the two rot on one
 * axis, so both reseal in the same atomic pass and one registry-entry
 * rewrite records both fresh pairs). The
 * shell, the ladder member (where one rides), and the binding tag all travel
 * untouched, since the re-mint can decrypt none of them and does not need to.
 * A re-mint therefore can never change the pointer or controller the
 * credential was bound against -- and after a host migration the tag no
 * longer matches the moved pointer, so credentials must be rebound (codes
 * re-issued) when the account moves hosts.
 *
 * The re-mint holds the code's KAK public half but not its signing key, so
 * every record it re-PUTs is signed with the acting client's own account key
 * (`recordSigner`) -- the mixed-signer case a reader settles against the
 * verified did:webvh document.
 *
 * Best-effort per entry: a skipped entry stays flagged by the login-time
 * health check, whose regenerate nudge remains the backstop.
 *
 * @param options {object}
 * @param options.doc {PublishedKeyDocument}   the locally verified did:webvh
 *   document, AFTER the revocation edit
 * @param options.entries {RecoveryDelegationEntry[]}   the registry's
 *   recovery-code entries, as the app's registry read returned them
 * @param options.pointer {AccountPointer}
 * @param options.storageServerUrl {string}   the unlock Spaces' storage server
 * @param options.zcapClient {ZcapClient}   the acting client's promoted
 *   signer, which mints the fresh delegations
 * @param options.recordSigner {RecordSigner}   the acting client's account
 *   key, which signs the re-wrapped records
 * @param options.managementZcapClient {Function}   `({ capability }) =>
 *   ZcapClient` -- the client an entry's management zcap is invoked with
 * @param options.recordEntry {Function}   `({ entry }) => Promise<void>` --
 *   persists one updated registry entry (matching on the app's entry key)
 * @param [options.mintDelegatedClientsDelegation] {Function}   `({ controller })
 *   => Promise<IZcap | undefined>` -- the annex-side mint of a fresh
 *   `delegatedClients` sibling delegation, injected by the caller (the
 *   annex subpath's `delegatedClientsDelegationMinter` builds one over the
 *   verified document); `undefined` when the document points at no
 *   generation, in which case the old sealed member travels verbatim
 * @returns {Promise<{ reminted: number; skipped: number }>}
 */
export async function remintRecoveryDelegations<
  Entry extends RecoveryDelegationEntry
>({
  doc,
  entries,
  pointer,
  storageServerUrl,
  zcapClient,
  recordSigner,
  managementZcapClient,
  recordEntry,
  mintDelegatedClientsDelegation,
  retiringKeyMultibases = [],
  now = Date.now()
}: {
  doc: PublishedKeyDocument
  entries: Entry[]
  pointer: AccountPointer
  storageServerUrl: string
  zcapClient: ZcapClient
  recordSigner: RecordSigner
  managementZcapClient: (options: { capability: IZcap }) => ZcapClient
  recordEntry: (options: { entry: Entry }) => Promise<void>
  mintDelegatedClientsDelegation?: (options: {
    controller: string
  }) => Promise<IZcap | undefined>
  retiringKeyMultibases?: string[]
  now?: number
}): Promise<{
  reminted: number
  skipped: number
  outcomes: RecordRemintOutcome[]
}> {
  let reminted = 0
  let skipped = 0
  const outcomes: RecordRemintOutcome[] = []
  // The house staleness policy, decided once in `webvh` and asked here over
  // the scalars a registry entry records: expiry, the current-key-set rule
  // (a recorded signing key the document no longer lists under
  // `capabilityDelegation` -- or no recorded key at all -- has rotted), and
  // the caller's retiring set, which the document still lists only until the
  // entry that removes those keys lands.
  const recordedStale = (
    delegationKeyId: string | undefined,
    expires: string | undefined
  ): boolean =>
    recordedZcapStale({
      doc,
      ...(delegationKeyId ? { delegationKeyId } : {}),
      ...(expires ? { expires } : {}),
      retiringKeyMultibases,
      now
    })
  for (const entry of entries) {
    const stale = recordedStale(entry.delegationKeyId, entry.delegationExpires)
    // The annex Space sibling, where the entry records one, is checked on the
    // same axes; either member going stale re-mints BOTH in one atomic pass
    // (both resealed, one registry-entry rewrite).
    const siblingRecorded =
      entry.delegatedClientsKeyId !== undefined ||
      entry.delegatedClientsExpires !== undefined
    const siblingStale =
      siblingRecorded &&
      recordedStale(entry.delegatedClientsKeyId, entry.delegatedClientsExpires)
    if (!stale && !siblingStale) {
      outcomes.push({
        label: entry.label,
        unlockSpaceId: entry.unlockSpaceId,
        outcome: 'current'
      })
      continue
    }
    if (
      !entry.recoveryClientDid ||
      !entry.unlockKeyAgreementKeyId ||
      !entry.unlockKeyAgreementKeyMultibase ||
      !entry.manageCapability
    ) {
      // An entry issued before the re-mint fields existed: the health check
      // keeps flagging it until the code is regenerated.
      skipped += 1
      outcomes.push({
        label: entry.label,
        unlockSpaceId: entry.unlockSpaceId,
        outcome: 'incomplete-entry'
      })
      continue
    }
    try {
      // The standing record, whose credential-authenticated core travels
      // verbatim (a record with no binding predates the standing layout and
      // cannot be re-minted -- `remintUnlockRecordDelegations` refuses, and the
      // entry is skipped into the health check's regenerate nudge).
      const standing = await getUnlockKeyringWithCapability({
        storageServerUrl,
        zcapClient: managementZcapClient({
          capability: entry.manageCapability
        }),
        spaceId: entry.unlockSpaceId,
        capability: entry.manageCapability
      })
      // The pending-shaped guard: the entry's `unlockSpaceId` and
      // `manageCapability` name one credential while its identity members
      // name another -- the state a passphrase change torn before its
      // retirement leaves. Re-minting here would seal a fresh
      // current-client-signed bridge for the OLD credential into the NEW
      // credential's record, re-arming the half-retired credential and
      // bricking the new one's entry paths. Nothing is written; the next
      // passphrase login's repair is the mender.
      if (
        !unlockRecordSealedTo({
          record: standing,
          keyAgreementKeyMultibase: entry.unlockKeyAgreementKeyMultibase
        })
      ) {
        log.warn(
          'The unlock record at the Space recorded for this entry is ' +
            'sealed to another credential (a passphrase change torn before ' +
            'its retirement landed); its delegations are not re-minted',
          { label: entry.label }
        )
        skipped += 1
        outcomes.push({
          label: entry.label,
          unlockSpaceId: entry.unlockSpaceId,
          outcome: 'pending-entry'
        })
        continue
      }
      const delegation = await delegateLogWrite({
        zcapClient,
        pointer,
        recoveryClientDid: entry.recoveryClientDid
      })
      // The fresh annex Space sibling, for an entry that records one --
      // minted through the injected annex-side closure, so this orchestrator
      // never imports the annex module. A document not (yet) pointing at a
      // generation (or a caller wiring no minter) leaves nothing to rebuild
      // the target from, so the old sealed member travels verbatim and the
      // pair stays stale-flagged for the login-time health check.
      let delegatedClients: IZcap | undefined
      let siblingCarriedVerbatim = false
      if (siblingRecorded) {
        delegatedClients = await mintDelegatedClientsDelegation?.({
          controller: entry.recoveryClientDid
        })
        if (!delegatedClients) {
          siblingCarriedVerbatim = true
          log.warn(
            'The account document names no client-annex generation; the ' +
              'delegatedClients delegation for this entry is carried verbatim',
            { label: entry.label }
          )
        }
      }
      // The credential's unlock KAK, public half only -- exactly enough to
      // seal the fresh bridge to the same recipient the credential derives
      // (sealing goes through the encrypt-only cipher, so no secret is
      // needed).
      const unlockKak = (await X25519KeyAgreementKey2020.from({
        id: entry.unlockKeyAgreementKeyId,
        controller: entry.unlockKeyAgreementKeyId.split('#')[0],
        type: 'X25519KeyAgreementKey2020',
        publicKeyMultibase: entry.unlockKeyAgreementKeyMultibase
      })) as IKeyAgreementKey
      const wrapped = await remintUnlockRecordDelegations({
        record: standing,
        delegation,
        ...(delegatedClients ? { delegatedClients } : {}),
        keyAgreementKey: unlockKak,
        signer: recordSigner
      })
      await putUnlockKeyringWithCapability({
        storageServerUrl,
        zcapClient: managementZcapClient({
          capability: entry.manageCapability
        }),
        spaceId: entry.unlockSpaceId,
        record: wrapped,
        capability: entry.manageCapability
      })
      await recordEntry({
        entry: {
          ...entry,
          ...recordedDelegationFields({
            delegation,
            ...(delegatedClients ? { delegatedClients } : {})
          })
        }
      })
      reminted += 1
      outcomes.push({
        label: entry.label,
        unlockSpaceId: entry.unlockSpaceId,
        outcome: 'reminted',
        ...(siblingCarriedVerbatim ? { siblingCarriedVerbatim } : {})
      })
    } catch (err) {
      log.warn('Could not re-mint the recovery delegation', {
        label: entry.label,
        err
      })
      skipped += 1
      outcomes.push({
        label: entry.label,
        unlockSpaceId: entry.unlockSpaceId,
        outcome: 'failed',
        error: err
      })
    }
  }
  return { reminted, skipped, outcomes }
}
