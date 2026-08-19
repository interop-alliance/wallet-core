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
 * chains (its signing verification method left the document) or is expired
 * or inside the renewal window, the acting
 * client signs a fresh delegation to the code's signing DID, re-wraps the
 * record to the code's unlock KAK (the public half the registry records --
 * the record carries no secrets, so re-encryption needs none), re-PUTs it
 * through the entry's management zcap, and updates the registry's
 * `delegationKeyId` and `delegationExpires`. The skip policy is
 * cross-replica correctness and is
 * decided here once: an entry that predates the re-mint fields, or whose
 * standing record cannot be read or carries no binding, is skipped and stays
 * flagged by the login-time health check. What stays app-side is the seams:
 * the management-zcap client factory, the storage server URL, and the
 * registry read/record halves.
 */
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey, IZcap } from '@interop/data-integrity-core'
import type { ZcapClient } from '@interop/ezcap'
import { resourcePath, toUrl } from '@interop/was-client/paths'
import { DID_LOG_RESOURCE, ID_COLLECTION } from '../space/collections.js'
import { delegationKeyInDocument } from '../webvh/listClients.js'
import type { PublishedKeyDocument } from '../webvh/listClients.js'
import {
  getUnlockKeyringWithCapability,
  putUnlockKeyringWithCapability
} from '../keyring/unlockSpace.js'
import type { AccountPointer, RecordSigner } from '../keyring/record.js'
import { remintUnlockRecordBridge } from '../unlock/unlockRecord.js'

/**
 * The recovery delegation's lifetime: one year, following NIST SP 800-57's
 * one-to-two-year cryptoperiod guidance for private signature keys. The
 * delegation's scope stays narrow (PUT on the one world-readable DID log
 * resource, whose worst-case abuse is a log write that still has to verify
 * against the published hash chain and prerotation commitments to resolve),
 * but a standing bearer artifact should not outlive its signing key's
 * recommended cryptoperiod. A code must keep working past the year, so
 * expiry is watched rather than terminal: the registry entry records the
 * delegation's `expires`, {@link zcapExpiring} treats the
 * renewal window before it as stale, the re-mint refreshes a stale
 * delegation, and the login-time recovery health check flags one the same
 * way it flags rot (the signing client's verification method leaving the
 * document).
 */
export const RECOVERY_DELEGATION_TTL_MS = 365 * 24 * 60 * 60 * 1000

/**
 * How long before its `expires` a standing recorded zcap counts as stale:
 * thirty days, so a refresh (a re-mint, a login-time re-delegation) or a
 * regenerate nudge lands well before the zcap actually lapses.
 */
export const ZCAP_RENEWAL_WINDOW_MS = 30 * 24 * 60 * 60 * 1000

/**
 * Whether a recorded zcap expiry is past or inside the renewal window -- the
 * expiry half of the staleness predicate for every long-lived zcap a wallet
 * records beside its registry entries (the recovery `did.jsonl` delegation,
 * an unlock Space's management zcap). The re-mint and the wallets'
 * login-time checks all ask this one predicate. A record carrying no expiry
 * (or an unparseable one) is uncheckable and therefore not assumed healthy,
 * matching the rot check's treatment of a missing `delegationKeyId`.
 *
 * @param options {object}
 * @param [options.expires] {string}   the recorded ISO 8601 expiry
 * @param [options.now] {number}   epoch milliseconds, for tests
 * @returns {boolean}
 */
export function zcapExpiring({
  expires,
  now = Date.now()
}: {
  expires?: string
  now?: number
}): boolean {
  if (!expires) {
    return true
  }
  const expiresAt = Date.parse(expires)
  if (Number.isNaN(expiresAt)) {
    return true
  }
  return expiresAt - now <= ZCAP_RENEWAL_WINDOW_MS
}

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
 * @returns {Promise<IZcap>}
 */
export async function delegateLogWrite({
  zcapClient,
  pointer,
  recoveryClientDid
}: {
  zcapClient: ZcapClient
  pointer: AccountPointer
  recoveryClientDid: string
}): Promise<IZcap> {
  return zcapClient.delegate({
    invocationTarget: didLogUrl({ pointer }),
    controller: recoveryClientDid,
    allowedActions: ['PUT'],
    expires: new Date(Date.now() + RECOVERY_DELEGATION_TTL_MS)
  })
}

/**
 * The verification method that signed a delegation's proof -- recorded in the
 * registry entry so the health check and the re-mint's rot check can test it
 * against the current document without holding the code.
 *
 * @param delegation {IZcap}
 * @returns {string | undefined}
 */
export function delegationProofKeyId(delegation: IZcap): string | undefined {
  const { proof } = delegation as unknown as {
    proof?:
      | { verificationMethod?: string }
      | Array<{
          verificationMethod?: string
        }>
  }
  const single = Array.isArray(proof) ? proof[0] : proof
  return single?.verificationMethod
}

/**
 * The members of a recovery-code registry entry the re-mint reads: where the
 * code's unlock Space and record are (`unlockSpaceId`, `manageCapability`),
 * which key signed the recorded delegation and when it expires
 * (`delegationKeyId` / `delegationExpires` -- either absent on an entry
 * predating its field, which the staleness checks conservatively flag), and
 * the re-mint fields: the code-derived signing DID the fresh delegation names
 * and the unlock KAK public half the record is re-wrapped to. Structural on
 * purpose -- an app's richer registry entry satisfies it, and the re-mint
 * hands the SAME entry back (with the fresh `delegationKeyId`) through the
 * record seam, extra members untouched.
 */
export interface RecoveryDelegationEntry {
  label: string
  unlockSpaceId: string
  manageCapability?: IZcap
  delegationKeyId?: string
  delegationExpires?: string
  recoveryClientDid?: string
  unlockKeyAgreementKeyId?: string
  unlockKeyAgreementKeyMultibase?: string
}

/**
 * Re-mints the recovery delegations the current document no longer backs --
 * the recovery-code delta riding the revocation cascade (see the module doc
 * for the mechanism and the skip policy).
 *
 * The record's credential-authenticated core is preserved verbatim: the
 * re-mint reads the standing record through the entry's management zcap and
 * replaces only its bridge member ({@link remintUnlockRecordBridge}) -- the
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
  recordEntry
}: {
  doc: PublishedKeyDocument
  entries: Entry[]
  pointer: AccountPointer
  storageServerUrl: string
  zcapClient: ZcapClient
  recordSigner: RecordSigner
  managementZcapClient: (options: { capability: IZcap }) => ZcapClient
  recordEntry: (options: { entry: Entry }) => Promise<void>
}): Promise<{ reminted: number; skipped: number }> {
  let reminted = 0
  let skipped = 0
  for (const entry of entries) {
    // The current-key-set rule, decided once in `webvh`: an entry whose
    // recorded signing key the document no longer publishes -- or that
    // records no signing key at all -- is rotted. Expiry is the other
    // staleness axis: a delegation expired or inside the renewal window
    // (or recording no expiry at all) is re-minted even though its key
    // still stands.
    const stands = delegationKeyInDocument({
      doc,
      ...(entry.delegationKeyId
        ? { delegationKeyId: entry.delegationKeyId }
        : {})
    })
    const expiring = zcapExpiring({
      ...(entry.delegationExpires ? { expires: entry.delegationExpires } : {})
    })
    if (stands && !expiring) {
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
      continue
    }
    try {
      // The standing record, whose credential-authenticated core travels
      // verbatim (a record with no binding predates the standing layout and
      // cannot be re-minted -- `remintUnlockRecordBridge` refuses, and the
      // entry is skipped into the health check's regenerate nudge).
      const standing = await getUnlockKeyringWithCapability({
        storageServerUrl,
        zcapClient: managementZcapClient({
          capability: entry.manageCapability
        }),
        spaceId: entry.unlockSpaceId,
        capability: entry.manageCapability
      })
      const delegation = await delegateLogWrite({
        zcapClient,
        pointer,
        recoveryClientDid: entry.recoveryClientDid
      })
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
      const wrapped = await remintUnlockRecordBridge({
        record: standing,
        delegation,
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
      const delegationKeyId = delegationProofKeyId(delegation)
      const delegationExpires = (delegation as { expires?: string }).expires
      await recordEntry({
        entry: {
          ...entry,
          ...(delegationKeyId ? { delegationKeyId } : {}),
          ...(delegationExpires ? { delegationExpires } : {})
        }
      })
      reminted += 1
    } catch (err) {
      console.warn(
        `Could not re-mint the recovery delegation for "${entry.label}":`,
        err
      )
      skipped += 1
    }
  }
  return { reminted, skipped }
}
