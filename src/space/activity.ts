/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `wallet-activity` wire shape and the pure payload builders for it.
 *
 * {@link WalletActivity} is the decrypted body of one `wallet-activity`
 * document: an ActivityStreams-shaped record (a typed action carrying a
 * human-readable summary and a creation timestamp). Both wallet replicas read
 * and write this exact shape, so each reads the other's entries. Every field is
 * optional because a payload arrives from the storage server and is not
 * schema-validated on read.
 *
 * The builders are pure: each returns the activity payload object only -- no
 * storage, no port calls. `id` and `created` are injectable (a caller that wants
 * a specific resource id or timestamp passes them); otherwise `id` defaults to
 * `crypto.randomUUID()` and `created` to `new Date().toISOString()`. The
 * `type` strings and `summary` phrasings are byte-significant: two replicas that
 * build the same activity must produce the same `type` / `summary`, so these are
 * kept verbatim.
 */

/**
 * The decrypted body of one `wallet-activity` document. Reconciles the web
 * wallet's `WalletActivity` interface and the mobile wallet's
 * `WalletActivityPayload`, which are the same shape.
 */
export interface WalletActivity {
  id?: string
  type?: string[]
  summary?: string
  actor?: unknown
  object?: unknown
  created?: string
}

/**
 * The activity `type` strings the wallet uses, verbatim on the wire.
 */
export const ACTIVITY_TYPE = {
  Create: 'Create',
  Delete: 'Delete',
  Share: 'Share',
  Unshare: 'Unshare',
  Login: 'Login',
  Revoke: 'Revoke',
  ClientRevoke: 'ClientRevoke',
  CollectionShare: 'CollectionShare',
  CollectionUnshare: 'CollectionUnshare',
  GenerationCollect: 'GenerationCollect'
} as const

/**
 * A minimal actor descriptor; the wallet records the user's email.
 */
type Actor = { email?: string; id?: string }

/**
 * Fills in the id / created defaults shared by every builder.
 */
function stamp(id?: string, created?: string): { id: string; created: string } {
  return {
    id: id ?? crypto.randomUUID(),
    created: created ?? new Date().toISOString()
  }
}

/**
 * The Create activity for a freshly generated bootstrap `did:key` DID.
 *
 * @param options {object}
 * @param options.user {Actor}
 * @param [options.id] {string}
 * @param [options.created] {string}
 * @returns {WalletActivity}
 */
export function addHistoryNewAccount({
  user,
  id,
  created
}: {
  user: Actor
  id?: string
  created?: string
}): WalletActivity {
  const stamped = stamp(id, created)
  return {
    id: stamped.id,
    type: [ACTIVITY_TYPE.Create],
    summary: 'Account Sign Up. did:key DID generated.',
    actor: { email: user.email },
    object: user.id,
    created: stamped.created
  }
}

/**
 * The Create activity for the wallet's storage collections (and, when a remote
 * replica is configured, the remote Space). `object` -- the created Space /
 * Collection descriptors -- is supplied by the caller (it comes from the app's
 * storage layer); `remote` selects the summary phrasing.
 *
 * @param options {object}
 * @param options.actor {unknown}   recorded as the activity actor
 * @param options.object {unknown}   the created Space / Collection descriptors
 * @param [options.remote] {boolean}   whether a remote Space was created
 * @param [options.id] {string}
 * @param [options.created] {string}
 * @returns {WalletActivity}
 */
export function addHistorySpaceCreated({
  actor,
  object,
  remote,
  id,
  created
}: {
  actor: unknown
  object: unknown
  remote?: boolean
  id?: string
  created?: string
}): WalletActivity {
  const stamped = stamp(id, created)
  return {
    id: stamped.id,
    type: [ACTIVITY_TYPE.Create],
    summary: remote
      ? 'Account space created on remote storage server, collections initialized.'
      : 'Wallet collections initialized in local storage.',
    actor,
    object,
    created: stamped.created
  }
}

/**
 * The shared shape behind the four credential builders, which differ only in the
 * activity type and the summary verb. When the credential's display `title` is
 * known it goes into the summary line and `object` becomes `{ cid, title }`;
 * without one the legacy shape (`summary` naming the cid, `object` the bare cid
 * string) is kept, so readers handle both.
 */
function credentialActivity({
  cid,
  title,
  user,
  type,
  verb,
  id,
  created
}: {
  cid: string
  title?: string
  user: Actor
  type: string
  verb: string
  id?: string
  created?: string
}): WalletActivity {
  const stamped = stamp(id, created)
  return {
    id: stamped.id,
    type: [type],
    summary: `Credential ${verb}: ${title ?? cid}`,
    actor: { email: user.email },
    object: title === undefined ? cid : { cid, title },
    created: stamped.created
  }
}

/**
 * The Create activity for a credential.
 */
export function addHistoryCredentialCreated({
  cid,
  title,
  user,
  id,
  created
}: {
  cid: string
  title?: string
  user: Actor
  id?: string
  created?: string
}): WalletActivity {
  return credentialActivity({
    cid,
    title,
    user,
    type: ACTIVITY_TYPE.Create,
    verb: 'created',
    id,
    created
  })
}

/**
 * The Delete activity for a credential.
 */
export function addHistoryCredentialDeleted({
  cid,
  title,
  user,
  id,
  created
}: {
  cid: string
  title?: string
  user: Actor
  id?: string
  created?: string
}): WalletActivity {
  return credentialActivity({
    cid,
    title,
    user,
    type: ACTIVITY_TYPE.Delete,
    verb: 'deleted',
    id,
    created
  })
}

/**
 * The Share activity for a credential (a public link created).
 */
export function addHistoryCredentialShared({
  cid,
  title,
  user,
  id,
  created
}: {
  cid: string
  title?: string
  user: Actor
  id?: string
  created?: string
}): WalletActivity {
  return credentialActivity({
    cid,
    title,
    user,
    type: ACTIVITY_TYPE.Share,
    verb: 'shared',
    id,
    created
  })
}

/**
 * The Unshare activity for a credential (a public link revoked).
 */
export function addHistoryCredentialUnshared({
  cid,
  title,
  user,
  id,
  created
}: {
  cid: string
  title?: string
  user: Actor
  id?: string
  created?: string
}): WalletActivity {
  return credentialActivity({
    cid,
    title,
    user,
    type: ACTIVITY_TYPE.Unshare,
    verb: 'unshared',
    id,
    created
  })
}

/**
 * One capability grant recorded on a Login activity. `zcap` is kept verbatim.
 */
export interface ActivityGrant {
  id: string
  target: string
  allowedActions: string[]
  expires: string
  zcap?: unknown
}

/**
 * The Login activity: the user logged in to a relying party (or connected an
 * app) via "Login with Wallet", granting the listed capabilities. The recorded
 * zcap ids are the hook for a later revocation UI.
 *
 * @param options {object}
 * @param options.user {Actor}
 * @param options.origin {string}   the relying party's origin
 * @param options.grants {ActivityGrant[]}
 * @param [options.appConnect] {{ name: string; firstRun: boolean; appUrl?:
 *   string }}   set for an App Connect login: the app's display name, whether
 *   the app key was minted on this connect (first run) or matched (returning),
 *   and optionally the connected app's `appUrl` -- the validated App Connect
 *   request's parsed-URL serialization
 * @param [options.id] {string}
 * @param [options.created] {string}
 * @returns {WalletActivity}
 */
export function addHistoryLogin({
  user,
  origin,
  grants,
  appConnect,
  id,
  created
}: {
  user: Actor
  origin: string
  grants: ActivityGrant[]
  appConnect?: { name: string; firstRun: boolean; appUrl?: string }
  id?: string
  created?: string
}): WalletActivity {
  const stamped = stamp(id, created)
  const summary = appConnect
    ? `Connected ${appConnect.name} (${origin}) to wallet` +
      `${appConnect.firstRun ? ', minting a new app key' : ''}.`
    : `Logged in to ${origin} with wallet.`
  return {
    id: stamped.id,
    type: [ACTIVITY_TYPE.Login],
    summary,
    actor: { email: user.email },
    object: appConnect
      ? { origin, zcaps: grants, appConnect }
      : { origin, zcaps: grants },
    created: stamped.created
  }
}

/**
 * The Login activity for a local wallet unlock -- the user opened their own
 * wallet, no relying party involved ({@link addHistoryLogin} covers "Login
 * with Wallet" grants to an origin).
 *
 * @param options {object}
 * @param [options.user] {Actor}   omitted when the wallet has no account email
 * @param [options.id] {string}
 * @param [options.created] {string}
 * @returns {WalletActivity}
 */
export function addHistoryWalletLogin({
  user,
  id,
  created
}: {
  user?: Actor
  id?: string
  created?: string
} = {}): WalletActivity {
  const stamped = stamp(id, created)
  return {
    id: stamped.id,
    type: [ACTIVITY_TYPE.Login],
    summary: 'Logged in to wallet.',
    ...(user ? { actor: { email: user.email } } : {}),
    created: stamped.created
  }
}

/**
 * The Revoke activity: the user revoked a connected app's access, retiring its
 * app-key credential and its storage grants.
 *
 * @param options {object}
 * @param options.user {Actor}
 * @param options.origin {string}   the connected app's origin
 * @param options.name {string}   the connected app's display name
 * @param [options.cid] {string}   the retired app-key credential's cid
 * @param [options.revoked] {number}   how many storage grants were revoked
 * @param [options.skipped] {number}   how many grants needed no revocation
 * @param [options.id] {string}
 * @param [options.created] {string}
 * @returns {WalletActivity}
 */
/**
 * The ClientRevoke activity: the user disconnected an enrolled wallet client
 * -- its verification methods and update key left the did:webvh document, the
 * user key rotated, and the encrypted collections re-epoch'd (the revocation
 * cascade).
 *
 * @param options {object}
 * @param options.user {Actor}
 * @param options.signingKeyMultibase {string}   the revoked client's signing
 *   key multibase (its document identity)
 * @param [options.label] {string}   a display label for the revoked client,
 *   when one is known
 * @param [options.rotated] {number}   how many encrypted collections took a
 *   fresh epoch
 * @param [options.failed] {number}   how many collections failed to rotate
 *   (the completion sweep's remainder)
 * @param [options.id] {string}
 * @param [options.created] {string}
 * @returns {WalletActivity}
 */
export function addHistoryClientRevoked({
  user,
  signingKeyMultibase,
  label,
  rotated,
  failed,
  id,
  created
}: {
  user: Actor
  signingKeyMultibase: string
  label?: string
  rotated?: number
  failed?: number
  id?: string
  created?: string
}): WalletActivity {
  const stamped = stamp(id, created)
  const who = label ?? signingKeyMultibase
  return {
    id: stamped.id,
    type: [ACTIVITY_TYPE.ClientRevoke],
    summary: `Disconnected wallet client ${who}.`,
    actor: { email: user.email },
    object: { signingKeyMultibase, label, rotated, failed },
    created: stamped.created
  }
}

/**
 * The GenerationCollect activity: client-annex GC collected one generation --
 * the owner-side digest written BEFORE the generation collection is deleted,
 * and the only record of the collected window's visits that survives the
 * delete. One row per collected generation.
 *
 * The id is the generation id VERBATIM -- a deliberate exception to the
 * uuidv7 id convention (readers must not assume activity ids are UUIDs):
 * the deterministic payload id is what lets a torn re-run's second row
 * collapse at read time under the store's documented dedupe model.
 *
 * `firstEntry` / `lastEntry` quote the collected annex log's first and
 * last entries' `versionTime` strings verbatim (the digest outlives the log
 * it describes, so it does not launder its source), and `entryCount` is the
 * log's total entry count, genesis included -- an entry count, deliberately
 * not a visit count.
 *
 * @param options {object}
 * @param options.user {Actor}
 * @param options.generationId {string}   the collected generation's id (the
 *   `gen-` collection name); doubles as the activity id
 * @param [options.firstEntry] {string}   the log's first entry
 *   `versionTime`, verbatim
 * @param [options.lastEntry] {string}   the log's last entry `versionTime`,
 *   verbatim
 * @param [options.entryCount] {number}   total log entries, genesis included
 * @param [options.created] {string}
 * @returns {WalletActivity}
 */
export function addHistoryGenerationCollected({
  user,
  generationId,
  firstEntry,
  lastEntry,
  entryCount,
  created
}: {
  user: Actor
  generationId: string
  firstEntry?: string
  lastEntry?: string
  entryCount?: number
  created?: string
}): WalletActivity {
  return {
    id: generationId,
    type: [ACTIVITY_TYPE.GenerationCollect],
    summary: `Collected client-annex generation "${generationId}".`,
    actor: { email: user.email },
    object: { generationId, firstEntry, lastEntry, entryCount },
    created: created ?? new Date().toISOString()
  }
}

export function addHistoryAppRevoke({
  user,
  origin,
  name,
  cid,
  revoked,
  skipped,
  id,
  created
}: {
  user: Actor
  origin: string
  name: string
  cid?: string
  revoked?: number
  skipped?: number
  id?: string
  created?: string
}): WalletActivity {
  const stamped = stamp(id, created)
  const summary =
    typeof revoked === 'number'
      ? `Revoked ${name} (${origin}) app access: ${revoked} grant(s) ` +
        `revoked${skipped ? `, ${skipped} skipped` : ''}.`
      : `Revoked ${name} (${origin}) app access.`
  return {
    id: stamped.id,
    type: [ACTIVITY_TYPE.Revoke],
    summary,
    actor: { email: user.email },
    object: { origin, appConnect: { name }, cid, revoked, skipped },
    created: stamped.created
  }
}
