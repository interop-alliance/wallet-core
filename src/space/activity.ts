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

/** The activity `type` strings the wallet uses, verbatim on the wire. */
export const ACTIVITY_TYPE = {
  Create: 'Create',
  Delete: 'Delete',
  Share: 'Share',
  Unshare: 'Unshare',
  Login: 'Login',
  Revoke: 'Revoke',
  CollectionShare: 'CollectionShare',
  CollectionUnshare: 'CollectionUnshare'
} as const

/** A minimal actor descriptor; the wallet records the user's email. */
type Actor = { email?: string; id?: string }

/** Fills in the id / created defaults shared by every builder. */
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
 * activity type and the summary verb.
 */
function credentialActivity({
  cid,
  user,
  type,
  verb,
  id,
  created
}: {
  cid: string
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
    summary: `Credential ${verb}: ${cid}`,
    actor: { email: user.email },
    object: cid,
    created: stamped.created
  }
}

/** The Create activity for a credential. */
export function addHistoryCredentialCreated({
  cid,
  user,
  id,
  created
}: {
  cid: string
  user: Actor
  id?: string
  created?: string
}): WalletActivity {
  return credentialActivity({
    cid,
    user,
    type: ACTIVITY_TYPE.Create,
    verb: 'created',
    id,
    created
  })
}

/** The Delete activity for a credential. */
export function addHistoryCredentialDeleted({
  cid,
  user,
  id,
  created
}: {
  cid: string
  user: Actor
  id?: string
  created?: string
}): WalletActivity {
  return credentialActivity({
    cid,
    user,
    type: ACTIVITY_TYPE.Delete,
    verb: 'deleted',
    id,
    created
  })
}

/** The Share activity for a credential (a public link created). */
export function addHistoryCredentialShared({
  cid,
  user,
  id,
  created
}: {
  cid: string
  user: Actor
  id?: string
  created?: string
}): WalletActivity {
  return credentialActivity({
    cid,
    user,
    type: ACTIVITY_TYPE.Share,
    verb: 'shared',
    id,
    created
  })
}

/** The Unshare activity for a credential (a public link revoked). */
export function addHistoryCredentialUnshared({
  cid,
  user,
  id,
  created
}: {
  cid: string
  user: Actor
  id?: string
  created?: string
}): WalletActivity {
  return credentialActivity({
    cid,
    user,
    type: ACTIVITY_TYPE.Unshare,
    verb: 'unshared',
    id,
    created
  })
}

/** One capability grant recorded on a Login activity. `zcap` is kept verbatim. */
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
 * @param [options.appConnect] {{ name: string; firstRun: boolean }}   set for an
 *   App Connect login: the app's display name and whether the app key was minted
 *   on this connect (first run) or matched (returning)
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
  appConnect?: { name: string; firstRun: boolean }
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
