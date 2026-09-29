/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The writer roster's entry: its version-1 shape, the shape check every
 * reader runs, the resource id an entry lives at, and the expiry policy both
 * wallets sweep under.
 *
 * An entry is advisory display data. Its writer asserts every field about
 * itself, and nothing checks them beyond shape. `signingKeyMultibase` links a
 * wallet writer to its enrolled client only when the verified did:webvh
 * document lists that key, and no field is an input to any authorization.
 */
import { sha256 } from '@noble/hashes/sha2.js'
import { edvIdFromBytes } from '@interop/was-client/edv/cipher'

/**
 * The version-1 roster entry. A type alias rather than an interface, so it
 * is assignable to was-client's `JsonObject`.
 */
export type RegisteredWriterEntry = {
  version: 1
  /**
   * The writer's `writerId`, verbatim. The resource id is a hash of it, so a
   * reader takes the id from here.
   */
  writerId: string
  /**
   * An enrolled wallet client's own signing-key multibase, the key the
   * client-labels record and `listAccountClients` rows are keyed by. Absent
   * for a non-wallet writer.
   */
  signingKeyMultibase?: string
  /**
   * A coarse platform self-description, or the user's rename of it.
   */
  label: string
  /**
   * ISO 8601 UTC timestamp of the writer's latest liveness touch.
   */
  lastSeen: string
  /**
   * `false` once a sweep found `lastSeen` past the inactivity TTL. The writer's
   * next touch sets it back to `true`.
   */
  active: boolean
}

/**
 * The expiry and liveness policy of the roster. Every replica that sweeps
 * must use the same values, or two sweepers disagree about which entries are
 * orphans.
 */
export interface RegisteredWriterPolicy {
  /**
   * How long an entry may go untouched before a sweep marks it inactive.
   */
  inactiveAfterMs: number
  /**
   * The entry count past which a sweep (or an enrollment) deletes the
   * oldest-`lastSeen` entries.
   */
  maxEntries: number
  /**
   * The least time between two liveness touches by the same writer.
   */
  touchIntervalMs: number
}

const DAY_MS = 24 * 60 * 60 * 1000

/**
 * The default policy: inactive after 90 days, at most 64 entries, touched at
 * most once a day. A wallet that overrides any of these passes the same
 * override on every replica.
 */
export const REGISTERED_WRITER_POLICY: RegisteredWriterPolicy = {
  inactiveAfterMs: 90 * DAY_MS,
  maxEntries: 64,
  touchIntervalMs: DAY_MS
}

/**
 * The domain label of the resource id hash.
 */
export const REGISTERED_WRITER_ID_LABEL = 'registered-writers/v1'

/**
 * The resource id of one writer's entry under one account: the first 16
 * bytes of `sha256(utf8('registered-writers/v1|' + accountDid + '|' +
 * writerId))`, formatted as an EDV document id.
 *
 * The id is deterministic, so a registration and a touch are idempotent
 * upserts. It hides the `writerId` from the storage host and does not link
 * one `writerId` across accounts.
 *
 * @param options {object}
 * @param options.accountDid {string}   the account whose Space holds the roster
 * @param options.writerId {string}
 * @returns {string}
 */
export function registeredWriterResourceId({
  accountDid,
  writerId
}: {
  accountDid: string
  writerId: string
}): string {
  const input = new TextEncoder().encode(
    `${REGISTERED_WRITER_ID_LABEL}|${accountDid}|${writerId}`
  )
  return edvIdFromBytes(sha256(input).subarray(0, 16))
}

/**
 * Resolves a partial policy override against the defaults.
 *
 * @param [policy] {Partial<RegisteredWriterPolicy>}
 * @returns {RegisteredWriterPolicy}
 */
export function registeredWriterPolicy(
  policy?: Partial<RegisteredWriterPolicy>
): RegisteredWriterPolicy {
  return { ...REGISTERED_WRITER_POLICY, ...policy }
}

/**
 * Reads a stored body as a roster entry, or `undefined` when it is not one.
 * A malformed entry is skipped by every reader, and never repaired.
 *
 * @param body {unknown}
 * @returns {RegisteredWriterEntry | undefined}
 */
export function parseRegisteredWriterEntry(
  body: unknown
): RegisteredWriterEntry | undefined {
  if (body === null || typeof body !== 'object') {
    return undefined
  }
  const { version, writerId, signingKeyMultibase, label, lastSeen, active } =
    body as Record<string, unknown>
  if (
    version !== 1 ||
    typeof writerId !== 'string' ||
    writerId === '' ||
    typeof label !== 'string' ||
    typeof lastSeen !== 'string' ||
    Number.isNaN(Date.parse(lastSeen)) ||
    typeof active !== 'boolean' ||
    (signingKeyMultibase !== undefined &&
      typeof signingKeyMultibase !== 'string')
  ) {
    return undefined
  }
  return {
    version: 1,
    writerId,
    ...(signingKeyMultibase !== undefined && { signingKeyMultibase }),
    label,
    lastSeen,
    active
  }
}
