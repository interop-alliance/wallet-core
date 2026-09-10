/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The invariant ids: the closed census both wallets declare against and the
 * mender event channel keys on. Each names the predicate an entry makes
 * true rather than the code that converges it, so moving a converger between
 * modules renames nothing. The ids are code-only; nothing persists them.
 * Numbered in the order the design table assigned them, and a new one takes
 * the next free number rather than renumbering.
 */

/**
 * Every invariant id, in design-table order.
 */
export const INVARIANT_IDS = [
  // 1
  'roster-wraps-exactly-the-document-key-set',
  // 2
  'governed-log-heads-anchor-past-the-membership-change',
  // 3
  'collection-epochs-name-the-current-user-key',
  // 4
  'unlock-registry-opens-under-the-current-user-key',
  // 5
  'registry-passphrase-entry-names-the-standing-credential',
  // 6
  'passkey-entry-carries-its-standing-configuration',
  // 7
  'registry-lists-the-passphrase-method',
  // 8
  'standing-delegations-verify-under-the-current-document',
  // 9
  'registry-records-the-committed-ladder-rung',
  // 10
  'unlock-record-points-at-the-account-did',
  // 11
  'account-pointer-names-the-account-did',
  // 12
  'space-controller-is-the-account-did',
  // 13
  'roster-and-collection-epochs-exist',
  // 14
  'registry-records-the-establishing-credential',
  // 15
  'annex-generation-is-reachable',
  // 16
  'generation-delegation-is-current',
  // 17
  'acting-credential-manage-zcap-is-current',
  // 18
  'did-web-projection-matches-the-log',
  // 19
  'no-annex-generation-outlives-its-pointer',
  // 20
  'app-keys-live-only-in-app-connections',
  // 21
  'client-key-record-matches-the-pointed-account',
  // 22
  'this-browser-is-still-an-enrolled-client',
  // 23
  'no-client-key-record-stays-pending',
  // 24
  'recovery-spend-is-completed',
  // 25
  'retired-credential-leaves-no-annex-inventory',
  // 26
  'document-lists-the-acting-credential',
  // 27
  'keystore-controller-is-the-account-did',
  // 28
  'account-document-publishes-an-authentication-key',
  // 29
  'every-document-key-agreement-entry-has-a-locatable-credential',
  // 30
  'no-unlock-space-outlives-its-credential',
  // 31
  'no-keystore-outlives-its-account',
  // 32
  'saved-recovery-codes-locate-their-account',
  // 33
  'standard-collections-are-provisioned',
  // 34
  'no-auxiliary-space-stands-unnamed'
] as const

/**
 * One id from {@link INVARIANT_IDS}.
 */
export type InvariantId = (typeof INVARIANT_IDS)[number]
