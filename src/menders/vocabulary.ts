/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The closed vocabularies the mender registry is keyed on: the authority a
 * converger needs, the trigger sites that check an invariant today, the
 * account shapes a violation can stand on, the evidence a detector trusts,
 * the mend outcomes, and the two gap kinds. Each is an `as const` array with
 * its union, so extending one is a compile error rather than a drift. All
 * are code-only; nothing persists them.
 */

/**
 * The one authority context a converger needs. `enrolled` and `ladder` are
 * the two kinds the wallets' account-ceremony context resolves; `account`
 * means either kind converges the invariant; `none` means no account
 * authority at all (local cleanup, reads, writes the visit's own generation
 * delegation covers).
 */
export const AUTHORITIES = ['none', 'account', 'enrolled', 'ladder'] as const

/**
 * One value of {@link AUTHORITIES}.
 */
export type Authority = (typeof AUTHORITIES)[number]

/**
 * Where an invariant is checked today. The two chain triggers are the
 * login-time chains a remembered and a transient login seed; `login-routing`
 * entries are invoked by name at a routing call site before or during
 * session assembly and may refuse the login; `ceremony-tail` entries execute
 * inside a ceremony's own sequenced code and only report through the
 * registry.
 */
export const TRIGGERS = [
  'remembered-login-chain',
  'transient-login-chain',
  'login-routing',
  'ceremony-tail'
] as const

/**
 * One value of {@link TRIGGERS}.
 */
export type Trigger = (typeof TRIGGERS)[number]

/**
 * The two triggers a runner batches registrations for, and the only two the
 * held-authority filter applies to.
 */
export const CHAIN_TRIGGERS = [
  'remembered-login-chain',
  'transient-login-chain'
] as const

/**
 * One value of {@link CHAIN_TRIGGERS}.
 */
export type ChainTrigger = (typeof CHAIN_TRIGGERS)[number]

/**
 * The account shapes a violation can stand on un-mended: `client-less` (a
 * credential-anchored account with no enrolled client) and `enrolled` (an
 * account with at least one enrolled client).
 */
export const ACCOUNT_SHAPES = ['client-less', 'enrolled'] as const

/**
 * One value of {@link ACCOUNT_SHAPES}.
 */
export type AccountShape = (typeof ACCOUNT_SHAPES)[number]

/**
 * What a detector trusts when it decides an invariant is violated. A
 * `verified-log` read is checked under the visit's continuity pins; a
 * `verified-registry` read is a registry record whose proof verified under the
 * user key the reader holds, before it was decrypted; every `served-*` value
 * and `host-listing` is host state taken as served; the two `local-*` values
 * are this browser's own state and clock.
 */
export const EVIDENCE = [
  'verified-log',
  'verified-registry',
  'served-registry',
  'served-unlock-record',
  'host-listing',
  'served-body',
  'served-projection',
  'local-record',
  'local-clock'
] as const

/**
 * One value of {@link EVIDENCE}.
 */
export type Evidence = (typeof EVIDENCE)[number]

/**
 * The outcome of one mend attempt, shared with the mender event channel so
 * a report entry and an emitted event cannot diverge.
 */
export const MEND_OUTCOMES = [
  'clean',
  'noop',
  'partial',
  'refused',
  'failed'
] as const

/**
 * One value of {@link MEND_OUTCOMES}.
 */
export type MendOutcomeKind = (typeof MEND_OUTCOMES)[number]

/**
 * The two kinds of declared gap. `none`: no registration reports the
 * invariant on any trigger, whether because no converger is built or because
 * the code that converges it is not an addressable symbol. `unreachable`: a
 * registration reports it, but only on triggers a credential-only visit on
 * the affected account shape cannot fire.
 */
export const GAP_KINDS = ['none', 'unreachable'] as const

/**
 * One value of {@link GAP_KINDS}.
 */
export type GapKind = (typeof GAP_KINDS)[number]
