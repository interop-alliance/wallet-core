/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The stage vocabulary of the credential-anchored ceremonies: the ordered
 * tuples their `onStage` notifiers report from, the aliases, and the union
 * types derived from them. The ceremonies emit from these types, so a
 * mistyped stage name fails the type check, and a consumer's progress
 * display derives its step list from the tuples instead of re-declaring the
 * names as bare strings.
 *
 * The vocabulary sits in a leaf module of its own rather than beside the
 * code that emits it, because a progress display needs the names and none of
 * the ceremony: an app store importing them from `establish.js` would pull
 * that whole module graph into its bundle.
 */

import { KMS_AUTHENTICATION_STAGE } from '../stages.js'

export { KMS_AUTHENTICATION_STAGE }

/**
 * The controller-promotion stage, emitted by the genesis ceremony when it
 * promotes and by the establishment when the promotion is deferred to it.
 * Declared once so the two emitters cannot drift apart.
 */
export const CONTROLLER_PROMOTION_STAGE = 'controller-promotion'

/**
 * The stages `ensureCredentialAnchoredAccountGenesis` reports, in the order
 * they fire, up to but not including the controller promotion (which a
 * caller may defer -- see {@link CONTROLLER_PROMOTION_STAGE}).
 */
export const CREDENTIAL_ANCHORED_GENESIS_STAGES = [
  'space-provisioning',
  KMS_AUTHENTICATION_STAGE,
  'webvh-genesis',
  'roster-genesis',
  'collection-epochs'
] as const

/**
 * A stage name the credential-anchored genesis may emit.
 */
export type CredentialAnchoredGenesisStage =
  | (typeof CREDENTIAL_ANCHORED_GENESIS_STAGES)[number]
  | typeof CONTROLLER_PROMOTION_STAGE

/**
 * The establishment's stage names in the order they fire: its own marks with
 * the genesis ceremony's spliced in where that ceremony runs (stage 2).
 *
 * Two kinds of name are absent by construction. The stages whose body is a
 * caller's own closure (`beforePromotion`, `promoteKeystore`) are the
 * caller's to name and mark, since only the caller knows what its closure
 * does; and an alias below fires in place of a listed name rather than
 * beside it.
 */
export const CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES = [
  'interim-bind',
  ...CREDENTIAL_ANCHORED_GENESIS_STAGES,
  'account-log-read',
  'annex-generation',
  'record-rebind',
  CONTROLLER_PROMOTION_STAGE
] as const

/**
 * A stage the establishment reports as a step of its own.
 */
export type CredentialAnchoredEstablishmentStage =
  (typeof CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGES)[number]

/**
 * Stage names that fire in place of a listed stage rather than beside it,
 * and the stage each stands in for. The heal branch delivers the collection
 * epochs off an adopted roster instead of minting them, so its mark closes
 * the boundary `collection-epochs` closes on a fresh run.
 */
export const CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGE_ALIASES = {
  'roster-delivered-epochs': 'collection-epochs'
} as const satisfies Record<string, CredentialAnchoredEstablishmentStage>

/**
 * Every name the establishment may emit: the stages above plus the aliases.
 */
export type CredentialAnchoredEstablishmentStageName =
  | CredentialAnchoredEstablishmentStage
  | keyof typeof CREDENTIAL_ANCHORED_ESTABLISHMENT_STAGE_ALIASES
