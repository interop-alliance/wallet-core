/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The typed ceremony vocabulary: one stable id per shared account ceremony.
 * The ids are code-only identifiers (nothing persists them yet); each names
 * one ceremony documented in the wallets' ceremony inventories.
 */

/**
 * The shared account ceremony ids, in ceremony-inventory order.
 */
export const CEREMONY_IDS = [
  'account-genesis',
  'credential-anchored-genesis',
  'self-enrollment',
  'client-enrollment',
  'client-revocation',
  'recovery-code-issuance',
  'recovery-code-spend',
  'recovery-code-revocation',
  'unlock-credential-rotation',
  'forget-client',
  'last-client-transition',
  'update-key-rotation'
] as const

/**
 * One id from {@link CEREMONY_IDS}.
 */
export type CeremonyId = (typeof CEREMONY_IDS)[number]
