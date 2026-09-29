/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The typed ceremony vocabulary: one stable id per account ceremony either
 * wallet runs. Most have a shared half in this package; some are still
 * implemented app-side. The ids are code-only identifiers (nothing persists
 * them yet); each names one ceremony documented in the wallets' ceremony
 * inventories.
 */

/**
 * The account ceremony ids, in ceremony-inventory order. The last four
 * (account deletion, the shared wipe executor, content migration, and backup
 * export) are implemented in the app for now.
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
  'update-key-rotation',
  'account-deletion',
  'wallet-wipe',
  'content-migration',
  'backup-export'
] as const

/**
 * One id from {@link CEREMONY_IDS}.
 */
export type CeremonyId = (typeof CEREMONY_IDS)[number]
