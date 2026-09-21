/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The standing unlock credential's management zcap verb set: the
 * `allowedAction` list an unlock identity delegates to the account over its
 * own sibling unlock Space at bind time, and re-mints at every login.
 */

/**
 * The management zcap's `allowedAction` set for a standing unlock credential:
 * `GET`, `PUT`, `DELETE`, `POST`.
 *
 * - `GET` reads the Space's keyring record (directly, or through the
 *   target-exact child a ladder-anchored session mints).
 * - `PUT` re-writes that record, which is what lets the revocation cascade
 *   re-seal it with a freshly minted bridge delegation.
 * - `DELETE` removes the Space when the credential retires, so a lost method
 *   stays revocable without re-deriving the unlock identity.
 * - `POST` reaches the Space's export and import endpoints and Create
 *   Resource on each Collection container. It adds no authority a holder of
 *   this set lacked: `PUT` already creates Resources by id, and Update Space
 *   Metadata is controller-only whatever the actions carry.
 *
 * Wire-level and permanent. Accounts bound before this set widened carry the
 * previous `GET`, `PUT`, `DELETE` until their next re-mint.
 */
export const UNLOCK_MANAGEMENT_ACTIONS = ['GET', 'PUT', 'DELETE', 'POST']
