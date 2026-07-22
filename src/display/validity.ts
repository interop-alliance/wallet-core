/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Validity-period readers for both VC Data Model 1.0 (`issuanceDate` /
 * `expirationDate`) and 2.0 (`validFrom` / `validUntil`). The library returns
 * the raw ISO strings and a `Date` -- never a formatted string -- so each app
 * applies its own locale formatting on top (the raw-values seam).
 *
 * Drift resolution: this is the union of DCW's `credentialValidityPeriod.ts`
 * (which had `getIssuanceDate` / `getExpirationDate` / `isExpired` returning
 * `undefined` when absent) and Freewallet's `formatDate.ts` (which had
 * `getExpirationInstant` returning `Date | null`, plus an empty-string variant
 * of `getExpirationDate`). DCW's `undefined` convention wins for the string
 * getters; Freewallet's `''`-returning wrapper is trivially reproduced app-side
 * as `getExpirationDate(vc) ?? ''`.
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'

/**
 * The issuance instant as a raw ISO string: VC 2.0 `validFrom` preferred, else
 * VC 1.0 `issuanceDate`, else `undefined`.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string | undefined}
 */
export function getIssuanceDate(
  credential: IVerifiableCredential
): string | undefined {
  return credential.validFrom ?? credential.issuanceDate
}

/**
 * The expiration instant as a raw ISO string: VC 2.0 `validUntil` preferred,
 * else VC 1.0 `expirationDate`, else `undefined`.
 *
 * @param credential {IVerifiableCredential}
 * @returns {string | undefined}
 */
export function getExpirationDate(
  credential: IVerifiableCredential
): string | undefined {
  return credential.validUntil ?? credential.expirationDate
}

/**
 * The expiration instant as a `Date`, or `null` when there is no expiration or
 * it does not parse.
 *
 * @param credential {IVerifiableCredential}
 * @returns {Date | null}
 */
export function getExpirationInstant(
  credential: IVerifiableCredential
): Date | null {
  const iso = getExpirationDate(credential)
  if (!iso) {
    return null
  }
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? null : d
}

/**
 * Whether the credential has an expiration date that is already in the past.
 * A credential with no expiration is never expired.
 *
 * @param credential {IVerifiableCredential}
 * @returns {boolean}
 */
export function isExpired(credential: IVerifiableCredential): boolean {
  const expiration = getExpirationDate(credential)
  if (!expiration) {
    return false
  }
  const t = Date.parse(String(expiration))
  return !Number.isNaN(t) && t < Date.now()
}
