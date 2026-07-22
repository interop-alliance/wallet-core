/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Validity-period readers (VC 1.0 + 2.0). Ported from DCW
 * `credentialValidityPeriod.test.ts` and the VC-model split of Freewallet
 * `formatDate.test.ts` (the `Intl` formatting cases stay a Freewallet test).
 * The empty result is `undefined` (DCW's convention), not `''`.
 */
import { describe, it, expect } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import {
  getIssuanceDate,
  getExpirationDate,
  getExpirationInstant,
  isExpired
} from '../../src/display/index.js'

describe('getIssuanceDate', () => {
  it('returns the VC 1.0 issuanceDate when available', () => {
    expect(
      getIssuanceDate({
        issuanceDate: '2023-01-01T00:00:00Z'
      } as IVerifiableCredential)
    ).toBe('2023-01-01T00:00:00Z')
  })

  it('returns the VC 2.0 validFrom when available', () => {
    expect(
      getIssuanceDate({
        validFrom: '2023-02-01T00:00:00Z'
      } as IVerifiableCredential)
    ).toBe('2023-02-01T00:00:00Z')
  })

  it('prefers VC 2.0 validFrom over VC 1.0 issuanceDate', () => {
    expect(
      getIssuanceDate({
        issuanceDate: '2023-01-01T00:00:00Z',
        validFrom: '2023-02-01T00:00:00Z'
      } as IVerifiableCredential)
    ).toBe('2023-02-01T00:00:00Z')
  })

  it('returns undefined when no date is available', () => {
    expect(getIssuanceDate({} as IVerifiableCredential)).toBeUndefined()
  })
})

describe('getExpirationDate', () => {
  it('returns the VC 1.0 expirationDate when available', () => {
    expect(
      getExpirationDate({
        expirationDate: '2024-01-01T00:00:00Z'
      } as IVerifiableCredential)
    ).toBe('2024-01-01T00:00:00Z')
  })

  it('prefers VC 2.0 validUntil over VC 1.0 expirationDate', () => {
    expect(
      getExpirationDate({
        expirationDate: '2024-01-01T00:00:00Z',
        validUntil: '2024-02-01T00:00:00Z'
      } as IVerifiableCredential)
    ).toBe('2024-02-01T00:00:00Z')
  })

  it('returns undefined when no date is available', () => {
    expect(getExpirationDate({} as IVerifiableCredential)).toBeUndefined()
  })
})

describe('getExpirationInstant', () => {
  it('returns a Date for a valid expiration', () => {
    expect(
      getExpirationInstant({
        validUntil: '2030-01-01T00:00:00Z'
      } as IVerifiableCredential)?.toISOString()
    ).toBe('2030-01-01T00:00:00.000Z')
  })

  it('returns null when there is no expiration date', () => {
    expect(getExpirationInstant({} as IVerifiableCredential)).toBeNull()
  })

  it('returns null for an unparseable expiration date', () => {
    expect(
      getExpirationInstant({
        validUntil: 'not-a-date'
      } as IVerifiableCredential)
    ).toBeNull()
  })
})

describe('isExpired', () => {
  it('is false when there is no expiration', () => {
    expect(isExpired({} as IVerifiableCredential)).toBe(false)
  })

  it('is true for a past expiration', () => {
    expect(
      isExpired({ validUntil: '2000-01-01T00:00:00Z' } as IVerifiableCredential)
    ).toBe(true)
  })

  it('is false for a future expiration', () => {
    expect(
      isExpired({ validUntil: '2999-01-01T00:00:00Z' } as IVerifiableCredential)
    ).toBe(false)
  })
})
