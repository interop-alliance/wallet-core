/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Verification-to-UI derivation. Ported from Freewallet `mapVerificationToUi.test.ts`
 * (`verifyResultToChecklist` is now `buildVerificationChecklist`, taking an
 * injected fixed `labels` object instead of a `TFunction`) and DCW
 * `credentialSecurity.test.ts` (retargeted from `shouldDisableUrls` to the
 * underlying `issuerRecognizedByVerification`, whose sense is inverted:
 * `shouldDisableUrls === !issuerRecognizedByVerification`).
 */
import { describe, it, expect } from 'vitest'
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import type { ChecklistMsgKey } from '../../src/display/index.js'
import {
  buildVerificationChecklist,
  getVerificationAggregateStatus,
  isExpiredOnly,
  isFullyVerified,
  issuerRecognizedByVerification
} from '../../src/display/index.js'

const LABELS: Record<ChecklistMsgKey, string> = {
  supportedFormatOk: 'is in a supported credential format',
  supportedFormatFail: 'is not a recognized credential type',
  signatureOk: 'has a valid signature',
  signatureFail: 'has an invalid signature',
  issuerOk: 'has been issued by a known issuer',
  issuerFail: "isn't in a known issuer registry",
  revocationOk: 'has not been revoked',
  revocationFail: 'has been revoked',
  expirationOk: 'has not expired',
  expirationFail: 'has expired',
  noExpiration: 'has no expiration date set'
}

const BASE_VC = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:key:zABC'
} as IVerifiableCredential

function payload(
  log: Array<{ id: string; valid?: boolean; error?: { message?: string } }>
) {
  return {
    verified: log.every(entry => entry.valid !== false),
    log,
    results: [{ verified: true, log }]
  }
}

describe('buildVerificationChecklist', () => {
  it('maps a fully valid credential to five positive steps', () => {
    const result = buildVerificationChecklist(
      payload([
        { id: 'valid_signature', valid: true },
        { id: 'registered_issuer', valid: true },
        { id: 'revocation_status', valid: true },
        { id: 'expiration', valid: true }
      ]),
      BASE_VC,
      LABELS
    )
    expect(result.supportedFormat.valid).toBe(true)
    expect(result.supportedFormat.status).toBe('positive')
    expect(result.signature.message).toBe('has a valid signature')
    expect(result.issuer.message).toBe('has been issued by a known issuer')
    expect(result.revocation.message).toBe('has not been revoked')
    expect(result.expiration.message).toBe('has not expired')
    expect(isFullyVerified(result)).toBe(true)
    expect(result.expiry).toBe(result.expiration)
    expect(result.status).toBe(result.revocation)
  })

  it('marks an unknown issuer as a warning, not a hard failure', () => {
    const result = buildVerificationChecklist(
      payload([
        { id: 'valid_signature', valid: true },
        {
          id: 'registered_issuer',
          valid: false,
          error: {
            message: 'Could not find issuer in registry with given DID.'
          }
        }
      ]),
      BASE_VC,
      LABELS
    )
    expect(result.issuer.valid).toBe(false)
    expect(result.issuer.status).toBe('warning')
    expect(result.signature.valid).toBe(true)
    expect(getVerificationAggregateStatus(result)).toBe('warning')
    expect(isFullyVerified(result)).toBe(false)
  })

  it('marks expiration failure as a warning when other checks pass', () => {
    const result = buildVerificationChecklist(
      payload([
        { id: 'valid_signature', valid: true },
        { id: 'registered_issuer', valid: true },
        { id: 'expiration', valid: false }
      ]),
      BASE_VC,
      LABELS
    )
    expect(result.expiration.valid).toBe(false)
    expect(result.expiration.status).toBe('warning')
    expect(getVerificationAggregateStatus(result)).toBe('warning')
    expect(isExpiredOnly(result)).toBe(true)
  })

  it('marks revocation failure as a hard failure', () => {
    const result = buildVerificationChecklist(
      payload([
        { id: 'valid_signature', valid: true },
        { id: 'registered_issuer', valid: true },
        { id: 'revocation_status', valid: false }
      ]),
      {
        ...BASE_VC,
        credentialStatus: { id: 'status:1' }
      } as IVerifiableCredential,
      LABELS
    )
    expect(result.revocation.valid).toBe(false)
    expect(result.revocation.status).toBe('negative')
    expect(getVerificationAggregateStatus(result)).toBe('not_verified')
  })

  it('reports unsupported credential types as a hard failure', () => {
    const result = buildVerificationChecklist(
      payload([{ id: 'valid_signature', valid: true }]),
      { ...BASE_VC, type: ['CustomCredential'] } as IVerifiableCredential,
      LABELS
    )
    expect(result.supportedFormat.valid).toBe(false)
    expect(result.supportedFormat.status).toBe('negative')
    expect(getVerificationAggregateStatus(result)).toBe('not_verified')
  })

  it('shows no expiration date when the credential has none', () => {
    const result = buildVerificationChecklist(
      payload([{ id: 'valid_signature', valid: true }]),
      BASE_VC,
      LABELS
    )
    expect(result.expiration.valid).toBe(true)
    expect(result.expiration.message).toBe('has no expiration date set')
  })
})

describe('issuerRecognizedByVerification', () => {
  it('is false when there is no log', () => {
    expect(issuerRecognizedByVerification()).toBe(false)
    expect(issuerRecognizedByVerification(undefined)).toBe(false)
    expect(issuerRecognizedByVerification([])).toBe(false)
  })

  it('is false when the log has no registered_issuer entry', () => {
    expect(
      issuerRecognizedByVerification([{ id: 'valid_signature', valid: true }])
    ).toBe(false)
  })

  it('is true when verification confirms a registered issuer', () => {
    expect(
      issuerRecognizedByVerification([
        { id: 'registered_issuer', valid: true, matchingIssuers: [{}] }
      ])
    ).toBe(true)
  })

  it('is false when the registered_issuer entry has no matches', () => {
    expect(
      issuerRecognizedByVerification([
        { id: 'registered_issuer', valid: false, matchingIssuers: [] }
      ])
    ).toBe(false)
  })

  it('is false when the registered_issuer entry is valid but empty', () => {
    expect(
      issuerRecognizedByVerification([
        { id: 'registered_issuer', valid: true, matchingIssuers: [] }
      ])
    ).toBe(false)
  })
})
