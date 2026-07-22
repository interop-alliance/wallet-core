/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Verification-to-UI derivation: pure readers over a `verifyCredential` result
 * `log[]`. No conflict existed between the apps -- they read different things
 * from the same log -- so both are extracted:
 *
 * - `buildVerificationChecklist` (Freewallet) builds the five-step
 *   supportedFormat / signature / issuer / revocation / expiration checklist,
 *   each `{ valid, message, status }`, plus the `getVerificationAggregateStatus`
 *   / `isFullyVerified` / `isExpiredOnly` / `hasVerificationWarning` rollups.
 * - `issuerRecognizedByVerification` (backs DCW's `shouldDisableUrls`) reports
 *   whether the `registered_issuer` entry confirms a registry match.
 *
 * i18n stays OUT of the library: instead of Freewallet's injected `TFunction`
 * or DCW's hardcoded English, `buildVerificationChecklist` takes an injected
 * `labels` map keyed by {@link ChecklistMsgKey}. Each app supplies its own
 * strings (Freewallet from `t(...)`, DCW its English literals).
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'
import { getExpirationInstant } from './validity.js'
import { typeArray } from '@interop/data-integrity-core/guards'

/** Per-step severity. */
export type VerificationStepStatus = 'positive' | 'warning' | 'negative'

/** One checklist step. */
export interface VerificationStep {
  valid: boolean
  message: string
  status: VerificationStepStatus
  error?: string
}

/** The five-step checklist, with `expiry` / `status` legacy aliases. */
export interface VerificationChecklist {
  supportedFormat: VerificationStep
  signature: VerificationStep
  issuer: VerificationStep
  revocation: VerificationStep
  expiration: VerificationStep
  /** @deprecated Use `expiration`. */
  expiry: VerificationStep
  /** @deprecated Use `revocation`. */
  status: VerificationStep
}

/** Rolled-up verification outcome. */
export type VerificationAggregateStatus =
  'verified' | 'warning' | 'not_verified'

/** The message keys `buildVerificationChecklist` looks up in the `labels` map. */
export type ChecklistMsgKey =
  | 'supportedFormatOk'
  | 'supportedFormatFail'
  | 'signatureOk'
  | 'signatureFail'
  | 'issuerOk'
  | 'issuerFail'
  | 'revocationOk'
  | 'revocationFail'
  | 'expirationOk'
  | 'expirationFail'
  | 'noExpiration'

const STEP_ID = {
  validSignature: 'valid_signature',
  expiration: 'expiration',
  revocation: 'revocation_status',
  registeredIssuer: 'registered_issuer'
} as const

const SUPPORTED_CREDENTIAL_TYPES = [
  'VerifiableCredential',
  'OpenBadgeCredential'
]

interface LogLine {
  id: string
  valid?: boolean
  error?: { message?: string; name?: string }
}

function getVerifyLogFromPayload(raw: Record<string, unknown>): LogLine[] {
  const results = raw.results as Array<{ log?: LogLine[] }> | undefined
  const logFromFirstResult = results?.[0]?.log
  if (Array.isArray(logFromFirstResult)) {
    return logFromFirstResult
  }
  const topLevelLog = raw.log
  if (Array.isArray(topLevelLog)) {
    return topLevelLog as LogLine[]
  }
  return []
}

function step(
  valid: boolean,
  message: string,
  severity: VerificationStepStatus,
  error?: string
): VerificationStep {
  return {
    valid,
    message,
    status: severity,
    ...(error ? { error } : {})
  }
}

function logValid(entry: LogLine | undefined): boolean | undefined {
  if (!entry) {
    return undefined
  }
  return entry.valid === true && !entry.error
}

function supportedFormatStep(
  credential: IVerifiableCredential,
  labels: Record<ChecklistMsgKey, string>
): VerificationStep {
  const hasKnownType = typeArray(credential.type).some(type =>
    SUPPORTED_CREDENTIAL_TYPES.includes(type)
  )
  return step(
    hasKnownType,
    hasKnownType ? labels.supportedFormatOk : labels.supportedFormatFail,
    hasKnownType ? 'positive' : 'negative'
  )
}

function signatureStep(
  entry: LogLine | undefined,
  labels: Record<ChecklistMsgKey, string>
): VerificationStep {
  const valid = logValid(entry) ?? false
  return step(
    valid,
    valid ? labels.signatureOk : labels.signatureFail,
    valid ? 'positive' : 'negative',
    entry?.error?.message
  )
}

function issuerStep(
  entry: LogLine | undefined,
  labels: Record<ChecklistMsgKey, string>
): VerificationStep {
  const valid = logValid(entry) ?? false
  return step(
    valid,
    valid ? labels.issuerOk : labels.issuerFail,
    valid ? 'positive' : 'warning',
    entry?.error?.message
  )
}

function revocationStep(
  entry: LogLine | undefined,
  credential: IVerifiableCredential,
  labels: Record<ChecklistMsgKey, string>
): VerificationStep {
  if (!credential.credentialStatus && !entry) {
    return step(true, labels.revocationOk, 'positive')
  }
  const valid = logValid(entry) ?? true
  return step(
    valid,
    valid ? labels.revocationOk : labels.revocationFail,
    valid ? 'positive' : 'negative',
    entry?.error?.message
  )
}

function expirationStep(
  entry: LogLine | undefined,
  credential: IVerifiableCredential,
  labels: Record<ChecklistMsgKey, string>
): VerificationStep {
  const exp = getExpirationInstant(credential)
  const hasExpirationDate = exp != null

  if (!hasExpirationDate && !entry) {
    return step(true, labels.noExpiration, 'positive')
  }

  if (entry) {
    const valid = logValid(entry) ?? false
    return step(
      valid,
      valid ? labels.expirationOk : labels.expirationFail,
      valid ? 'positive' : 'warning',
      entry.error?.message
    )
  }

  const expired = exp!.getTime() < Date.now()
  return step(
    !expired,
    expired ? labels.expirationFail : labels.expirationOk,
    expired ? 'warning' : 'positive'
  )
}

function withGlobalErr(
  stepValue: VerificationStep,
  globalErr?: string
): VerificationStep {
  if (stepValue.valid || !globalErr) {
    return stepValue
  }
  return { ...stepValue, error: stepValue.error ?? globalErr }
}

function attachLegacyAliases(
  checklist: Omit<VerificationChecklist, 'expiry' | 'status'>
): VerificationChecklist {
  return {
    ...checklist,
    expiry: checklist.expiration,
    status: checklist.revocation
  }
}

/**
 * Builds the five-step verification checklist from a raw `verifyCredential`
 * payload, the credential, and an injected `labels` map.
 *
 * @param raw {Record<string, unknown>} the raw verify result
 * @param credential {IVerifiableCredential}
 * @param labels {Record<ChecklistMsgKey, string>} localized message strings
 * @returns {VerificationChecklist}
 */
export function buildVerificationChecklist(
  raw: Record<string, unknown>,
  credential: IVerifiableCredential,
  labels: Record<ChecklistMsgKey, string>
): VerificationChecklist {
  const log = getVerifyLogFromPayload(raw)
  const byId = (id: string) => log.find(line => line.id === id)

  const resultsWithError = raw.results as
    Array<{ error?: { message?: string } }> | undefined
  const globalErr =
    typeof resultsWithError?.[0]?.error?.message === 'string'
      ? resultsWithError[0]!.error!.message
      : undefined

  const checklist = {
    supportedFormat: supportedFormatStep(credential, labels),
    signature: signatureStep(byId(STEP_ID.validSignature), labels),
    issuer: issuerStep(byId(STEP_ID.registeredIssuer), labels),
    revocation: revocationStep(byId(STEP_ID.revocation), credential, labels),
    expiration: expirationStep(byId(STEP_ID.expiration), credential, labels)
  }

  if (!globalErr) {
    return attachLegacyAliases(checklist)
  }

  return attachLegacyAliases({
    supportedFormat: withGlobalErr(checklist.supportedFormat, globalErr),
    signature: withGlobalErr(checklist.signature, globalErr),
    issuer: withGlobalErr(checklist.issuer, globalErr),
    revocation: withGlobalErr(checklist.revocation, globalErr),
    expiration: withGlobalErr(checklist.expiration, globalErr)
  })
}

/**
 * Rolls the checklist up to a single status. Hard failures (bad signature /
 * format / revocation) yield `'not_verified'`; a soft issue (unknown issuer or
 * expired) yields `'warning'`; otherwise `'verified'`.
 *
 * @param result {VerificationChecklist | null}
 * @returns {VerificationAggregateStatus | null}
 */
export function getVerificationAggregateStatus(
  result: VerificationChecklist | null
): VerificationAggregateStatus | null {
  if (!result) {
    return null
  }

  const hasFailure =
    !result.signature.valid ||
    !result.supportedFormat.valid ||
    !result.revocation.valid

  const hasWarning = !result.issuer.valid || !result.expiration.valid

  if (hasFailure) {
    return 'not_verified'
  }
  if (hasWarning) {
    return 'warning'
  }
  return 'verified'
}

/**
 * Whether every check passed.
 *
 * @param result {VerificationChecklist | null}
 * @returns {boolean}
 */
export function isFullyVerified(result: VerificationChecklist | null): boolean {
  return getVerificationAggregateStatus(result) === 'verified'
}

/**
 * Whether the only failing check is expiration (everything else passed).
 *
 * @param result {VerificationChecklist | null}
 * @returns {boolean}
 */
export function isExpiredOnly(result: VerificationChecklist | null): boolean {
  if (!result) {
    return false
  }
  return (
    result.signature.valid &&
    result.supportedFormat.valid &&
    result.issuer.valid &&
    result.revocation.valid &&
    !result.expiration.valid
  )
}

/**
 * Whether the aggregate status is a warning.
 *
 * @param result {VerificationChecklist | null}
 * @returns {boolean}
 */
export function hasVerificationWarning(
  result: VerificationChecklist | null
): boolean {
  return getVerificationAggregateStatus(result) === 'warning'
}

/**
 * Whether verification confirms a registered issuer: the `registered_issuer`
 * log entry is valid and (when present) its `matchingIssuers` is non-empty.
 * Backs DCW's `shouldDisableUrls` (a one-line app wrapper:
 * `!issuerRecognizedByVerification(log)`).
 *
 * @param log {Array<{ id: string; valid?: boolean; matchingIssuers?: unknown[] }> | undefined}
 * @returns {boolean}
 */
export function issuerRecognizedByVerification(
  log?: Array<{ id: string; valid?: boolean; matchingIssuers?: unknown[] }>
): boolean {
  if (!Array.isArray(log)) {
    return false
  }

  return log.some(entry => {
    if (entry.id !== 'registered_issuer') {
      return false
    }
    const { matchingIssuers } = entry
    return entry.valid && Array.isArray(matchingIssuers)
      ? matchingIssuers.length > 0
      : Boolean(entry.valid)
  })
}
