/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Credential type predicates.
 *
 * Drift resolution: DCW and Freewallet disagreed on the resume check -- DCW's
 * took a `credentialSubject` and did a case-insensitive SUBSTRING match on its
 * `type`, while Freewallet's took the whole VC and did an exact
 * `subject.type === 'Resume'`; and DCW's own callers passed the whole VC to the
 * subject-typed function. Rather than pick one, TWO clearly-named functions are
 * exposed:
 *
 * - `isResumeCredentialSubject(subject)` -- DCW's case-insensitive substring
 *   check over a subject's `type`.
 * - `isResumeCredential(vc)` -- a vc-typed entry point that reads the subject's
 *   `type` off the VC and applies the same substring check, fixing both
 *   Freewallet's exact-match miss (`['...','Resume']`) and DCW's callers that
 *   passed a VC to a subject-typed function.
 *
 * `isEmploymentCredential` / `isVolunteerCredential` are DCW's, verbatim, over
 * the VC's top-level `type`.
 */
import type {
  ICredentialSubject,
  IVerifiableCredential
} from '@interop/data-integrity-core'
import { typeArray } from '@interop/data-integrity-core/guards'
import { getSubject } from './subject.js'

/**
 * Whether a credential SUBJECT is a resume, by a case-insensitive substring
 * match (`'resume'`) over its `type` (string or array).
 *
 * @param credentialSubject {ICredentialSubject}
 * @returns {boolean}
 */
export function isResumeCredentialSubject(
  credentialSubject: ICredentialSubject
): boolean {
  return typeArray(credentialSubject?.type).some(x =>
    x.toLowerCase().includes('resume')
  )
}

/**
 * Whether a CREDENTIAL is a resume, by applying the subject-level substring
 * check to the VC's (first) subject `type`.
 *
 * @param vc {IVerifiableCredential}
 * @returns {boolean}
 */
export function isResumeCredential(vc: IVerifiableCredential): boolean {
  return isResumeCredentialSubject(getSubject(vc))
}

/**
 * Whether a credential's top-level `type` includes `'EmploymentCredential'`.
 *
 * @param credential {IVerifiableCredential}
 * @returns {boolean}
 */
export function isEmploymentCredential(
  credential: IVerifiableCredential
): boolean {
  return typeArray(credential?.type).includes('EmploymentCredential')
}

/**
 * Whether a credential's top-level `type` includes `'VolunteeringCredential'`.
 *
 * @param credential {IVerifiableCredential}
 * @returns {boolean}
 */
export function isVolunteerCredential(
  credential: IVerifiableCredential
): boolean {
  return typeArray(credential?.type).includes('VolunteeringCredential')
}
