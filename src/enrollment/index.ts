/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/enrollment` subpath: the client enrollment
 * ceremony -- connecting another wallet client to an existing account with
 * only public halves travelling, point to point.
 *
 * - `CONNECT_CODE_PREFIX` / `isConnectCode` -- the connect-code grammar, on
 *   its own so an input classifier can recognize a code without the ceremony.
 * - `mintEnrollmentRequest` / `encodeEnrollmentRequest` /
 *   `parseEnrollmentRequest` / `enrollmentClientDid` /
 *   `enrollmentRecipientKid` -- the connect-code channel layer.
 * - `assertCanonicalEnrollmentKeys` -- the refusal of a code whose
 *   key-agreement key is not its signing key's canonical X25519 twin, run by
 *   both the parse and the approval.
 * - `approveEnrollment` -- the enrolling client's half, in the push order
 *   (roster wrap, then the two did:webvh log entries).
 * - `encodeOnboardingResponse` / `parseOnboardingResponse` -- the onboarding-
 *   response envelope, the transport that carries a connect code (verbatim)
 *   plus a suggested display label back over an exchange whose request asked
 *   with a `WalletOnboardingQuery` (`@interop/wallet-core/request`).
 * - `ONBOARDING_INVITE_TTL_MS` -- how long a wallet offers an invite for. The
 *   invite's transport (creating the ephemeral exchange that carries the
 *   query, polling it until the envelope arrives) is the generic requester in
 *   `@interop/wallet-core/request` (`createEphemeralExchange` /
 *   `pollEphemeralExchange`).
 * - `completeEnrollmentCore` -- the enrollee's half: verify from the published
 *   log, read the roster, hand back the user key and the epoch to pin. Persisting
 *   the key set stays with the caller's own unlock layer.
 */
export {
  approveEnrollment,
  assertCanonicalEnrollmentKeys,
  completeEnrollmentCore,
  encodeEnrollmentRequest,
  EnrollmentPendingError,
  enrollmentClientDid,
  enrollmentRecipientKid,
  mintEnrollmentRequest,
  parseEnrollmentRequest
} from './enrollment.js'
export type { EnrollmentRequest } from './enrollment.js'
export { CONNECT_CODE_PREFIX, isConnectCode } from './connectCode.js'
export {
  encodeOnboardingResponse,
  ONBOARDING_LABEL_MAX_LENGTH,
  ONBOARDING_RESPONSE_VERSION,
  parseOnboardingResponse
} from './onboardingResponse.js'
export type { WalletOnboardingResponse } from './onboardingResponse.js'
export { ONBOARDING_INVITE_TTL_MS } from './onboardingInvite.js'
