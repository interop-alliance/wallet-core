/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/enrollment` subpath: the client enrollment
 * ceremony -- connecting another wallet client to an existing account with
 * only public halves travelling, point to point.
 *
 * - `mintEnrollmentRequest` / `encodeEnrollmentRequest` /
 *   `parseEnrollmentRequest` / `enrollmentClientDid` /
 *   `enrollmentRecipientKid` -- the connect-code channel layer.
 * - `approveEnrollment` -- the enrolling client's half, in the push order
 *   (roster wrap, then the two did:webvh log entries).
 * - `completeEnrollmentCore` -- the enrollee's half: verify from the published
 *   log, read the roster, hand back the PUK and the epoch to pin. Persisting
 *   the key set stays with the caller's own unlock layer.
 */
export {
  approveEnrollment,
  completeEnrollmentCore,
  encodeEnrollmentRequest,
  EnrollmentPendingError,
  enrollmentClientDid,
  enrollmentRecipientKid,
  mintEnrollmentRequest,
  parseEnrollmentRequest
} from './enrollment.js'
export type { EnrollmentRequest } from './enrollment.js'
