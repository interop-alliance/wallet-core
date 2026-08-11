/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The onboarding-response envelope: what a fresh wallet (the enrollee) POSTs
 * back to an ephemeral exchange whose request carried a
 * `WalletOnboardingQuery` (`@interop/wallet-core/request`). It is transport
 * vocabulary only -- the enrollment ceremony is untouched.
 *
 * The envelope carries an ordinary connect code VERBATIM as its payload, so
 * the ceremony's strict validation applies unchanged and the inviter hands the
 * string it receives straight to `approveEnrollment`; the connect-code payload
 * version is deliberately NOT bumped by this transport. Beside it rides an
 * optional display label the enrollee suggests for itself. The label lives in
 * the envelope rather than in the code because its durable home is the
 * account's client-labels record, which the approving client writes -- the
 * code stays the ceremony's own artifact.
 *
 * The label is attacker-adjacent free text that renders on the approver's
 * consent screen, so it is stripped of control characters, trimmed, and
 * length-capped, and an over-cap label is REFUSED rather than silently
 * truncated: a truncated label would be a silently different name for a client
 * the person is about to authorize, where a refusal costs only a fresh code.
 */
import { parseEnrollmentRequest } from './enrollment.js'
import type { EnrollmentRequest } from './enrollment.js'

/**
 * The onboarding-response envelope version this build mints and accepts.
 */
export const ONBOARDING_RESPONSE_VERSION = 1

/**
 * The longest suggested display label an onboarding response may carry, in
 * code points, after control characters are stripped and whitespace trimmed.
 */
export const ONBOARDING_LABEL_MAX_LENGTH = 64

/**
 * Characters stripped from a suggested label before it is measured: the C0 and
 * C1 control ranges (including DEL) plus the bidirectional formatting and
 * isolate controls, none of which a display name needs and all of which can
 * reorder or hide what a consent screen shows.
 */
const LABEL_STRIPPED_CHARACTERS =
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu

/**
 * The onboarding-response envelope as it travels: the versioned wrapper, the
 * connect code verbatim, and the enrollee's optional suggested display label.
 */
export type WalletOnboardingResponse = {
  walletOnboarding: {
    v: number
    code: string
    label?: string
  }
}

/**
 * Sanitizes a suggested display label: strips the control and bidi characters
 * above, trims surrounding whitespace, and refuses anything still longer than
 * {@link ONBOARDING_LABEL_MAX_LENGTH}. A label that sanitizes to nothing at
 * all is absent rather than empty, so no consent screen renders a blank name.
 *
 * @param options {object}
 * @param options.label {unknown}   the envelope's `label` member, if any
 * @returns {string | undefined}
 */
function sanitizedOnboardingLabel({
  label
}: {
  label: unknown
}): string | undefined {
  if (label === undefined || label === null) {
    return undefined
  }
  if (typeof label !== 'string') {
    throw new Error('An onboarding response label must be a string.')
  }
  const sanitized = label.replace(LABEL_STRIPPED_CHARACTERS, '').trim()
  if (sanitized.length === 0) {
    return undefined
  }
  if ([...sanitized].length > ONBOARDING_LABEL_MAX_LENGTH) {
    throw new Error(
      `An onboarding response label may be at most ` +
        `${ONBOARDING_LABEL_MAX_LENGTH} characters.`
    )
  }
  return sanitized
}

/**
 * ENROLLEE: builds the response envelope for a connect code it just minted.
 * The code is validated with the ceremony's own parser (a code this side
 * cannot parse is one the inviter would refuse), and the label is sanitized by
 * the same rule the parse side applies, so an envelope this call produces is
 * always one {@link parseOnboardingResponse} accepts.
 *
 * @param options {object}
 * @param options.code {string}   the `freewallet-connect:` connect code
 * @param [options.label] {string}   a display label to suggest for this client
 * @returns {WalletOnboardingResponse}
 */
export function encodeOnboardingResponse({
  code,
  label
}: {
  code: string
  label?: string
}): WalletOnboardingResponse {
  parseEnrollmentRequest({ code })
  const suggested = sanitizedOnboardingLabel({ label })
  return {
    walletOnboarding: {
      v: ONBOARDING_RESPONSE_VERSION,
      code,
      ...(suggested !== undefined && { label: suggested })
    }
  }
}

/**
 * INVITER: validates a received onboarding-response body and hands back what
 * the approval screen needs -- the parsed enrollment request (so the
 * fingerprint renders without a second parse), the code verbatim (so
 * `approveEnrollment` receives exactly what the enrollee minted), and the
 * sanitized label, if any. Anything malformed throws: a body that is not an
 * object, a missing or mis-shaped envelope, an unsupported version, a
 * non-string or unparseable code, or a label that is not a string or exceeds
 * the cap. The remedy for every one of them is the same -- generate a new code
 * and try again.
 *
 * @param options {object}
 * @param options.body {unknown}   the received JSON body
 * @returns {object}   the parsed request, the code verbatim, and the label
 */
export function parseOnboardingResponse({ body }: { body: unknown }): {
  request: EnrollmentRequest
  code: string
  label?: string
} {
  if (body === null || typeof body !== 'object') {
    throw new Error('The onboarding response is malformed.')
  }
  const { walletOnboarding } = body as Record<string, unknown>
  if (walletOnboarding === null || typeof walletOnboarding !== 'object') {
    throw new Error('The onboarding response carries no walletOnboarding.')
  }
  const { v, code, label } = walletOnboarding as Record<string, unknown>
  if (v !== ONBOARDING_RESPONSE_VERSION) {
    throw new Error(`Unsupported onboarding response version "${String(v)}".`)
  }
  if (typeof code !== 'string') {
    throw new Error('The onboarding response carries no connect code.')
  }
  const request = parseEnrollmentRequest({ code })
  const suggested = sanitizedOnboardingLabel({ label })
  return {
    request,
    code,
    ...(suggested !== undefined && { label: suggested })
  }
}
