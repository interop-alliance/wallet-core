/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The connect-code grammar, on its own: the scheme-like prefix a wallet
 * connect code carries and the predicate that recognizes one.
 *
 * It is a leaf module deliberately. Recognizing a connect code is something a
 * paste box or a QR scanner does long before any ceremony machinery is
 * involved, so the input classifier can depend on this without pulling in the
 * enrollment ceremony's whole graph -- and there is still exactly one spelling
 * of the prefix in the codebase.
 */

/**
 * The connect-code prefix; the payload after it is base64url(JSON) of an
 * enrollment request plus a `v` version stamp.
 */
export const CONNECT_CODE_PREFIX = 'freewallet-connect:'

/**
 * Whether some pasted or scanned text is a wallet connect code. A prefix
 * check only -- whether the payload is well-formed (and of a supported
 * version) is `parseEnrollmentRequest`'s answer, which is what surfaces a
 * clear refusal for a code that is recognizable but unusable.
 *
 * @param text {string}
 * @returns {boolean}
 */
export function isConnectCode(text: string): boolean {
  return text.trim().startsWith(CONNECT_CODE_PREFIX)
}
