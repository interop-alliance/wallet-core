/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The character set and length every attacker-adjacent display string is
 * held to: the onboarding response's suggested label, and a server-served
 * identifier the ceremony event helpers carry. An import-free leaf, so a
 * layer that must not load the enrollment ceremony can still take it.
 */

/**
 * The longest suggested display label an onboarding response may carry, in
 * code points, after control characters are stripped and whitespace trimmed.
 * The ceremony event helpers truncate a server-served identifier to the same
 * length.
 */
export const ONBOARDING_LABEL_MAX_LENGTH = 64

/**
 * Characters stripped from a display string before it is measured: the C0
 * and C1 control ranges (including DEL) plus the bidirectional formatting and
 * isolate controls, none of which a display name needs and all of which can
 * reorder or hide what a consent screen or a log line shows.
 */
export const LABEL_STRIPPED_CHARACTERS =
  // eslint-disable-next-line no-control-regex
  /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu
