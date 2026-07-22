/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Small string / record coercion helpers shared by the display derivation
 * functions. These read the loosely-typed fields of a decoded Verifiable
 * Credential without importing any UI or formatting library.
 *
 * Drift resolution: two apps had two slightly different "coerce to a usable
 * string" helpers. DCW's `asNonEmptyString` (stringifies any value, trims,
 * returns `null` when empty) and Freewallet's `getTrimmedString` (only accepts
 * an actual string, returns `''` when not). Both are kept verbatim because
 * their callers depend on the different empty conventions (`null` vs `''`).
 * `asRecord` is Freewallet's object narrower.
 */

/**
 * Coerces an arbitrary value to a trimmed, non-empty string, or `null`. Any
 * non-string value is stringified first (so a number `3` becomes `'3'`).
 * `null` / `undefined` and whitespace-only values yield `null`.
 *
 * @param value {unknown}
 * @returns {string | null}
 */
export function asNonEmptyString(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null
  }
  if (typeof value === 'string') {
    const s = value.trim()
    return s.length ? s : null
  }
  const s = `${value}`.trim()
  return s.length ? s : null
}

/**
 * Returns the trimmed value when it is a string, else the empty string. Unlike
 * {@link asNonEmptyString} this never stringifies a non-string value.
 *
 * @param value {unknown}
 * @returns {string}
 */
export function getTrimmedString(value: unknown): string {
  if (typeof value !== 'string') {
    return ''
  }
  return value.trim()
}

/**
 * Narrows an arbitrary value to a plain record (`Record<string, unknown>`), or
 * `undefined` when it is null / a primitive / an array is acceptable here since
 * arrays are objects too and callers pass only object-shaped subjects.
 *
 * @param value {unknown}
 * @returns {Record<string, unknown> | undefined}
 */
export function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object') {
    return undefined
  }
  return value as Record<string, unknown>
}
