/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The plain-JSON-object guard every codec reads a parsed body through. An
 * import-free leaf, so any layer may take it, `space` included, without
 * importing a higher layer.
 */

/**
 * Whether a value is a plain JSON object (not null, not an array).
 *
 * @param value {unknown}
 * @returns {boolean}
 */
export function isJsonObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
