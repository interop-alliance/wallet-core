/**
 * A deterministic 32-byte seed, so two derivations agree across helpers and
 * a test can re-derive the same key across two stores.
 *
 * @param fill {number}   the byte every position holds
 * @returns {Uint8Array}
 */
export function fixedSeed(fill: number): Uint8Array {
  return new Uint8Array(32).fill(fill)
}
