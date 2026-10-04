/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Readable placeholder Ed25519 multikeys for the account-log fixtures. A
 * fixture that only needs distinct, stable `publicKeyMultibase` strings used
 * to spell them out (`'z6MkRungZero'`), but `deriveNextKeyHash` now decodes
 * its input and refuses anything that is not a 32-byte Ed25519 multikey. This
 * helper keeps the label as the key's identity: the 32 bytes are the label's
 * SHA-256, prefixed with the Ed25519 multicodec, so two calls with one label
 * agree and two labels never collide. The bytes are not an actual curve point,
 * which no fixture here verifies a signature against.
 */
import { sha256 } from '@noble/hashes/sha2.js'
import { base58 } from '@scure/base'

const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01])

/**
 * @param label {string}   the key's readable identity in the fixture
 * @returns {string}   a `z6Mk...` multibase string `deriveNextKeyHash` accepts
 */
export function fakeEd25519Multikey(label: string): string {
  const bytes = new Uint8Array(34)
  bytes.set(ED25519_MULTICODEC)
  bytes.set(sha256(new TextEncoder().encode(label)), 2)
  return `z${base58.encode(bytes)}`
}
