/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Real Ed25519 signer helpers for the compose / presentation-suite suites. A
 * fresh `did:key` key pair is generated per call so the signing paths run
 * end-to-end (no crypto mocking), which the Node vitest runner handles fine.
 */
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import type { ISigner } from '@interop/data-integrity-core'
import type { PresentationSigner } from '../../../../src/request/index.js'

/** Generates a `did:key` Ed25519 signer. */
export async function makeSigner(): Promise<ISigner> {
  const { signer } = await makePresentationSigner()
  return signer
}

/** Generates a `did:key` Ed25519 signer plus the holder DID naming it. */
export async function makePresentationSigner(): Promise<PresentationSigner> {
  const key = await Ed25519VerificationKey.generate()
  const did = `did:key:${key.fingerprint()}`
  key.controller = did
  key.id = `${did}#${key.fingerprint()}`
  return { signer: key.signer(), holder: did }
}
