/**
 * Unit tests for the enrollment ceremony's channel layer
 * (`src/enrollment/enrollment.ts`): the connect-code round-trip and its
 * validation, the exact wire format of a code (prefix + base64url of the
 * versioned JSON payload -- two wallet apps must mint byte-identical codes),
 * and the load-bearing kid invariant -- the roster entry the enrolling client
 * mints from a code must carry exactly the key id the enrollee's own
 * `agentsFromSeed` derivation will look for at login. The ceremony's two
 * halves against real stores are covered by the didWebvh / pukRoster tests.
 */
import { describe, expect, it } from 'vitest'
import { base64urlnopad } from '@scure/base'
import { agentsFromSeed } from '../../src/identity/agents.js'
import {
  encodeEnrollmentRequest,
  enrollmentClientDid,
  enrollmentRecipientKid,
  mintEnrollmentRequest,
  parseEnrollmentRequest,
  type EnrollmentRequest
} from '../../src/enrollment/enrollment.js'

/**
 * A fixed request whose code is asserted byte for byte below.
 */
const FIXED_REQUEST: EnrollmentRequest = {
  signingKeyMultibase: 'z6MkClientSigningKeyExample',
  keyAgreementKeyMultibase: 'z6LSClientAgreementKeyExample',
  updateKeyMultibase: 'z6MkUpdateKeyExample',
  stagedUpdateKeyMultibase: 'z6MkStagedUpdateKeyExample'
}

describe('the connect-code wire format', () => {
  it('mints the documented prefix + base64url(JSON) payload', () => {
    const code = encodeEnrollmentRequest({ request: FIXED_REQUEST })
    expect(code.startsWith('freewallet-connect:')).toBe(true)

    // The payload is the version stamp followed by the four multibases, in
    // that key order -- the byte-level contract two wallets share.
    const payload = new TextDecoder().decode(
      base64urlnopad.decode(code.slice('freewallet-connect:'.length))
    )
    expect(payload).toBe(JSON.stringify({ v: 1, ...FIXED_REQUEST }))
    expect(code).toBe(
      `freewallet-connect:${base64urlnopad.encode(
        new TextEncoder().encode(payload)
      )}`
    )
    expect(parseEnrollmentRequest({ code })).toEqual(FIXED_REQUEST)
  })
})

describe('connect code round-trip', () => {
  it('mints a key set whose code parses back to the same public halves', async () => {
    const minted = await mintEnrollmentRequest()
    const request = parseEnrollmentRequest({ code: minted.code })

    expect(request.signingKeyMultibase.startsWith('z6Mk')).toBe(true)
    expect(request.keyAgreementKeyMultibase.startsWith('z6LS')).toBe(true)
    expect(request.updateKeyMultibase.startsWith('z6Mk')).toBe(true)
    expect(request.stagedUpdateKeyMultibase.startsWith('z6Mk')).toBe(true)
    expect(request.updateKeyMultibase).not.toBe(
      request.stagedUpdateKeyMultibase
    )
    expect(encodeEnrollmentRequest({ request })).toBe(minted.code)

    // The displayed fingerprint is the signing key's did:key.
    expect(minted.clientDid).toBe(enrollmentClientDid({ request }))
    expect(minted.clientDid).toBe(`did:key:${request.signingKeyMultibase}`)

    // Surrounding whitespace (a sloppy paste) is tolerated.
    expect(parseEnrollmentRequest({ code: `  ${minted.code}\n` })).toEqual(
      request
    )
  })

  it('derives the roster kid the enrollee itself will look for', async () => {
    const minted = await mintEnrollmentRequest()
    const request = parseEnrollmentRequest({ code: minted.code })

    // The invariant the PUK delivery depends on: the wrap's kid equals the
    // enrollee's own key-agreement key id as agentsFromSeed derives it.
    const { keyAgreementKey } = await agentsFromSeed({
      seed: minted.clientSeed
    })
    expect(enrollmentRecipientKid({ request })).toBe(keyAgreementKey.id)
  })
})

describe('parseEnrollmentRequest validation', () => {
  it('refuses a code without the prefix', () => {
    expect(() => parseEnrollmentRequest({ code: 'hello' })).toThrow(
      'Not a wallet connect code'
    )
  })

  it('refuses an undecodable payload', () => {
    expect(() =>
      parseEnrollmentRequest({ code: 'freewallet-connect:!!not-base64url!!' })
    ).toThrow('malformed')
  })

  it('refuses an unsupported payload version', () => {
    const recoded = `freewallet-connect:${base64urlnopad.encode(
      new TextEncoder().encode(JSON.stringify({ v: 99, ...FIXED_REQUEST }))
    )}`
    expect(() => parseEnrollmentRequest({ code: recoded })).toThrow('version')
  })

  it('refuses a key of the wrong type', () => {
    // An X25519 multibase where an Ed25519 signing key belongs.
    const swapped = encodeEnrollmentRequest({
      request: {
        ...FIXED_REQUEST,
        signingKeyMultibase: FIXED_REQUEST.keyAgreementKeyMultibase
      }
    })
    expect(() => parseEnrollmentRequest({ code: swapped })).toThrow(
      'signing key'
    )
  })
})
