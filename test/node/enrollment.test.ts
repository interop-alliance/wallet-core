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
 * A fixed request whose code is asserted byte for byte below. The four
 * multibases are real Ed25519/X25519 public keys (deterministically generated
 * from the seeds 1..4), because the parser decodes every one of them.
 */
const FIXED_REQUEST: EnrollmentRequest = {
  signingKeyMultibase: 'z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX',
  keyAgreementKeyMultibase: 'z6LSi9ig66fZi18Mk7mwkb5TPBY6bT4CstAAQi4cE6bED5bV',
  updateKeyMultibase: 'z6MkvRXNYcE7MMduynWTgeKbDaT1iijDSC8pZqXZc8rHPrf2',
  stagedUpdateKeyMultibase: 'z6Mkt6316e2PN3mZdB6N9CrzomJYUd1s5yBZi1XYHmwT9TUP'
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

  it('refuses a key that is not base58-decodable', () => {
    // `l` is not in the base58btc alphabet: the prefix still looks right, so
    // only a real decode catches it.
    const corrupted = encodeEnrollmentRequest({
      request: {
        ...FIXED_REQUEST,
        updateKeyMultibase: `${FIXED_REQUEST.updateKeyMultibase.slice(0, -1)}l`
      }
    })
    expect(() => parseEnrollmentRequest({ code: corrupted })).toThrow(
      'update key'
    )
  })

  it('refuses a truncated key', () => {
    const truncated = encodeEnrollmentRequest({
      request: {
        ...FIXED_REQUEST,
        stagedUpdateKeyMultibase: FIXED_REQUEST.stagedUpdateKeyMultibase.slice(
          0,
          40
        )
      }
    })
    expect(() => parseEnrollmentRequest({ code: truncated })).toThrow(
      'staged update key'
    )
  })

  it('rejects a corrupted minted code before anything can be published', async () => {
    const minted = await mintEnrollmentRequest()
    const request = parseEnrollmentRequest({ code: minted.code })

    // One transcription slip in the key-agreement key: the code still carries
    // the right prefix and the right shape, and the enrolling client would
    // otherwise sign it into the account's append-only did:webvh log.
    const corrupted = encodeEnrollmentRequest({
      request: {
        ...request,
        keyAgreementKeyMultibase: `${request.keyAgreementKeyMultibase.slice(
          0,
          -1
        )}O`
      }
    })
    expect(() => parseEnrollmentRequest({ code: corrupted })).toThrow(
      'key-agreement key'
    )
  })
})
