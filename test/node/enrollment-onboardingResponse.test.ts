/**
 * Unit tests for the onboarding-response envelope codec
 * (`src/enrollment/onboardingResponse.ts`) that carries a connect code
 * verbatim back over an exchange in answer to a `WalletOnboardingQuery`
 * (`@interop/wallet-request`), and the invite's TTL policy
 * (`src/enrollment/onboardingInvite.ts`).
 */
import { describe, expect, it } from 'vitest'
import { base64urlnopad } from '@scure/base'
import {
  CONNECT_CODE_PREFIX,
  encodeEnrollmentRequest,
  encodeOnboardingResponse,
  ONBOARDING_INVITE_TTL_MS,
  ONBOARDING_LABEL_MAX_LENGTH,
  parseOnboardingResponse
} from '../../src/enrollment/index.js'
import type { EnrollmentRequest } from '../../src/enrollment/index.js'

/**
 * The same fixed request the enrollment tests use: four real Ed25519 / X25519
 * public multibases, since the connect-code parser decodes every one of them
 * (and checks the key-agreement key against its signing key's twin).
 */
const FIXED_REQUEST: EnrollmentRequest = {
  signingKeyMultibase: 'z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX',
  keyAgreementKeyMultibase: 'z6LSdVzMmB67tKXYmkjiKRAQgbxgjnjdfiajqUvx7C9fxTNv',
  updateKeyMultibase: 'z6MkvRXNYcE7MMduynWTgeKbDaT1iijDSC8pZqXZc8rHPrf2',
  stagedUpdateKeyMultibase: 'z6Mkt6316e2PN3mZdB6N9CrzomJYUd1s5yBZi1XYHmwT9TUP'
}

const CODE = encodeEnrollmentRequest({ request: FIXED_REQUEST })

describe('encodeOnboardingResponse', () => {
  it('wraps a connect code, with no label', () => {
    expect(encodeOnboardingResponse({ code: CODE })).toEqual({
      walletOnboarding: { v: 1, code: CODE }
    })
  })

  it('wraps a connect code with a suggested label', () => {
    expect(
      encodeOnboardingResponse({ code: CODE, label: 'Work phone' })
    ).toEqual({ walletOnboarding: { v: 1, code: CODE, label: 'Work phone' } })
  })

  it('rejects a code the ceremony would refuse', () => {
    expect(() => encodeOnboardingResponse({ code: 'nonsense' })).toThrow(
      /Not a wallet connect code/
    )
  })

  it('rejects an over-cap label rather than truncating it', () => {
    expect(() =>
      encodeOnboardingResponse({
        code: CODE,
        label: 'x'.repeat(ONBOARDING_LABEL_MAX_LENGTH + 1)
      })
    ).toThrow(/at most 64 characters/)
  })
})

describe('parseOnboardingResponse', () => {
  it('round-trips an encoded envelope, returning the parsed request', () => {
    const parsed = parseOnboardingResponse({
      body: JSON.parse(
        JSON.stringify(
          encodeOnboardingResponse({ code: CODE, label: 'Work phone' })
        )
      )
    })
    expect(parsed.code).toBe(CODE)
    expect(parsed.label).toBe('Work phone')
    expect(parsed.request).toEqual(FIXED_REQUEST)
  })

  it('accepts an envelope with no label', () => {
    const parsed = parseOnboardingResponse({
      body: { walletOnboarding: { v: 1, code: CODE } }
    })
    expect(parsed.label).toBeUndefined()
    expect(parsed.request.signingKeyMultibase).toBe(
      FIXED_REQUEST.signingKeyMultibase
    )
  })

  it('rejects a body that is not an object', () => {
    for (const body of [null, undefined, 'text', 42]) {
      expect(() => parseOnboardingResponse({ body })).toThrow(
        /onboarding response is malformed/
      )
    }
  })

  it('rejects a body carrying no walletOnboarding envelope', () => {
    for (const walletOnboarding of [undefined, null, 'text']) {
      expect(() =>
        parseOnboardingResponse({ body: { walletOnboarding } })
      ).toThrow(/carries no walletOnboarding/)
    }
  })

  it('rejects an unsupported envelope version', () => {
    for (const v of [0, 2, '1', undefined]) {
      expect(() =>
        parseOnboardingResponse({
          body: { walletOnboarding: { v, code: CODE } }
        })
      ).toThrow(/Unsupported onboarding response version/)
    }
  })

  it('rejects a non-string code', () => {
    for (const code of [undefined, null, 42, { code: CODE }]) {
      expect(() =>
        parseOnboardingResponse({ body: { walletOnboarding: { v: 1, code } } })
      ).toThrow(/carries no connect code/)
    }
  })

  it('rejects a code the ceremony would refuse', () => {
    const corrupted = `${CODE.slice(0, CODE.length - 4)}AAAA`
    const wrongVersion = `${CONNECT_CODE_PREFIX}${base64urlnopad.encode(
      new TextEncoder().encode(JSON.stringify({ v: 2, ...FIXED_REQUEST }))
    )}`
    const codes = [
      'nonsense',
      'freewallet-connect:not-base64url!!',
      corrupted,
      wrongVersion
    ]
    for (const code of codes) {
      expect(() =>
        parseOnboardingResponse({ body: { walletOnboarding: { v: 1, code } } })
      ).toThrow()
    }
  })

  it('rejects a non-string label', () => {
    expect(() =>
      parseOnboardingResponse({
        body: { walletOnboarding: { v: 1, code: CODE, label: 42 } }
      })
    ).toThrow(/label must be a string/)
  })

  it('rejects an over-cap label', () => {
    expect(() =>
      parseOnboardingResponse({
        body: {
          walletOnboarding: {
            v: 1,
            code: CODE,
            label: 'x'.repeat(ONBOARDING_LABEL_MAX_LENGTH + 1)
          }
        }
      })
    ).toThrow(/at most 64 characters/)
  })

  it('measures the label after stripping, so a stripped-to-fit one is kept', () => {
    const label = `${'x'.repeat(ONBOARDING_LABEL_MAX_LENGTH)}\u202e\u0007`
    expect(
      parseOnboardingResponse({
        body: { walletOnboarding: { v: 1, code: CODE, label } }
      }).label
    ).toBe('x'.repeat(ONBOARDING_LABEL_MAX_LENGTH))
  })

  it('strips control characters and trims the label', () => {
    expect(
      parseOnboardingResponse({
        body: {
          walletOnboarding: {
            v: 1,
            code: CODE,
            label: '  Work\u0000 phone\u202e  '
          }
        }
      }).label
    ).toBe('Work phone')
  })

  it('treats a label that sanitizes to nothing as absent', () => {
    for (const label of ['', '   ', '\u0000\u202e\u2066']) {
      expect(
        parseOnboardingResponse({
          body: { walletOnboarding: { v: 1, code: CODE, label } }
        }).label
      ).toBeUndefined()
    }
  })
})

describe('ONBOARDING_INVITE_TTL_MS', () => {
  // The requester's ephemeral-exchange TTL (`EPHEMERAL_EXCHANGE_TTL_MS` in
  // `@interop/wallet-request`) is ten minutes; the invite must expire first
  // so the countdown ends before the server drops the exchange.
  it('expires the invite inside the server exchange TTL', () => {
    expect(ONBOARDING_INVITE_TTL_MS).toBeLessThan(10 * 60 * 1000)
  })
})
