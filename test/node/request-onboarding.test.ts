/**
 * Unit tests for the wallet-onboarding transport vocabulary: the
 * `WalletOnboardingQuery` compose helper and its classification
 * (`src/request/onboarding.ts`), the fail-closed behavior an older wallet
 * exhibits when it meets one, and the onboarding-response envelope codec
 * (`src/enrollment/onboardingResponse.ts`) that carries a connect code
 * verbatim back over the exchange.
 */
import { describe, expect, it } from 'vitest'
import {
  classifyRequest,
  composeWalletOnboardingRequest,
  queriesOf,
  serializedOnboardingHost,
  walletOnboardingRequestOf
} from '../../src/request/index.js'
import type { IVPRQuery } from '../../src/request/index.js'
import { appConnectRequestOf } from '../../src/request/index.js'
import { base64urlnopad } from '@scure/base'
import {
  CONNECT_CODE_PREFIX,
  encodeEnrollmentRequest,
  encodeOnboardingResponse,
  ONBOARDING_LABEL_MAX_LENGTH,
  parseOnboardingResponse
} from '../../src/enrollment/index.js'
import type { EnrollmentRequest } from '../../src/enrollment/index.js'

/**
 * The same fixed request the enrollment tests use: four real Ed25519 / X25519
 * public multibases, since the connect-code parser decodes every one of them.
 */
const FIXED_REQUEST: EnrollmentRequest = {
  signingKeyMultibase: 'z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX',
  keyAgreementKeyMultibase: 'z6LSi9ig66fZi18Mk7mwkb5TPBY6bT4CstAAQi4cE6bED5bV',
  updateKeyMultibase: 'z6MkvRXNYcE7MMduynWTgeKbDaT1iijDSC8pZqXZc8rHPrf2',
  stagedUpdateKeyMultibase: 'z6Mkt6316e2PN3mZdB6N9CrzomJYUd1s5yBZi1XYHmwT9TUP'
}

const CODE = encodeEnrollmentRequest({ request: FIXED_REQUEST })

const onboardingQuery = (host: unknown) =>
  ({ type: 'WalletOnboardingQuery', host }) as never as IVPRQuery

describe('composeWalletOnboardingRequest', () => {
  it('composes a single-query VPR body', () => {
    expect(
      composeWalletOnboardingRequest({ host: 'https://was.example' })
    ).toEqual({
      query: [{ type: 'WalletOnboardingQuery', host: 'https://was.example/' }]
    })
  })

  it('stores the serialized host', () => {
    const request = composeWalletOnboardingRequest({
      host: 'https://was.example:443/a/../storage'
    })
    expect(queriesOf(request)).toEqual([
      {
        type: 'WalletOnboardingQuery',
        host: 'https://was.example/storage'
      }
    ])
  })

  it('throws on a relative host', () => {
    expect(() => composeWalletOnboardingRequest({ host: '/storage' })).toThrow(
      /must be an absolute URL/
    )
  })

  it('throws on a non-http(s) host', () => {
    expect(() =>
      composeWalletOnboardingRequest({ host: 'ftp://was.example' })
    ).toThrow(/must be an http\(s\) URL/)
  })

  it('throws on a host carrying a fragment', () => {
    expect(() =>
      composeWalletOnboardingRequest({ host: 'https://was.example/#frag' })
    ).toThrow(/must not carry a fragment/)
    expect(() =>
      composeWalletOnboardingRequest({ host: 'https://was.example/#' })
    ).toThrow(/must not carry a fragment/)
  })
})

describe('serializedOnboardingHost', () => {
  it('normalizes the default port, dot segments, and the empty path', () => {
    expect(serializedOnboardingHost({ host: 'https://was.example' })).toBe(
      'https://was.example/'
    )
    expect(
      serializedOnboardingHost({ host: 'http://was.example:80/a/./b/../c' })
    ).toBe('http://was.example/a/c')
  })
})

describe('walletOnboardingRequestOf', () => {
  it('returns null when no WalletOnboardingQuery is present', () => {
    expect(
      walletOnboardingRequestOf({ queries: [{ type: 'DIDAuthentication' }] })
    ).toBeNull()
  })

  it('classifies a valid query, serializing the host', () => {
    expect(
      walletOnboardingRequestOf({
        queries: [onboardingQuery('https://was.example:443/storage')]
      })
    ).toEqual({ host: 'https://was.example/storage' })
  })

  it('throws on more than one WalletOnboardingQuery', () => {
    const query = onboardingQuery('https://was.example')
    expect(() =>
      walletOnboardingRequestOf({ queries: [query, query] })
    ).toThrow(/More than one WalletOnboardingQuery/)
  })

  it('throws on a missing or non-string host', () => {
    for (const host of [undefined, null, 42, { href: 'https://was.example' }]) {
      expect(() =>
        walletOnboardingRequestOf({ queries: [onboardingQuery(host)] })
      ).toThrow(/missing its host/)
    }
  })

  it('throws on a host violating the URL rules', () => {
    for (const host of [
      '/storage',
      'ftp://was.example',
      'https://was.example/#frag'
    ]) {
      expect(() =>
        walletOnboardingRequestOf({ queries: [onboardingQuery(host)] })
      ).toThrow()
    }
  })

  it('throws when combined with another consent-bearing query type', () => {
    const query = onboardingQuery('https://was.example')
    const others: IVPRQuery[] = [
      { type: 'QueryByExample', credentialQuery: [] } as never as IVPRQuery,
      {
        type: 'AuthorizationCapabilityQuery',
        capabilityQuery: [{ invocationTarget: 'https://was.example/space/1' }]
      } as never as IVPRQuery,
      {
        type: 'AppConnectQuery',
        app: { name: 'Notes', appUrl: 'https://app.example/' }
      } as never as IVPRQuery
    ]
    for (const other of others) {
      expect(() =>
        walletOnboardingRequestOf({ queries: [query, other] })
      ).toThrow(/cannot be combined with/)
    }
  })
})

describe('appConnectRequestOf, meeting a WalletOnboardingQuery', () => {
  it('refuses the mixture from its own side too', () => {
    expect(() =>
      appConnectRequestOf({
        queries: [
          {
            type: 'AppConnectQuery',
            app: { name: 'Notes', appUrl: 'https://app.example/' }
          } as never as IVPRQuery,
          onboardingQuery('https://was.example')
        ],
        origin: 'https://app.example'
      })
    ).toThrow(/cannot be combined with/)
  })
})

describe('a wallet that predates the query type', () => {
  it('finds nothing it can satisfy, and so refuses rather than degrading', () => {
    const profile = classifyRequest(
      composeWalletOnboardingRequest({ host: 'https://was.example' })
    )
    expect(profile).toEqual({ didAuth: false, vcQueries: [], zcapRequests: [] })
  })
})

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
