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

/** The account the inviter is onboarding another wallet onto. */
const ACCOUNT_DID = 'did:webvh:QmZ4tDuvesekSs4qM5JBGwjJHfxpTBEjLE:was.example'
const SPACE_ID = 'urn:uuid:8f2c1d9a-3b6e-4a1f-9d0c-52b7e6a1c4d3'
const CONTROLLER = 'did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX'

const POINTER = {
  did: ACCOUNT_DID,
  spaceId: SPACE_ID,
  host: 'https://was.example'
}

const onboardingQuery = (members: Record<string, unknown>) =>
  ({
    type: 'WalletOnboardingQuery',
    did: ACCOUNT_DID,
    spaceId: SPACE_ID,
    controller: CONTROLLER,
    host: 'https://was.example',
    ...members
  }) as never as IVPRQuery

describe('composeWalletOnboardingRequest', () => {
  it('composes a single-query VPR body', () => {
    expect(
      composeWalletOnboardingRequest({
        pointer: POINTER,
        controller: CONTROLLER
      })
    ).toEqual({
      query: [
        {
          type: 'WalletOnboardingQuery',
          host: 'https://was.example/',
          did: ACCOUNT_DID,
          spaceId: SPACE_ID,
          controller: CONTROLLER
        }
      ]
    })
  })

  it('stores the serialized host', () => {
    const request = composeWalletOnboardingRequest({
      pointer: { ...POINTER, host: 'https://was.example:443/a/../storage' },
      controller: CONTROLLER
    })
    expect(queriesOf(request)).toEqual([
      {
        type: 'WalletOnboardingQuery',
        host: 'https://was.example/storage',
        did: ACCOUNT_DID,
        spaceId: SPACE_ID,
        controller: CONTROLLER
      }
    ])
  })

  it('round-trips the pointer and controller through classification', () => {
    const request = composeWalletOnboardingRequest({
      pointer: POINTER,
      controller: CONTROLLER
    })
    expect(walletOnboardingRequestOf({ queries: queriesOf(request) })).toEqual({
      host: 'https://was.example/',
      did: ACCOUNT_DID,
      spaceId: SPACE_ID,
      controller: CONTROLLER
    })
  })

  it('throws on a pointer carrying no did, or a non-webvh one', () => {
    for (const did of [undefined, '', CONTROLLER, 'did:web:was.example']) {
      expect(() =>
        composeWalletOnboardingRequest({
          pointer: { ...POINTER, did },
          controller: CONTROLLER
        })
      ).toThrow(/must be the account's did:webvh id/)
    }
  })

  it('throws on an empty spaceId', () => {
    expect(() =>
      composeWalletOnboardingRequest({
        pointer: { ...POINTER, spaceId: '' },
        controller: CONTROLLER
      })
    ).toThrow(/"spaceId" must be a non-empty string/)
  })

  it('throws on a missing or non-did:key controller', () => {
    for (const controller of ['', 'did:webvh:abc:was.example', 'nonsense']) {
      expect(() =>
        composeWalletOnboardingRequest({ pointer: POINTER, controller })
      ).toThrow(/"controller" must be a did:key string/)
    }
  })

  it('throws on a relative host', () => {
    expect(() =>
      composeWalletOnboardingRequest({
        pointer: { ...POINTER, host: '/storage' },
        controller: CONTROLLER
      })
    ).toThrow(/must be an absolute URL/)
  })

  it('throws on a non-http(s) host', () => {
    expect(() =>
      composeWalletOnboardingRequest({
        pointer: { ...POINTER, host: 'ftp://was.example' },
        controller: CONTROLLER
      })
    ).toThrow(/must be an http\(s\) URL/)
  })

  it('throws on a host carrying a fragment', () => {
    for (const host of ['https://was.example/#frag', 'https://was.example/#']) {
      expect(() =>
        composeWalletOnboardingRequest({
          pointer: { ...POINTER, host },
          controller: CONTROLLER
        })
      ).toThrow(/must not carry a fragment/)
    }
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
        queries: [onboardingQuery({ host: 'https://was.example:443/storage' })]
      })
    ).toEqual({
      host: 'https://was.example/storage',
      did: ACCOUNT_DID,
      spaceId: SPACE_ID,
      controller: CONTROLLER
    })
  })

  it('throws on a legacy host-only query', () => {
    expect(() =>
      walletOnboardingRequestOf({
        queries: [
          {
            type: 'WalletOnboardingQuery',
            host: 'https://was.example'
          } as never as IVPRQuery
        ]
      })
    ).toThrow(/must be the account's did:webvh id/)
  })

  it('throws on a missing or non-webvh did', () => {
    for (const did of [undefined, null, 42, CONTROLLER]) {
      expect(() =>
        walletOnboardingRequestOf({ queries: [onboardingQuery({ did })] })
      ).toThrow(/must be the account's did:webvh id/)
    }
  })

  it('throws on a missing or empty spaceId', () => {
    for (const spaceId of [undefined, null, '', 42]) {
      expect(() =>
        walletOnboardingRequestOf({ queries: [onboardingQuery({ spaceId })] })
      ).toThrow(/"spaceId" must be a non-empty string/)
    }
  })

  it('throws on a missing or non-did:key controller', () => {
    for (const controller of [undefined, null, 42, ACCOUNT_DID]) {
      expect(() =>
        walletOnboardingRequestOf({
          queries: [onboardingQuery({ controller })]
        })
      ).toThrow(/"controller" must be a did:key string/)
    }
  })

  it('throws on more than one WalletOnboardingQuery', () => {
    const query = onboardingQuery({})
    expect(() =>
      walletOnboardingRequestOf({ queries: [query, query] })
    ).toThrow(/More than one WalletOnboardingQuery/)
  })

  it('throws on a missing or non-string host', () => {
    for (const host of [undefined, null, 42, { href: 'https://was.example' }]) {
      expect(() =>
        walletOnboardingRequestOf({ queries: [onboardingQuery({ host })] })
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
        walletOnboardingRequestOf({ queries: [onboardingQuery({ host })] })
      ).toThrow()
    }
  })

  it('throws when combined with another consent-bearing query type', () => {
    const query = onboardingQuery({})
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
          onboardingQuery({})
        ],
        origin: 'https://app.example'
      })
    ).toThrow(/cannot be combined with/)
  })
})

describe('a wallet that predates the query type', () => {
  it('finds nothing it can satisfy, and so refuses rather than degrading', () => {
    const profile = classifyRequest(
      composeWalletOnboardingRequest({
        pointer: POINTER,
        controller: CONTROLLER
      })
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
