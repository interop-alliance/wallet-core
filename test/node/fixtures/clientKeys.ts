/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Canonical client key pairs for the did:webvh tests: real Ed25519 signing
 * keys with their real X25519 twins.
 *
 * Every site that writes the controller marker builds through
 * `markedVerificationMethodPair`, which refuses a key-agreement key that is
 * not the signing key's canonical twin, so a test that publishes a client
 * needs a genuinely twinned pair rather than a readable placeholder. The pairs
 * are derived once from fixed seeds (`wallet-core/test/client/<n>`) and pinned
 * here so the test modules stay synchronous.
 */
export const CANONICAL_CLIENT_KEYS = [
  {
    signingKeyMultibase: 'z6MkqEsRdSXonu2cLjPHv4U5bbKkiTz62nRFgKzBHBKJGsdX',
    keyAgreementKeyMultibase: 'z6LStrgBTZ4ikurpU18TSXkRvEG69h63ion5GLjjfkLGRSW2'
  },
  {
    signingKeyMultibase: 'z6Mkq2wxPGE59ohoTYbMRYd82vHiyNwXq1S9Z43BHxM8PxDt',
    keyAgreementKeyMultibase: 'z6LSjfqSAs73PuUJMkXtNpdPQrwqSfaTVYPFKcF1MRV27QGb'
  },
  {
    signingKeyMultibase: 'z6Mkqo4jjriQXgFjCuaErtKhL3R9GBa7dY6SvzyrWLPskeFx',
    keyAgreementKeyMultibase: 'z6LSomNDdnwwUCQJXvCYrepBGhP8bALu1Ab5R9vUsGj9dHk6'
  },
  {
    signingKeyMultibase: 'z6Mkt1dENVc9tJtndK9Rso2ieqFzA5g7gDHgVLdnyfZ6BU5f',
    keyAgreementKeyMultibase: 'z6LSm3kZVqjhvZb667dVafcFCt1oCehuoGgY3RETrxNfSHZ7'
  },
  {
    signingKeyMultibase: 'z6MkjP6oytG6iPrviMJiiFoPJF9XDU6tUmme7Ugokh8YqNSo',
    keyAgreementKeyMultibase: 'z6LSkae7r4s4LLaYDjykGRtFbxVwV6GsxmL6bLXGnGVwyEa4'
  },
  {
    signingKeyMultibase: 'z6Mku27tbx9Ai1iFnVCq9ymgCJLhDrx9zubawrpAyHQNYjb6',
    keyAgreementKeyMultibase: 'z6LSfFhWGqeCho1Sw3qoug6g2qDYk7NSBXVHZJocsFaewWYV'
  },
  {
    signingKeyMultibase: 'z6Mki4qqMKPdAPwVPusFTu99aa21MWvPVCq9dFaKom4VeatW',
    keyAgreementKeyMultibase: 'z6LSqvGaxpDxdP7nQRjuiZoxPvbjmti8YVLDsY5SB23nP5mh'
  },
  {
    signingKeyMultibase: 'z6MkiwF1HbnUmCrVPKw17ucbg33NB5UaYTexvW5LhAMwqMMJ',
    keyAgreementKeyMultibase: 'z6LStWcH3q41eg7FUeYv7GRqiVuEfjPYHhhbtVhW7wMZX9GR'
  },
  {
    signingKeyMultibase: 'z6Mkiisg2K5HSvJSfwLf3kipchFCSrQtNLWhwYAgZmgtJJMa',
    keyAgreementKeyMultibase: 'z6LScfFVAbNtpXo8wf61mqFhAc67s7pZCByaVaJwQCYUVit7'
  },
  {
    signingKeyMultibase: 'z6MkrVH7DeV4Fx7TaBYkDFkoixbsDb8seXAk1XYYbcz4RHKV',
    keyAgreementKeyMultibase: 'z6LSrvfkPrKNnu3hpimNH6rTepYd8BenuZvCs67HYbEk2ydr'
  },
  {
    signingKeyMultibase: 'z6MkrzcgD9yjqXSAL7DRJxiHLXEC2FFfKMRB2LS2AbnD2ngD',
    keyAgreementKeyMultibase: 'z6LSrKpGxjyq7DtJptjreiw6iAD2KdMpj5NvgKUkUoqHhMLT'
  },
  {
    signingKeyMultibase: 'z6MkhxpxHe5TbZ9ppUphVZAQ2YEHLyuduMmEaBDitX7SpytR',
    keyAgreementKeyMultibase: 'z6LSqc5JsDn4opb9qdrbMzeTXdtoNrEDrs58AsYzy4kSQJYr'
  }
] as const
