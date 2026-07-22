/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Cryptosuite negotiation (`negotiateCryptosuite`) and proof-suite construction
 * (`presentationSuiteFor`). `negotiateCryptosuite` decides which cryptosuite the
 * wallet signs with -- honoring a verifier's `acceptedCryptosuites` (in both the
 * VCALM `{ cryptosuite }` object form and the bare-string form, and stated on
 * the query or its individual `credentialQuery` details), or inferring VC 2.0
 * from a QueryByExample. A real Ed25519 signer is generated for the
 * suite-builder cases. Ported from DCW `presentationSuite.test.ts` /
 * `vcApi.test.ts` plus Freewallet's per-detail cases.
 */
import { describe, it, expect } from 'vitest'
import {
  EDDSA_RDFC_2022,
  negotiateCryptosuite,
  presentationSuiteFor
} from '../../src/request/index.js'
import type { IVPRQuery } from '../../src/request/index.js'
import { makeSigner } from './fixtures/request/signer.js'

const CREDENTIALS_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2'
const CREDENTIALS_CONTEXT_V1 = 'https://www.w3.org/2018/credentials/v1'

describe('negotiateCryptosuite', () => {
  it('honors an explicit supported acceptedCryptosuites entry (object form)', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'DIDAuthentication',
        acceptedCryptosuites: [{ cryptosuite: EDDSA_RDFC_2022 }]
      }
    ]
    expect(negotiateCryptosuite(queries)).toBe(EDDSA_RDFC_2022)
  })

  it('honors a bare-string acceptedCryptosuites entry', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'DIDAuthentication',
        acceptedCryptosuites: ['ecdsa-rdfc-2019', EDDSA_RDFC_2022]
      }
    ]
    expect(negotiateCryptosuite(queries)).toBe(EDDSA_RDFC_2022)
  })

  it('reads acceptedCryptosuites from a per-credentialQuery detail', () => {
    // What vcplayground.org sends: the preference lives on each credentialQuery
    // detail, as bare strings, not on the enclosing query.
    const queries: IVPRQuery[] = [
      {
        type: 'QueryByExample',
        credentialQuery: [
          {
            example: { type: ['VerifiableCredential'] },
            acceptedCryptosuites: ['Ed25519Signature2020', EDDSA_RDFC_2022]
          }
        ]
      }
    ]
    expect(negotiateCryptosuite(queries)).toBe(EDDSA_RDFC_2022)
  })

  it('picks the first supported suite in the verifier-stated order', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'DIDAuthentication',
        acceptedCryptosuites: [
          { cryptosuite: 'unsupported-suite' },
          { cryptosuite: EDDSA_RDFC_2022 }
        ]
      }
    ]
    expect(negotiateCryptosuite(queries)).toBe(EDDSA_RDFC_2022)
  })

  it('returns undefined when the verifier lists only unsupported suites', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'DIDAuthentication',
        acceptedCryptosuites: [{ cryptosuite: 'ecdsa-rdfc-2019' }]
      }
    ]
    expect(negotiateCryptosuite(queries)).toBeUndefined()
  })

  it('infers eddsa-rdfc-2022 from a VC 2.0 QueryByExample when no preference is stated', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'QueryByExample',
        credentialQuery: {
          example: {
            '@context': [CREDENTIALS_CONTEXT_V2],
            type: ['VerifiableCredential']
          }
        }
      }
    ]
    expect(negotiateCryptosuite(queries)).toBe(EDDSA_RDFC_2022)
  })

  it('returns undefined for a VC 1.0 QueryByExample with no preference', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'QueryByExample',
        credentialQuery: {
          example: {
            '@context': [CREDENTIALS_CONTEXT_V1],
            type: ['VerifiableCredential']
          }
        }
      }
    ]
    expect(negotiateCryptosuite(queries)).toBeUndefined()
  })

  it('honors a string @context that is the VC 2.0 url', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'QueryByExample',
        credentialQuery: { example: { '@context': CREDENTIALS_CONTEXT_V2 } }
      }
    ]
    expect(negotiateCryptosuite(queries)).toBe(EDDSA_RDFC_2022)
  })

  it('lets an explicit acceptedCryptosuites override the example heuristic', () => {
    const queries: IVPRQuery[] = [
      {
        type: 'QueryByExample',
        acceptedCryptosuites: [{ cryptosuite: 'ecdsa-rdfc-2019' }],
        credentialQuery: {
          example: {
            '@context': [CREDENTIALS_CONTEXT_V2],
            type: 'PermanentResidentCard'
          }
        }
      }
    ]
    expect(negotiateCryptosuite(queries)).toBeUndefined()
  })

  it('returns undefined for an empty query list', () => {
    expect(negotiateCryptosuite([])).toBeUndefined()
  })
})

describe('presentationSuiteFor', () => {
  it('builds a DataIntegrityProof at VC 2.0 for eddsa-rdfc-2022', async () => {
    const signer = await makeSigner()
    const { suite, version } = presentationSuiteFor({
      signer,
      cryptosuite: EDDSA_RDFC_2022
    })
    expect(version).toBe(2.0)
    expect((suite as { type: string }).type).toBe('DataIntegrityProof')
  })

  it('falls back to Ed25519Signature2020 at VC 1.0 when no cryptosuite is given', async () => {
    const signer = await makeSigner()
    const { suite, version } = presentationSuiteFor({ signer })
    expect(version).toBe(1.0)
    expect((suite as { type: string }).type).toBe('Ed25519Signature2020')
  })

  it('falls back to the default for an unrecognized cryptosuite', async () => {
    const signer = await makeSigner()
    const { suite, version } = presentationSuiteFor({
      signer,
      cryptosuite: 'something-else'
    })
    expect(version).toBe(1.0)
    expect((suite as { type: string }).type).toBe('Ed25519Signature2020')
  })
})
