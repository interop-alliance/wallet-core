/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Issuer display derivation. Ported from DCW `issuerRenderInfo.test.ts` (the
 * `registered_issuer` verification log is fed as a plain object instead of
 * `validate.ts` types) and Freewallet `issuerName.test.ts`.
 */
import { describe, it, expect } from 'vitest'
import {
  issuerName,
  getIssuerDetails,
  issuerRenderInfoFrom,
  issuerRenderInfoWithVerification,
  personNameFromCredential
} from '../../src/display/index.js'

const registeredIssuerLog = (matchingIssuers: unknown[]) => ({
  log: [{ id: 'registered_issuer', matchingIssuers }]
})

describe('issuerRenderInfoWithVerification', () => {
  it('uses federation_entity registry metadata when the issuer matches', () => {
    const verifyResult = registeredIssuerLog([
      {
        issuer: {
          federation_entity: {
            organization_name: 'MIT',
            homepage_uri: 'https://mit.edu'
          }
        }
      }
    ])
    expect(
      issuerRenderInfoWithVerification('did:key:zABC', verifyResult as never)
    ).toEqual({
      issuerName: 'MIT',
      issuerUrl: 'https://mit.edu',
      issuerId: null,
      issuerImage: null
    })
  })

  it('reads issuerId and issuerImage from an object issuer in the match branch', () => {
    const verifyResult = registeredIssuerLog([
      {
        issuer: {
          federation_entity: {
            organization_name: 'MIT',
            homepage_uri: 'https://mit.edu'
          }
        }
      }
    ])
    const issuer = {
      id: 'did:web:mit.edu',
      name: 'MIT',
      image: 'https://mit.edu/img.png'
    }
    const info = issuerRenderInfoWithVerification(
      issuer as never,
      verifyResult as never
    )
    expect(info.issuerName).toBe('MIT')
    expect(info.issuerId).toBe('did:web:mit.edu')
    expect(info.issuerImage).toBe('https://mit.edu/img.png')
  })

  it('falls back to the credential issuer when there is no verification match', () => {
    const issuer = {
      id: 'did:web:acme',
      name: 'Acme',
      url: 'https://acme.com',
      image: 'https://acme.com/logo.png'
    }
    expect(issuerRenderInfoWithVerification(issuer as never)).toEqual({
      issuerName: 'Acme',
      issuerUrl: 'https://acme.com',
      issuerId: 'did:web:acme',
      issuerImage: 'https://acme.com/logo.png'
    })
  })

  it('overrides the name with the SkillClaim person name and uses logo_uri', () => {
    const credential = {
      type: ['VerifiableCredential', 'SkillClaimCredential'],
      credentialSubject: { person: { name: 'Jane Doe' } }
    }
    const verifyResult = registeredIssuerLog([
      {
        issuer: {
          federation_entity: {
            organization_name: 'MIT',
            homepage_uri: 'https://mit.edu',
            logo_uri: 'https://mit.edu/logo.png'
          }
        }
      }
    ])
    const info = issuerRenderInfoWithVerification(
      'did:key:z',
      verifyResult as never,
      credential as never
    )
    expect(info.issuerName).toBe('Jane Doe')
    expect(info.issuerImage).toBe('https://mit.edu/logo.png')
  })
})

describe('issuerRenderInfoFrom', () => {
  it('returns the DID string as the name for a string issuer', () => {
    expect(issuerRenderInfoFrom('did:key:zXYZ')).toEqual({
      issuerName: 'did:key:zXYZ',
      issuerUrl: null,
      issuerId: null,
      issuerImage: null
    })
  })

  it('reads name/url/id/image from an object issuer', () => {
    const issuer = {
      id: 'did:web:acme',
      name: 'Acme',
      url: 'https://acme.com',
      image: 'https://acme.com/logo.png'
    }
    expect(issuerRenderInfoFrom(issuer as never)).toEqual({
      issuerName: 'Acme',
      issuerUrl: 'https://acme.com',
      issuerId: 'did:web:acme',
      issuerImage: 'https://acme.com/logo.png'
    })
  })
})

describe('personNameFromCredential', () => {
  it('returns the credentialSubject.person.name', () => {
    expect(
      personNameFromCredential({
        type: ['SkillClaimCredential'],
        credentialSubject: { person: { name: 'Bob' } }
      } as never)
    ).toBe('Bob')
  })

  it('returns null when there is no person name', () => {
    expect(
      personNameFromCredential({
        type: ['VerifiableCredential'],
        credentialSubject: {}
      } as never)
    ).toBeNull()
  })

  it('returns null when no credential is provided', () => {
    expect(personNameFromCredential()).toBeNull()
  })
})

describe('issuerName / getIssuerDetails', () => {
  it('returns a string issuer directly', () => {
    expect(issuerName({ issuer: 'did:web:example.edu' } as never)).toBe(
      'did:web:example.edu'
    )
  })

  it('prefers the issuer name for an object issuer', () => {
    expect(
      issuerName({
        issuer: { id: 'did:web:example.edu', name: 'Example University' }
      } as never)
    ).toBe('Example University')
  })

  it('falls back to the issuer id, then Unknown Issuer', () => {
    expect(issuerName({ issuer: { id: 'did:web:example.edu' } } as never)).toBe(
      'did:web:example.edu'
    )
    expect(issuerName({ issuer: {} } as never)).toBe('Unknown Issuer')
  })

  it('maps a string issuer to an id-only detail record', () => {
    expect(getIssuerDetails('did:web:example.edu')).toEqual({
      id: 'did:web:example.edu',
      name: '',
      url: '',
      image: ''
    })
  })

  it('extracts the image id from an object image', () => {
    expect(
      getIssuerDetails({
        id: 'did:web:example.edu',
        image: { id: 'https://example.edu/logo.png' }
      } as never).image
    ).toBe('https://example.edu/logo.png')
  })
})
