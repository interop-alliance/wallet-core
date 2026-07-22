/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared display fixtures for the cross-app disagreement cases where DCW and
 * Freewallet historically produced different titles / recipients. Pinning them
 * here keeps both the merged `credentialName` and `extractIssuedTo` behaviors in
 * one place. Also carries the two named fixtures the Freewallet suites used
 * (`welcomeCredential`) and the DCW alignment mock (`mockOpenBadgeWithAlignments`).
 */
import type { IVerifiableCredential } from '@interop/data-integrity-core'

/** A simple VC named only by its top-level `name`. */
export const welcomeCredential: IVerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  name: 'Your First Credential',
  credentialSubject: {
    description: 'You have successfully set up your credentials wallet!'
  },
  issuer: 'did:web:interopalliance.org'
}

/** OBv3 VC whose subject carries MULTIPLE achievements (DCW took the first, Freewallet joins). */
export const multiAchievementCredential: IVerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'OpenBadgeCredential'],
  issuer: 'did:web:issuer.example',
  credentialSubject: {
    achievement: [{ name: 'First Achievement' }, { name: 'Second Achievement' }]
  }
}

/** Subject recipient carried in the nested `person.contact.fullName` (Freewallet resolves it, DCW missed it). */
export const personContactFullNameCredential: IVerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:web:issuer.example',
  credentialSubject: {
    person: { contact: { fullName: 'Ada Lovelace' } }
  }
}

/** OBv3 identifier holding a NON-name hash (DCW returned it as the name, Freewallet skips it). */
export const obv3NonNameIdentifierCredential: IVerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'OpenBadgeCredential'],
  issuer: 'did:web:issuer.example',
  credentialSubject: {
    identifier: [
      { hashed: false, identityType: 'emailAddress', identityHash: 'a@b.co' }
    ]
  }
}

/** A resume credential (subject `type` includes `'Resume'`). */
export const resumeCredential: IVerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:web:issuer.example',
  credentialSubject: {
    type: ['Resume'],
    person: { name: 'Grace Hopper' }
  }
}

/** A SkillClaimCredential (title falls back to the skill name / 'Skill Claim'). */
export const skillClaimCredential: IVerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'SkillClaimCredential'],
  issuer: 'did:web:issuer.example',
  credentialSubject: {
    person: { name: 'Jane Doe' },
    skill: [{ name: 'Welding' }]
  }
}

/** DCW OBv3 mock with a mix of valid / invalid alignments (for URL validation). */
export const mockOpenBadgeWithAlignments: IVerifiableCredential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'
  ],
  id: 'http://example.edu/credentials/3732',
  type: ['VerifiableCredential', 'OpenBadgeCredential'],
  issuer: {
    id: 'https://example.edu/issuers/565049',
    name: 'Example University'
  },
  validFrom: '2010-01-01T00:00:00Z',
  name: 'Example University Degree',
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    achievement: {
      id: 'https://1edtech.edu/achievements/1',
      type: ['Achievement'],
      criteria: { type: 'Criteria', narrative: 'Analyze a sample text' },
      description: 'Analyze a sample text',
      name: 'Text analysis',
      alignment: [
        {
          type: ['Alignment'],
          targetCode: 'ce-cf4dee18-7cea-443a-b920-158a0762c6bf',
          targetFramework: 'Edmonds College Course Catalog',
          targetName: 'Requirements Analysis',
          targetUrl:
            'https://credentialfinder.org/credential/20229/Requirements_Analysis'
        },
        {
          type: ['Alignment'],
          targetName: 'Requirements Analysis with Description',
          targetUrl:
            'https://credentialfinder.org/credential/20229/Requirements_Analysis',
          targetDescription: 'This is a description'
        },
        {
          type: ['Alignment'],
          targetName: 'Invalid - No URL'
        },
        {
          type: ['Alignment'],
          targetName: 'Invalid URL',
          targetUrl: 'not-a-valid-url'
        }
      ]
    }
  }
}
