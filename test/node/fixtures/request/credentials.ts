/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Shared credential fixtures for the request-* suites. `mockCredential` is a
 * VC 1.0 signed credential (ported from DCW's `app/mock/credential`, trimmed of
 * its embedded issuer image); `mockCredentialV2` is its VC 2.0 variant. The
 * `universityCredential` / `employmentCredential` pair exercises the
 * QueryByExample matchers (nested-object issuer vs. string issuer).
 */
import type { IVerifiableCredential } from '../../../../src/request/index.js'

const ISSUER_DID = 'did:key:z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC'

/** A VC 1.0 credential with an Ed25519Signature2020 proof. */
export const mockCredential: IVerifiableCredential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://w3id.org/security/suites/ed25519-2020/v1',
    'https://w3id.org/dcc/v1',
    'https://w3id.org/vc/status-list/2021/v1'
  ],
  type: ['VerifiableCredential', 'Assertion'],
  issuer: {
    id: ISSUER_DID,
    name: 'Example University',
    url: 'https://cs.example.edu'
  },
  issuanceDate: '2020-08-16T12:00:00.000+00:00',
  credentialSubject: {
    id: ISSUER_DID,
    name: 'Kayode Ezike',
    hasCredential: {
      type: ['EducationalOccupationalCredential'],
      name: 'GT Guide',
      description:
        'The holder of this credential is qualified to lead new student ' +
        'orientations.'
    }
  },
  expirationDate: '2025-08-16T12:00:00.000+00:00',
  credentialStatus: {
    id: 'https://digitalcredentials.github.io/credential-status-playground/JWZM3H8WKU#2',
    type: 'StatusList2021Entry',
    statusPurpose: 'revocation',
    statusListIndex: 2,
    statusListCredential:
      'https://digitalcredentials.github.io/credential-status-playground/JWZM3H8WKU'
  },
  proof: {
    type: 'Ed25519Signature2020',
    created: '2022-08-19T06:55:17Z',
    verificationMethod: `${ISSUER_DID}#${ISSUER_DID.slice('did:key:'.length)}`,
    proofPurpose: 'assertionMethod',
    proofValue:
      'z4EiTbmC79r4dRaqLQZr2yxQASoMKneHVNHVaWh1xcDoPG2eTwYjKoYaku1Canb7a6Xp5fSogKJyEhkZCaqQ6Y5nw'
  }
} as IVerifiableCredential

/** A VC 2.0 variant of {@link mockCredential} (no proof; used for wrapping). */
export const mockCredentialV2: IVerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'Assertion'],
  issuer: ISSUER_DID,
  validFrom: '2020-08-16T12:00:00.000+00:00',
  credentialSubject: {
    id: ISSUER_DID,
    name: 'Kayode Ezike'
  }
} as IVerifiableCredential

/** A university-issued VC whose issuer is a nested `{ id, name }` object. */
export const universityCredential: IVerifiableCredential = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'Assertion'],
  issuer: { id: 'did:key:university', name: 'Example University' },
  credentialSubject: { id: 'did:key:holder', name: 'Kayode' }
} as IVerifiableCredential

/** An employment VC whose issuer is a bare DID string. */
export const employmentCredential: IVerifiableCredential = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential', 'EmploymentCredential'],
  issuer: 'did:key:employer',
  credentialSubject: { id: 'did:key:holder', role: 'co founder' }
} as IVerifiableCredential
