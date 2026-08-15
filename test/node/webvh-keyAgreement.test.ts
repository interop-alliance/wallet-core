/**
 * Unit tests for the shared reference-resolving `keyAgreement` reader both the
 * client listing's marker filter and the user key roster's recipient resolver
 * are built over: a string reference resolved against `verificationMethod`, a
 * reference nothing backs dropped, an embedded method taken verbatim, and
 * document order preserved across the mixture.
 */
import { describe, expect, it } from 'vitest'
import { resolvedKeyAgreementMethods } from '../../src/webvh/keyAgreement.js'

const DID = 'did:webvh:QmScid:example.com:space:abc:id'

describe('resolvedKeyAgreementMethods', () => {
  it('resolves a string reference against verificationMethod', () => {
    const methods = resolvedKeyAgreementMethods({
      doc: {
        verificationMethod: [
          {
            id: `${DID}#zRef`,
            controller: `did:key:zSigning`,
            publicKeyMultibase: 'zRef'
          }
        ],
        keyAgreement: [`${DID}#zRef`]
      }
    })
    expect(methods).toEqual([
      {
        id: `${DID}#zRef`,
        controller: 'did:key:zSigning',
        publicKeyMultibase: 'zRef'
      }
    ])
  })

  it('drops a reference no verification method backs', () => {
    const methods = resolvedKeyAgreementMethods({
      doc: {
        verificationMethod: [
          { id: `${DID}#zOther`, publicKeyMultibase: 'zOther' }
        ],
        keyAgreement: [`${DID}#zMissing`]
      }
    })
    expect(methods).toEqual([])
  })

  it('takes an embedded method verbatim', () => {
    const embedded = {
      id: `${DID}#zEmbedded`,
      controller: 'did:key:zSigning',
      publicKeyMultibase: 'zEmbedded'
    }
    const methods = resolvedKeyAgreementMethods({
      doc: { keyAgreement: [embedded] }
    })
    expect(methods).toEqual([embedded])
  })

  it('preserves document order across references and embedded methods', () => {
    const methods = resolvedKeyAgreementMethods({
      doc: {
        verificationMethod: [
          { id: `${DID}#zFirst`, publicKeyMultibase: 'zFirst' }
        ],
        keyAgreement: [
          `${DID}#zFirst`,
          { id: `${DID}#zSecond`, publicKeyMultibase: 'zSecond' },
          `${DID}#zMissing`
        ]
      }
    })
    expect(methods.map(method => method.publicKeyMultibase)).toEqual([
      'zFirst',
      'zSecond'
    ])
  })

  it('reads an absent keyAgreement relation as no methods', () => {
    expect(resolvedKeyAgreementMethods({ doc: {} })).toEqual([])
  })
})
