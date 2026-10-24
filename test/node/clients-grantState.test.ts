/**
 * Unit tests for the grant-state check (`src/clients/grantState.ts`): an
 * enrolled client's signer is judged against the account document under
 * either id form, and a client-annex per-visit signer, which the document
 * never lists, derives as unknown rather than orphaned.
 */
import { describe, expect, it } from 'vitest'
import { deriveGrantSignerState } from '../../src/clients/grantState.js'

const ACCOUNT_DID = 'did:webvh:scid:host:space:s:id'
const ANNEX_DID = 'did:webvh:annexscid:host:space:gen-1:id'

/**
 * The verified document: one enrolled client's key, `zKey`, under
 * `capabilityDelegation`.
 */
const doc = {
  verificationMethod: [
    { id: `${ACCOUNT_DID}#zKey`, publicKeyMultibase: 'zKey' }
  ],
  capabilityDelegation: [`${ACCOUNT_DID}#zKey`]
}

describe('deriveGrantSignerState', () => {
  it('is unknown without a verified document to check against', () => {
    expect(
      deriveGrantSignerState({
        signerKeyIds: [`${ACCOUNT_DID}#zKey`],
        accountDid: ACCOUNT_DID
      })
    ).toBe('unknown')
  })

  it('is unknown when no grant recorded a signer', () => {
    expect(
      deriveGrantSignerState({
        signerKeyIds: [undefined],
        accountDid: ACCOUNT_DID,
        doc
      })
    ).toBe('unknown')
  })

  it('is active when a signer is listed under capabilityDelegation', () => {
    expect(
      deriveGrantSignerState({
        signerKeyIds: [`${ACCOUNT_DID}#zGone`, `${ACCOUNT_DID}#zKey`],
        accountDid: ACCOUNT_DID,
        doc
      })
    ).toBe('active')
  })

  it('matches the did:key form of a still-enrolled key', () => {
    expect(
      deriveGrantSignerState({
        signerKeyIds: ['did:key:zKey#zKey'],
        accountDid: ACCOUNT_DID,
        doc
      })
    ).toBe('active')
  })

  it('is orphaned when no account-form signer is listed', () => {
    expect(
      deriveGrantSignerState({
        signerKeyIds: [`${ACCOUNT_DID}#zGone`, 'did:key:zOld#zOld'],
        accountDid: ACCOUNT_DID,
        doc
      })
    ).toBe('orphaned')
  })

  it('does not judge a did:key signer whose fragment names another key as active', () => {
    // `did:key:zX#zKey` is not the did:key form of `zKey`: the DID names a
    // different key, so the id resolves to nothing and the grant is orphaned.
    expect(
      deriveGrantSignerState({
        signerKeyIds: ['did:key:zOther#zKey'],
        accountDid: ACCOUNT_DID,
        doc
      })
    ).toBe('orphaned')
  })

  it('is unknown for a client-annex signer the document never lists', () => {
    expect(
      deriveGrantSignerState({
        signerKeyIds: [`${ANNEX_DID}#zVisit`],
        accountDid: ACCOUNT_DID,
        doc
      })
    ).toBe('unknown')
  })

  it('stays orphaned when a struck enrolled client signs beside an annex key', () => {
    expect(
      deriveGrantSignerState({
        signerKeyIds: [`${ANNEX_DID}#zVisit`, `${ACCOUNT_DID}#zGone`],
        accountDid: ACCOUNT_DID,
        doc
      })
    ).toBe('orphaned')
  })

  it('is active when an annex key signs beside a still-enrolled client', () => {
    expect(
      deriveGrantSignerState({
        signerKeyIds: [`${ANNEX_DID}#zVisit`, `${ACCOUNT_DID}#zKey`],
        accountDid: ACCOUNT_DID,
        doc
      })
    ).toBe('active')
  })

  it('treats a signer id with no fragment as one the document cannot judge', () => {
    expect(
      deriveGrantSignerState({
        signerKeyIds: [ACCOUNT_DID],
        accountDid: ACCOUNT_DID,
        doc
      })
    ).toBe('unknown')
  })
})
