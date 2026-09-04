/**
 * Unit tests for the disconnect-eligibility policy (`src/clients/policy.ts`):
 * the three refusals in their precedence order, the row-to-key-set narrowing,
 * and the partial-fan-out-is-a-resumable-success reporting rule.
 */
import { describe, expect, it } from 'vitest'
import {
  cascadeCompletion,
  disconnectEligibility,
  revokedClientKeysFor
} from '../../src/clients/policy.js'
import type { AccountClientView } from '../../src/clients/listing.js'

/**
 * A listed row.
 *
 * @param options {object}
 * @param options.signingKeyMultibase {string}
 * @param [options.isCurrent] {boolean}
 * @param [options.updateKeyMultibase] {string}
 * @returns {AccountClientView}
 */
function row({
  signingKeyMultibase,
  isCurrent = false,
  updateKeyMultibase = 'z6MkUpdate'
}: {
  signingKeyMultibase: string
  isCurrent?: boolean
  updateKeyMultibase?: string
}): AccountClientView {
  return {
    signingKeyMultibase,
    keyAgreementKeyMultibases: ['z6LSTwin'],
    isCurrent,
    ...(updateKeyMultibase ? { updateKeyMultibase } : {})
  }
}

describe('disconnectEligibility', () => {
  const other = row({ signingKeyMultibase: 'z6MkOther' })
  const current = row({ signingKeyMultibase: 'z6MkSelf', isCurrent: true })

  it('allows an ordinary other client on a multi-client account', () => {
    expect(
      disconnectEligibility({ client: other, clients: [current, other] })
    ).toEqual({ allowed: true })
  })

  it('refuses self-disconnection first', () => {
    expect(
      disconnectEligibility({ client: current, clients: [current, other] })
    ).toEqual({ allowed: false, refusal: 'self' })
  })

  it('refuses the last enrolled client', () => {
    expect(disconnectEligibility({ client: other, clients: [other] })).toEqual({
      allowed: false,
      refusal: 'last-client'
    })
  })

  it('lifts the self and last-client refusals on the ladder branch', () => {
    // A standing credential's rung signs the removal entry, so there is no
    // self, and the last client's removal lands the account ladder-anchored
    // rather than abandoning its update authority (`decisions/0017`).
    expect(
      disconnectEligibility({
        client: current,
        clients: [current, other],
        signerKind: 'ladder'
      })
    ).toEqual({ allowed: true })
    expect(
      disconnectEligibility({
        client: other,
        clients: [other],
        signerKind: 'ladder'
      })
    ).toEqual({ allowed: true })
  })

  it('keeps the unattributed-update-key refusal on the ladder branch', () => {
    const unattributed = row({
      signingKeyMultibase: 'z6MkOther',
      updateKeyMultibase: ''
    })
    expect(
      disconnectEligibility({
        client: unattributed,
        clients: [unattributed],
        signerKind: 'ladder'
      })
    ).toEqual({ allowed: false, refusal: 'unattributed-update-key' })
  })

  it('refuses a row whose update key was not attributed', () => {
    const unattributed = row({
      signingKeyMultibase: 'z6MkOther',
      updateKeyMultibase: ''
    })
    expect(
      disconnectEligibility({
        client: unattributed,
        clients: [current, unattributed]
      })
    ).toEqual({ allowed: false, refusal: 'unattributed-update-key' })
  })
})

describe('revokedClientKeysFor', () => {
  it('narrows a fully attributed row', () => {
    expect(
      revokedClientKeysFor({ client: row({ signingKeyMultibase: 'z6MkA' }) })
    ).toEqual({
      signingKeyMultibase: 'z6MkA',
      updateKeyMultibase: 'z6MkUpdate'
    })
  })

  it('refuses an unattributed row', () => {
    expect(() =>
      revokedClientKeysFor({
        client: row({ signingKeyMultibase: 'z6MkA', updateKeyMultibase: '' })
      })
    ).toThrow(/update key could not be attributed/)
  })
})

describe('cascadeCompletion', () => {
  it('reports a clean fan-out complete', () => {
    expect(
      cascadeCompletion({ collections: { outcomes: {}, failed: [] } })
    ).toBe('complete')
  })

  it('reports a fan-out with failures as partial, not failed', () => {
    expect(
      cascadeCompletion({
        collections: {
          outcomes: { contacts: 'rotated' },
          failed: [{ collectionId: 'wallet-activity', error: new Error('x') }]
        }
      })
    ).toBe('partial')
  })

  it('reports a failed roster seal as partial (the unsealed-log signal)', () => {
    expect(
      cascadeCompletion({
        collections: { outcomes: {}, failed: [] },
        rosterSeal: { outcome: 'failed', error: new Error('offline') }
      })
    ).toBe('partial')
  })

  it('treats a landed or unneeded seal as complete', () => {
    expect(
      cascadeCompletion({
        collections: { outcomes: {}, failed: [] },
        rosterSeal: { outcome: 'sealed' }
      })
    ).toBe('complete')
    expect(
      cascadeCompletion({
        collections: { outcomes: {}, failed: [] },
        rosterSeal: { outcome: 'noop' }
      })
    ).toBe('complete')
  })
})
