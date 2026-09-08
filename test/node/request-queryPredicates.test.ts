/**
 * Unit tests for the one-mental-model-per-exchange exclusion set
 * (`src/request/queryPredicates.ts`): every exclusive query type refuses
 * every other one from its own side, so a type can never be excluded in one
 * direction only, and each refusal keeps its own type-specific message.
 */
import { describe, expect, it } from 'vitest'
import {
  EXCLUSIVE_QUERY_TYPES,
  exclusiveQueryOf
} from '../../src/request/index.js'
import type { IVPRQuery } from '../../src/request/index.js'

function queryOfType(type: string): IVPRQuery {
  return { type } as never as IVPRQuery
}

describe('exclusiveQueryOf', () => {
  it('returns null when no query of the type is present', () => {
    for (const typeName of EXCLUSIVE_QUERY_TYPES) {
      expect(
        exclusiveQueryOf({
          queries: [queryOfType('QueryByExample')],
          typeName
        })
      ).toBeNull()
    }
  })

  it('returns the one query of the type when it stands alone', () => {
    for (const typeName of EXCLUSIVE_QUERY_TYPES) {
      const query = queryOfType(typeName)
      expect(exclusiveQueryOf({ queries: [query], typeName })).toBe(query)
    }
  })

  it('refuses a duplicate of the type', () => {
    for (const typeName of EXCLUSIVE_QUERY_TYPES) {
      expect(() =>
        exclusiveQueryOf({
          queries: [queryOfType(typeName), queryOfType(typeName)],
          typeName
        })
      ).toThrow(new RegExp(`More than one ${typeName}`))
    }
  })

  it('refuses QueryByExample and both capability query spellings beside every type', () => {
    for (const typeName of EXCLUSIVE_QUERY_TYPES) {
      for (const other of [
        'QueryByExample',
        'AuthorizationCapabilityQuery',
        'ZcapQuery'
      ]) {
        expect(() =>
          exclusiveQueryOf({
            queries: [queryOfType(typeName), queryOfType(other)],
            typeName
          })
        ).toThrow(/cannot be combined with/)
      }
    }
  })

  it('refuses every ordered pair of exclusive types from both sides', () => {
    for (const typeName of EXCLUSIVE_QUERY_TYPES) {
      for (const other of EXCLUSIVE_QUERY_TYPES) {
        if (other === typeName) {
          continue
        }
        const queries = [queryOfType(typeName), queryOfType(other)]
        expect(() => exclusiveQueryOf({ queries, typeName })).toThrow(
          new RegExp(`${typeName} cannot be combined with .*${other}`)
        )
        expect(() => exclusiveQueryOf({ queries, typeName: other })).toThrow(
          new RegExp(`${other} cannot be combined with .*${typeName}`)
        )
      }
    }
  })

  it('keeps the two refusal messages distinct and stable', () => {
    expect(() =>
      exclusiveQueryOf({
        queries: [
          queryOfType('AppConnectQuery'),
          queryOfType('WalletOnboardingQuery')
        ],
        typeName: 'AppConnectQuery'
      })
    ).toThrow(
      'An AppConnectQuery cannot be combined with QueryByExample, ' +
        'standalone capability queries, or a WalletOnboardingQuery.'
    )
    expect(() =>
      exclusiveQueryOf({
        queries: [
          queryOfType('AppConnectQuery'),
          queryOfType('WalletOnboardingQuery')
        ],
        typeName: 'WalletOnboardingQuery'
      })
    ).toThrow(
      'A WalletOnboardingQuery cannot be combined with QueryByExample, ' +
        'standalone capability queries, or an AppConnectQuery.'
    )
  })
})
