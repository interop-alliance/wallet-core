/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
import { describe, expect, it } from 'vitest'
import {
  ACCOUNT_SHAPES,
  AUTHORITIES,
  CHAIN_TRIGGERS,
  deriveGaps,
  EVIDENCE,
  GAP_KINDS,
  heldAuthorities,
  INVARIANT_IDS,
  MEND_OUTCOMES,
  menderRegistry,
  TRIGGERS,
  transientReachableInvariants,
  undeclaredGaps,
  undeclaredInvariants,
  type InvariantDeclaration,
  type RegistrationSite
} from '../../src/menders/index.js'
import { declaration } from './fixtures/menderDeclaration.js'

/**
 * A small table over real ids: one shared-bundle invariant, one enrolled
 * chain sweep, one ladder routing entry, one guarded routing entry, one
 * ceremony-tail entry, one routing detector, one block-C invariant, one
 * unreported no-detector declaration naming the transient chain, one
 * unreported enrolled-authority chain detector, and one guarded routing
 * entry standing on enrolled accounts alone.
 */

const declarations: ReadonlyArray<InvariantDeclaration<never>> = [
  declaration({
    id: 'unlock-registry-opens-under-the-current-user-key',
    authority: 'account',
    triggers: ['remembered-login-chain', 'transient-login-chain']
  }),
  declaration({
    id: 'no-annex-generation-outlives-its-pointer',
    authority: 'enrolled',
    triggers: ['remembered-login-chain']
  }),
  declaration({
    id: 'annex-generation-is-reachable',
    authority: 'ladder',
    triggers: ['login-routing']
  }),
  declaration({
    id: 'this-browser-is-still-an-enrolled-client',
    authority: 'none',
    triggers: ['login-routing']
  }),
  declaration({
    id: 'retired-credential-leaves-no-annex-inventory',
    authority: 'account',
    triggers: ['ceremony-tail']
  }),
  declaration({
    id: 'document-lists-the-acting-credential',
    authority: 'none',
    triggers: ['login-routing'],
    holdsWhen: async () => 'holds'
  }),
  declaration({
    id: 'no-keystore-outlives-its-account',
    authority: 'ladder',
    triggers: []
  }),
  declaration({
    id: 'standard-collections-are-provisioned',
    authority: 'ladder',
    triggers: ['transient-login-chain']
  }),
  declaration({
    id: 'no-unlock-space-outlives-its-credential',
    authority: 'enrolled',
    triggers: ['transient-login-chain'],
    holdsWhen: async () => 'holds'
  }),
  declaration({
    id: 'no-client-key-record-stays-pending',
    authority: 'enrolled',
    standsOn: ['enrolled'],
    triggers: ['login-routing']
  })
]

const sites: ReadonlyArray<RegistrationSite> = [
  {
    trigger: 'remembered-login-chain',
    reports: ['unlock-registry-opens-under-the-current-user-key']
  },
  {
    trigger: 'remembered-login-chain',
    reports: ['no-annex-generation-outlives-its-pointer']
  },
  {
    trigger: 'transient-login-chain',
    reports: ['unlock-registry-opens-under-the-current-user-key']
  },
  { trigger: 'login-routing', reports: ['annex-generation-is-reachable'] },
  {
    trigger: 'login-routing',
    reports: ['this-browser-is-still-an-enrolled-client'],
    guardedBy: 'client-key-record'
  },
  {
    trigger: 'login-routing',
    reports: ['no-client-key-record-stays-pending'],
    guardedBy: 'client-key-record'
  }
]

const registry = menderRegistry({ declarations, sites })

describe('menders vocabularies', () => {
  it('are closed as-const arrays with the designed members', () => {
    expect(AUTHORITIES).toEqual(['none', 'account', 'enrolled', 'ladder'])
    expect(TRIGGERS).toEqual([
      'remembered-login-chain',
      'transient-login-chain',
      'login-routing',
      'ceremony-tail'
    ])
    expect(CHAIN_TRIGGERS).toEqual([
      'remembered-login-chain',
      'transient-login-chain'
    ])
    expect(ACCOUNT_SHAPES).toEqual(['client-less', 'enrolled'])
    expect(MEND_OUTCOMES).toEqual([
      'clean',
      'noop',
      'partial',
      'refused',
      'failed'
    ])
    expect(GAP_KINDS).toEqual(['none', 'unreachable'])
    expect(EVIDENCE).toHaveLength(8)
    expect(INVARIANT_IDS).toHaveLength(34)
    expect(new Set(INVARIANT_IDS).size).toBe(34)
  })
})

describe('heldAuthorities', () => {
  it('derives the held set from the resolved context kind alone', () => {
    expect(heldAuthorities({})).toEqual(['none'])
    expect(heldAuthorities({ kind: 'enrolled' })).toEqual([
      'none',
      'account',
      'enrolled'
    ])
    expect(heldAuthorities({ kind: 'ladder' })).toEqual([
      'none',
      'account',
      'ladder'
    ])
  })
})

describe('menderRegistry readers', () => {
  it('reads declarations by id and in table order', () => {
    expect(registry.all()).toBe(declarations)
    expect(registry.byId('annex-generation-is-reachable')?.authority).toBe(
      'ladder'
    )
    expect(registry.byId('app-keys-live-only-in-app-connections')).toBe(
      undefined
    )
  })

  it('dueAt filters one chain trigger by the held set, in list order', () => {
    const remembered = registry.dueAt({
      held: heldAuthorities({ kind: 'enrolled' }),
      trigger: 'remembered-login-chain'
    })
    expect(remembered.map(site => site.reports[0])).toEqual([
      'unlock-registry-opens-under-the-current-user-key',
      'no-annex-generation-outlives-its-pointer'
    ])
    const transientOnRemembered = registry.dueAt({
      held: heldAuthorities({ kind: 'ladder' }),
      trigger: 'remembered-login-chain'
    })
    expect(transientOnRemembered.map(site => site.reports[0])).toEqual([
      'unlock-registry-opens-under-the-current-user-key'
    ])
    expect(
      registry.dueAt({
        held: heldAuthorities({}),
        trigger: 'transient-login-chain'
      })
    ).toEqual([])
  })

  it('refuses a site reporting an undeclared invariant at construction', () => {
    expect(() =>
      menderRegistry({
        declarations,
        sites: [
          {
            trigger: 'remembered-login-chain',
            reports: ['app-keys-live-only-in-app-connections']
          }
        ]
      })
    ).toThrow(TypeError)
    expect(() =>
      menderRegistry({
        declarations,
        sites: [
          {
            trigger: 'login-routing',
            reports: ['app-keys-live-only-in-app-connections']
          }
        ]
      })
    ).toThrow(/undeclared invariant/)
  })

  it('refuses a duplicated declaration id at construction', () => {
    expect(() =>
      menderRegistry({
        declarations: [
          ...declarations,
          declaration({
            id: 'annex-generation-is-reachable',
            authority: 'none',
            triggers: []
          })
        ],
        sites
      })
    ).toThrow(/declared twice/)
  })

  it('refuses a guard on a site that is not a login-routing one', () => {
    expect(() =>
      menderRegistry({
        declarations,
        sites: [
          {
            trigger: 'transient-login-chain',
            reports: ['unlock-registry-opens-under-the-current-user-key'],
            // @ts-expect-error -- the type forbids it; the runtime check backs it
            guardedBy: 'client-key-record'
          }
        ]
      })
    ).toThrow(/only a login-routing site/)
  })
})

describe('derived sets', () => {
  it('transientReachableInvariants reads the chain, the unguarded routing sites, the tails, and the detectors', () => {
    // Absent: the unreported no-detector chain declaration
    // (`standard-collections-are-provisioned`) and the unreported chain
    // detector whose authority the ladder held set lacks
    // (`no-unlock-space-outlives-its-credential`).
    expect(transientReachableInvariants({ registry })).toEqual([
      'unlock-registry-opens-under-the-current-user-key',
      'annex-generation-is-reachable',
      'retired-credential-leaves-no-annex-inventory',
      'document-lists-the-acting-credential'
    ])
  })

  it('counts an unreported detector only with a detector, and on the chain only under the ladder held set', () => {
    const withDetector = menderRegistry({
      declarations: declarations.map(decl =>
        decl.id === 'standard-collections-are-provisioned'
          ? { ...decl, holdsWhen: async () => 'holds' as const }
          : decl.id === 'no-unlock-space-outlives-its-credential'
            ? { ...decl, authority: 'account' as const }
            : decl
      ),
      sites
    })
    expect(transientReachableInvariants({ registry: withDetector })).toEqual([
      'unlock-registry-opens-under-the-current-user-key',
      'annex-generation-is-reachable',
      'retired-credential-leaves-no-annex-inventory',
      'document-lists-the-acting-credential',
      'standard-collections-are-provisioned',
      'no-unlock-space-outlives-its-credential'
    ])
    const withoutDetector = menderRegistry({
      declarations: declarations.map(decl =>
        decl.id === 'document-lists-the-acting-credential'
          ? { ...decl, holdsWhen: undefined }
          : decl
      ),
      sites
    })
    expect(
      transientReachableInvariants({ registry: withoutDetector })
    ).not.toContain('document-lists-the-acting-credential')
  })

  it('deriveGaps kinds an unreported invariant none (a detector included), a ceremony-tail entry nothing, and a client-less unreachable one unreachable', () => {
    expect(deriveGaps({ registry })).toEqual([
      {
        invariant: 'no-annex-generation-outlives-its-pointer',
        kind: 'unreachable'
      },
      {
        invariant: 'this-browser-is-still-an-enrolled-client',
        kind: 'unreachable'
      },
      { invariant: 'document-lists-the-acting-credential', kind: 'none' },
      { invariant: 'no-keystore-outlives-its-account', kind: 'none' },
      { invariant: 'standard-collections-are-provisioned', kind: 'none' },
      { invariant: 'no-unlock-space-outlives-its-credential', kind: 'none' }
    ])
  })

  it('a detector is not a mender: adding holdsWhen retires no gap', () => {
    const withDetector = menderRegistry({
      declarations: declarations.map(decl =>
        decl.id === 'no-keystore-outlives-its-account'
          ? { ...decl, holdsWhen: async () => 'holds' as const }
          : decl
      ),
      sites
    })
    expect(deriveGaps({ registry: withDetector })).toEqual(
      deriveGaps({ registry })
    )
  })

  it('undeclaredGaps admits gaps and retires none', () => {
    const derived = deriveGaps({ registry })
    const declared = [
      {
        invariant: 'no-annex-generation-outlives-its-pointer' as const,
        tornState: 'the GC never runs',
        standsOn: ['client-less' as const],
        item: 'FW-365',
        kind: 'unreachable' as const
      },
      {
        invariant: 'this-browser-is-still-an-enrolled-client' as const,
        tornState: 'a torn local wipe',
        standsOn: ['client-less' as const],
        item: 'FW-470',
        kind: 'none' as const
      },
      {
        invariant: 'no-keystore-outlives-its-account' as const,
        tornState: 'an orphaned keystore',
        standsOn: ['client-less' as const, 'enrolled' as const],
        item: 'FW-402',
        kind: 'none' as const
      },
      {
        invariant: 'document-lists-the-acting-credential' as const,
        tornState: 'a detector with no converger',
        standsOn: ['client-less' as const],
        item: 'FW-000',
        kind: 'none' as const
      },
      {
        invariant: 'standard-collections-are-provisioned' as const,
        tornState: 'no converger',
        standsOn: ['client-less' as const],
        item: 'FW-000',
        kind: 'none' as const
      },
      {
        invariant: 'no-unlock-space-outlives-its-credential' as const,
        tornState: 'a detector with no converger',
        standsOn: ['client-less' as const],
        item: 'FW-000',
        kind: 'none' as const
      },
      {
        invariant: 'unlock-registry-opens-under-the-current-user-key' as const,
        tornState: 'a lapsed row the derivation no longer produces',
        standsOn: ['client-less' as const],
        item: 'FW-000',
        kind: 'unreachable' as const
      }
    ]
    expect(undeclaredGaps({ derived, declared })).toEqual([])
    expect(
      undeclaredGaps({ derived, declared: declared.slice(0, 2) }).map(
        gap => gap.invariant
      )
    ).toEqual([
      'document-lists-the-acting-credential',
      'no-keystore-outlives-its-account',
      'standard-collections-are-provisioned',
      'no-unlock-space-outlives-its-credential'
    ])
  })

  it('undeclaredInvariants lists the census ids the table lacks', () => {
    const missing = undeclaredInvariants({ registry })
    expect(missing).toHaveLength(INVARIANT_IDS.length - declarations.length)
    expect(missing).not.toContain('annex-generation-is-reachable')
    expect(missing).toContain('app-keys-live-only-in-app-connections')
  })
})
