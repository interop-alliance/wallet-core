/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The shared merge-into-document helper reproduces, byte for byte, the inline
 * assembly each add-methods entry builder carried before it: the enrollment
 * add entry, the self-enrollment add entry, and the recovery continuation's
 * add-and-retire entry. Each oracle below is that site's previous code
 * verbatim, so a change to the helper that diverges any relation, filter
 * order, or dedupe from what those sites published fails here.
 */
import type { VerificationMethod } from '@interop/did-method-webvh'
import { describe, expect, it } from 'vitest'
import { mergeVerificationMethods, relationIds } from '../../src/webvh/index.js'
import type { RelationMembership } from '../../src/webvh/index.js'

const did = 'did:webvh:scid:host:space:sp:id'
const vmId = (multibase: string) => `${did}#${multibase}`

const clientA = { signing: 'z6MkA', keyAgreement: 'z6LSa' }
const clientB = { signing: 'z6MkB', keyAgreement: 'z6LSb' }
const code = { keyAgreement: 'z6LSc', ladderVm: 'z6MkLc' }
const passkey = { keyAgreement: 'z6LSp', ladderVm: 'z6MkLp' }

function method(multibase: string, controller = did): VerificationMethod {
  return {
    id: vmId(multibase),
    type: 'Multikey',
    controller,
    publicKeyMultibase: multibase
  }
}

/**
 * A fixture document with one enrolled client, a spendable recovery code, and
 * a passkey credential -- every method flavor the three sites meet. Both
 * string references and an embedded object stand in the relations so the
 * relation reader's tolerance is exercised.
 */
function fixtureDocument() {
  return {
    verificationMethod: [
      method(clientA.signing),
      method(clientA.keyAgreement, `did:key:${clientA.signing}`),
      method(code.keyAgreement),
      method(code.ladderVm),
      method(passkey.keyAgreement),
      method(passkey.ladderVm)
    ],
    authentication: [vmId(clientA.signing)],
    assertionMethod: [
      vmId(clientA.signing),
      vmId(code.ladderVm),
      { id: vmId(passkey.ladderVm) }
    ],
    keyAgreement: [
      vmId(clientA.keyAgreement),
      vmId(code.keyAgreement),
      vmId(passkey.keyAgreement)
    ],
    capabilityInvocation: [vmId(clientA.signing)],
    capabilityDelegation: [
      vmId(clientA.signing),
      vmId(code.ladderVm),
      vmId(passkey.ladderVm)
    ]
  }
}

const clientBMethods: VerificationMethod[] = [
  method(clientB.signing),
  method(clientB.keyAgreement, `did:key:${clientB.signing}`)
]

/**
 * The enrollment add entry's previous inline assembly, verbatim
 * (`webvh/enrollClient.ts`). The self-enrollment add entry
 * (`clientAnnex/ladderAnchored.ts`) carried the identical text under
 * different variable names.
 */
function enrollmentOracle({
  doc,
  addedMethods
}: {
  doc: ReturnType<typeof fixtureDocument>
  addedMethods: VerificationMethod[]
}) {
  const newClient = {
    signingKeyMultibase: clientB.signing,
    keyAgreementKeyMultibase: clientB.keyAgreement
  }
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const verificationMethods = [
    ...existingMethods.filter(
      method => !addedMethods.some(add => add.id === method.id)
    ),
    ...addedMethods
  ]
  const withReference = (
    relation: Array<string | { id?: string }> | undefined,
    id: string
  ) => [...new Set([...relationIds(relation), id])]
  const signingVmId = vmId(newClient.signingKeyMultibase)
  return {
    verificationMethods,
    authentication: withReference(doc.authentication, signingVmId),
    assertionMethod: withReference(doc.assertionMethod, signingVmId),
    keyAgreement: withReference(
      doc.keyAgreement,
      vmId(newClient.keyAgreementKeyMultibase)
    ),
    capabilityInvocation: withReference(doc.capabilityInvocation, signingVmId),
    capabilityDelegation: withReference(doc.capabilityDelegation, signingVmId)
  }
}

/**
 * The recovery add-and-retire entry's previous inline assembly, verbatim
 * (`recovery/continuation.ts`).
 */
function continuationOracle({
  doc,
  addedMethods,
  struck,
  variant,
  replacementVmId,
  replacementLadderVmId
}: {
  doc: ReturnType<typeof fixtureDocument>
  addedMethods: VerificationMethod[]
  struck: (id: string | undefined) => boolean
  variant: RelationMembership
  replacementVmId: string
  replacementLadderVmId: string
}) {
  const existingMethods = (doc.verificationMethod ?? []) as VerificationMethod[]
  const verificationMethods = [
    ...existingMethods.filter(
      method =>
        !struck(method.id) &&
        !addedMethods.some(added => added.id === method.id)
    ),
    ...addedMethods
  ]
  const withReference = (
    relation: Array<string | { id?: string }> | undefined,
    ...ids: string[]
  ) => [
    ...new Set([
      ...relationIds(relation).filter(referencedId => !struck(referencedId)),
      ...ids
    ])
  ]
  return {
    verificationMethods,
    authentication: withReference(
      doc.authentication,
      ...(variant.authentication ?? [])
    ),
    assertionMethod: withReference(
      doc.assertionMethod,
      ...(variant.assertionMethod ?? []),
      replacementLadderVmId
    ),
    keyAgreement: withReference(
      doc.keyAgreement,
      ...(variant.keyAgreement ?? []),
      replacementVmId
    ),
    capabilityInvocation: withReference(
      doc.capabilityInvocation,
      ...(variant.capabilityInvocation ?? [])
    ),
    capabilityDelegation: withReference(
      doc.capabilityDelegation,
      ...(variant.capabilityDelegation ?? []),
      replacementLadderVmId
    )
  }
}

describe('mergeVerificationMethods', () => {
  it('matches the enrollment and self-enrollment add entries byte for byte', () => {
    const doc = fixtureDocument()
    const signingVmId = vmId(clientB.signing)
    const merged = mergeVerificationMethods({
      doc,
      methods: clientBMethods,
      relations: {
        authentication: [signingVmId],
        assertionMethod: [signingVmId],
        keyAgreement: [vmId(clientB.keyAgreement)],
        capabilityInvocation: [signingVmId],
        capabilityDelegation: [signingVmId]
      }
    })
    const oracle = enrollmentOracle({ doc, addedMethods: clientBMethods })
    expect(JSON.stringify(merged)).toBe(JSON.stringify(oracle))
    // The new client landed once under every relation, after the existing
    // references, and the embedded reference resolved to its id.
    expect(merged.capabilityInvocation).toEqual([
      vmId(clientA.signing),
      signingVmId
    ])
    expect(merged.assertionMethod).toContain(vmId(passkey.ladderVm))
  })

  it('replaces a method already published under the same id, once', () => {
    const doc = fixtureDocument()
    // A re-run of an add entry whose client already stands: the method is
    // replaced in place rather than duplicated, and the relations are
    // unchanged.
    doc.verificationMethod.push(...clientBMethods)
    doc.authentication.push(vmId(clientB.signing))
    const signingVmId = vmId(clientB.signing)
    const merged = mergeVerificationMethods({
      doc,
      methods: clientBMethods,
      relations: {
        authentication: [signingVmId],
        assertionMethod: [signingVmId],
        keyAgreement: [vmId(clientB.keyAgreement)],
        capabilityInvocation: [signingVmId],
        capabilityDelegation: [signingVmId]
      }
    })
    expect(JSON.stringify(merged)).toBe(
      JSON.stringify(enrollmentOracle({ doc, addedMethods: clientBMethods }))
    )
    expect(
      merged.verificationMethods.filter(m => m.id === signingVmId)
    ).toHaveLength(1)
    expect(merged.authentication).toEqual([vmId(clientA.signing), signingVmId])
  })

  it('matches the recovery add-and-retire entry byte for byte', () => {
    const doc = fixtureDocument()
    const replacement = { keyAgreement: 'z6LSr', ladderVm: 'z6MkLr' }
    const replacementVmId = vmId(replacement.keyAgreement)
    const replacementLadderVmId = vmId(replacement.ladderVm)
    // The transient variant: a fresh credential (key-agreement member plus
    // its ladder VM) beside the replacement code's inventory.
    const fresh = { keyAgreement: 'z6LSf', ladderVm: 'z6MkLf' }
    const variant: RelationMembership = {
      assertionMethod: [vmId(fresh.ladderVm)],
      keyAgreement: [vmId(fresh.keyAgreement)],
      capabilityDelegation: [vmId(fresh.ladderVm)]
    }
    const addedMethods: VerificationMethod[] = [
      method(fresh.keyAgreement),
      method(fresh.ladderVm),
      method(replacement.keyAgreement),
      method(replacement.ladderVm)
    ]
    // The spent code and every pre-recovery credential retire in the entry.
    const spentVmId = vmId(code.keyAgreement)
    const ladderVms = [vmId(code.ladderVm), vmId(passkey.ladderVm)]
    const struckCredentialVmIds = [spentVmId, vmId(passkey.keyAgreement)]
    const struck = (id: string): boolean =>
      id === spentVmId ||
      ladderVms.includes(id) ||
      struckCredentialVmIds.includes(id)
    const merged = mergeVerificationMethods({
      doc,
      methods: addedMethods,
      retire: struck,
      relations: {
        authentication: variant.authentication,
        assertionMethod: [
          ...(variant.assertionMethod ?? []),
          replacementLadderVmId
        ],
        keyAgreement: [...(variant.keyAgreement ?? []), replacementVmId],
        capabilityInvocation: variant.capabilityInvocation,
        capabilityDelegation: [
          ...(variant.capabilityDelegation ?? []),
          replacementLadderVmId
        ]
      }
    })
    const oracle = continuationOracle({
      doc,
      addedMethods,
      struck: id => id !== undefined && struck(id),
      variant,
      replacementVmId,
      replacementLadderVmId
    })
    expect(JSON.stringify(merged)).toBe(JSON.stringify(oracle))
    // The retired inventory left every relation and `verificationMethod`; the
    // enrolled client stood; the fresh member precedes the replacement's.
    expect(merged.keyAgreement).toEqual([
      vmId(clientA.keyAgreement),
      vmId(fresh.keyAgreement),
      replacementVmId
    ])
    expect(merged.capabilityDelegation).toEqual([
      vmId(clientA.signing),
      vmId(fresh.ladderVm),
      replacementLadderVmId
    ])
    expect(merged.verificationMethods.map(m => m.id)).toEqual([
      vmId(clientA.signing),
      vmId(clientA.keyAgreement),
      ...addedMethods.map(m => m.id)
    ])
  })

  it('retires over the existing document only, never over the added ids', () => {
    const doc = fixtureDocument()
    // A reinstall of a ladder VM that already stands: the predicate names
    // it, and the merge must still publish it.
    const reinstalled = vmId(passkey.ladderVm)
    const merged = mergeVerificationMethods({
      doc,
      methods: [method(passkey.ladderVm)],
      retire: id => id === reinstalled,
      relations: {
        assertionMethod: [reinstalled],
        capabilityDelegation: [reinstalled]
      }
    })
    expect(merged.assertionMethod).toContain(reinstalled)
    expect(merged.capabilityDelegation).toContain(reinstalled)
    expect(
      merged.verificationMethods.filter(m => m.id === reinstalled)
    ).toHaveLength(1)
  })
})
