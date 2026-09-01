/**
 * Unit tests for the shared account-document readers
 * (`src/resourceLog/document.ts`): the reference-resolving relation reader the
 * client listing's marker filter and the user key roster's recipient resolver
 * are both built over (a string reference resolved against
 * `verificationMethod`, a reference nothing backs dropped, an embedded method
 * taken verbatim, document order preserved across the mixture), the ladder-VM
 * recognition by relation asymmetry, and the agreement between those readers
 * and the controller view's credential-inventory accessor, which is built on
 * them.
 */
import { describe, expect, it } from 'vitest'
import type { DIDLog } from '@interop/did-method-webvh'
import {
  credentialKeyAgreementMethods,
  ladderVmIds,
  ladderVmMethods,
  resolvedKeyAgreementMethods,
  resolvedRelationMethods
} from '../../src/resourceLog/document.js'
import { webvhResourceLogController } from '../../src/resourceLog/index.js'

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

describe('resolvedRelationMethods', () => {
  it('resolves any relation, references and embedded methods alike', () => {
    const methods = resolvedRelationMethods({
      doc: {
        verificationMethod: [
          { id: `${DID}#zClient`, publicKeyMultibase: 'zClient' }
        ],
        assertionMethod: [
          `${DID}#zClient`,
          { id: `${DID}#zLadder`, publicKeyMultibase: 'zLadder' },
          `${DID}#zMissing`
        ]
      },
      relation: 'assertionMethod'
    })
    expect(methods.map(method => method.publicKeyMultibase)).toEqual([
      'zClient',
      'zLadder'
    ])
  })

  it('reads an absent relation as no methods', () => {
    expect(
      resolvedRelationMethods({ doc: {}, relation: 'capabilityDelegation' })
    ).toEqual([])
  })
})

describe('ladderVmIds', () => {
  it('does not name an enrolled client, published under both relations', () => {
    const doc = {
      capabilityInvocation: [`${DID}#zClient`],
      capabilityDelegation: [`${DID}#zClient`]
    }
    expect(ladderVmIds({ doc })).toEqual([])
  })

  it('names a capabilityDelegation member absent from invocation', () => {
    const doc = {
      capabilityInvocation: [`${DID}#zClient`],
      capabilityDelegation: [`${DID}#zClient`, `${DID}#zLadder`]
    }
    expect(ladderVmIds({ doc })).toEqual([`${DID}#zLadder`])
  })

  it('reads embedded methods by their id, on either relation', () => {
    const doc = {
      capabilityInvocation: [{ id: `${DID}#zClient` }],
      capabilityDelegation: [{ id: `${DID}#zClient` }, { id: `${DID}#zLadder` }]
    }
    expect(ladderVmIds({ doc })).toEqual([`${DID}#zLadder`])
  })
})

describe('ladderVmMethods', () => {
  it('materializes the recognized ids, references and embedded alike', () => {
    const embedded = {
      id: `${DID}#zLadderTwo`,
      publicKeyMultibase: 'zLadderTwo'
    }
    const methods = ladderVmMethods({
      doc: {
        verificationMethod: [
          { id: `${DID}#zClient`, publicKeyMultibase: 'zClient' },
          { id: `${DID}#zLadderOne`, publicKeyMultibase: 'zLadderOne' }
        ],
        capabilityInvocation: [`${DID}#zClient`],
        capabilityDelegation: [`${DID}#zClient`, `${DID}#zLadderOne`, embedded]
      }
    })
    expect(methods.map(method => method.publicKeyMultibase)).toEqual([
      'zLadderOne',
      'zLadderTwo'
    ])
  })

  it('drops an id-less embedded delegation method', () => {
    const methods = ladderVmMethods({
      doc: { capabilityDelegation: [{ publicKeyMultibase: 'zAnonymous' }] }
    })
    expect(methods).toEqual([])
  })
})

/**
 * A document carrying the whole cast the readers discriminate: an enrolled
 * client (both signing relations, its key-agreement twin under the `did:key`
 * controller marker), a standing credential's ladder VM
 * (`capabilityDelegation` only) beside its unmarked `MultikeyCommitment`
 * key-agreement entry, and a recovery code's verbatim unmarked entry.
 */
function inventoryDocument(): Record<string, unknown> {
  return {
    id: DID,
    verificationMethod: [
      {
        id: `${DID}#zClient`,
        type: 'Multikey',
        controller: DID,
        publicKeyMultibase: 'zClient'
      },
      {
        id: `${DID}#zClientKak`,
        type: 'Multikey',
        controller: 'did:key:zClient',
        publicKeyMultibase: 'zClientKak'
      },
      {
        id: `${DID}#zLadder`,
        type: 'Multikey',
        controller: DID,
        publicKeyMultibase: 'zLadder'
      },
      {
        id: `${DID}#zCommitment`,
        type: 'MultikeyCommitment',
        controller: DID,
        publicKeyCommitment: 'uCommitment'
      },
      {
        id: `${DID}#zRecovery`,
        type: 'Multikey',
        controller: DID,
        publicKeyMultibase: 'zRecovery'
      }
    ],
    assertionMethod: [`${DID}#zClient`, `${DID}#zLadder`],
    keyAgreement: [
      `${DID}#zClientKak`,
      `${DID}#zCommitment`,
      `${DID}#zRecovery`
    ],
    capabilityInvocation: [`${DID}#zClient`],
    capabilityDelegation: [`${DID}#zClient`, `${DID}#zLadder`]
  }
}

describe('the controller view agrees with the shared readers', () => {
  it('reports the inventory the readers name over the same document', async () => {
    const doc = inventoryDocument()
    const log = [{ versionId: '1-v1', state: doc }] as unknown as DIDLog
    const inventory = await webvhResourceLogController({
      did: DID,
      log
    }).inventoryAt()

    const ladderKeys = ladderVmMethods({ doc }).map(
      method => method.publicKeyMultibase
    )
    expect(ladderVmIds({ doc })).toEqual([`${DID}#zLadder`])
    expect(inventory.ladderKeys).toEqual(new Set(ladderKeys))

    const credentialKeys = credentialKeyAgreementMethods({ doc, did: DID }).map(
      method => method.publicKeyCommitment ?? method.publicKeyMultibase
    )
    expect(credentialKeys).toEqual(['uCommitment', 'zRecovery'])
    expect(inventory.inventoryKeys).toEqual(
      new Set([...ladderKeys, ...credentialKeys])
    )
  })

  it('drops an id-less or empty-id delegation member from the ladder set', async () => {
    const doc = {
      ...inventoryDocument(),
      capabilityDelegation: [
        `${DID}#zClient`,
        { publicKeyMultibase: 'zAnon' },
        { id: '', publicKeyMultibase: 'zEmpty' }
      ]
    }
    const log = [{ versionId: '1-v1', state: doc }] as unknown as DIDLog
    const inventory = await webvhResourceLogController({
      did: DID,
      log
    }).inventoryAt()
    expect(inventory.ladderKeys).toEqual(new Set())
    expect(inventory.inventoryKeys.has('zAnon')).toBe(false)
    expect(inventory.inventoryKeys.has('zEmpty')).toBe(false)
  })

  it('leaves the enrolled client out of both sets', async () => {
    const doc = inventoryDocument()
    const log = [{ versionId: '1-v1', state: doc }] as unknown as DIDLog
    const inventory = await webvhResourceLogController({
      did: DID,
      log
    }).inventoryAt()
    expect(inventory.ladderKeys.has('zClient')).toBe(false)
    expect(inventory.inventoryKeys.has('zClientKak')).toBe(false)
  })
})
