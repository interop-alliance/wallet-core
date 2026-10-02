/**
 * Unit tests for the shared account-document readers
 * (`src/resourceLog/document.ts`): the reference-resolving relation reader the
 * client listing's marker filter and the user key roster's recipient resolver
 * are both built over (a string reference resolved against
 * `verificationMethod`, a reference nothing backs dropped, an embedded method
 * taken verbatim, document order preserved across the mixture), the ladder-VM
 * recognition by relation asymmetry, the two key-class readers (the enrolled
 * clients' signing keys, the ladder VMs' keys) under the one key-multibase
 * rule and their agreement with the ladder-rung attribution and the did:key
 * census built on them, and the agreement between those readers and the
 * controller view's credential-inventory accessor, which is built on them.
 */
import { describe, expect, it } from 'vitest'
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import type { DIDLog } from '@interop/did-method-webvh'
import {
  credentialKeyAgreementMethods,
  enrolledClientKeyMultibases,
  ladderVmIds,
  ladderVmKeyMultibases,
  ladderVmMethods,
  resolvedKeyAgreementMethods,
  resolvedRelationMethods
} from '../../src/resourceLog/document.js'
import {
  attributeLadderRungsPerVersion,
  webvhResourceLogController
} from '../../src/resourceLog/index.js'
import { accountLogDids } from '../../src/webvh/documentDids.js'

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

  it('resolves every relation of one document through one index', () => {
    // Each index build iterates `verificationMethod` once; a memoized index
    // is built on the first relation read and reused by every later one.
    let walks = 0
    const verificationMethod = new Proxy(
      [{ id: `${DID}#zClient`, publicKeyMultibase: 'zClient' }],
      {
        get(target, property, receiver) {
          if (property === Symbol.iterator) {
            walks++
          }
          return Reflect.get(target, property, receiver)
        }
      }
    )
    const doc = {
      verificationMethod,
      assertionMethod: [`${DID}#zClient`],
      capabilityInvocation: [`${DID}#zClient`],
      capabilityDelegation: [`${DID}#zClient`],
      keyAgreement: [`${DID}#zClient`]
    }
    for (const relation of [
      'assertionMethod',
      'capabilityInvocation',
      'capabilityDelegation',
      'keyAgreement'
    ] as const) {
      expect(
        resolvedRelationMethods({ doc, relation }).map(method => method.id)
      ).toEqual([`${DID}#zClient`])
    }
    expect(walks).toBe(1)
    // A rebuilt document carries a fresh array, and so a fresh index.
    const rebuilt = { ...doc, verificationMethod: [...verificationMethod] }
    expect(
      resolvedRelationMethods({ doc: rebuilt, relation: 'keyAgreement' })
    ).toHaveLength(1)
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
 * A one-entry ladder-anchored genesis whose document publishes one ladder VM
 * and, when given, one enrolled client, each as the given relation member and
 * `verificationMethod` entry, so a malformed member can be stated per key
 * class. The entry reveals the ladder's rung 0 outright, which the rung walk
 * attributes to the ladder only when no client is published beside it.
 *
 * @param options {object}
 * @param [options.client] {object}   the client's relation member and method
 * @param options.ladder {object}   the ladder VM's relation member and method
 * @returns {DIDLog}
 */
async function keyClassLog({
  client,
  ladder
}: {
  client?: { member: string | object; method?: object }
  ladder: { member: string | object; method?: object }
}): Promise<DIDLog> {
  const rungZero = 'z6MkRungZero'
  return [
    {
      versionId: '1-v1',
      parameters: {
        updateKeys: [rungZero],
        nextKeyHashes: [await deriveNextKeyHash(rungZero)]
      },
      state: {
        id: DID,
        verificationMethod: [client?.method, ladder.method].filter(Boolean),
        capabilityInvocation: client ? [client.member] : [],
        capabilityDelegation: [
          ...(client ? [client.member] : []),
          ladder.member
        ]
      },
      proof: [{ verificationMethod: `did:key:${rungZero}#${rungZero}` }]
    }
  ] as unknown as DIDLog
}

describe('the key-class readers', () => {
  const method = (id: string, publicKeyMultibase: string) => ({
    id: `${DID}#${id}`,
    controller: DID,
    publicKeyMultibase
  })
  const agreeing = {
    member: `${DID}#zClient`,
    method: method('zClient', 'zClient')
  }
  const agreeingLadder = {
    member: `${DID}#zLadder`,
    method: method('zLadder', 'zLadder')
  }

  it('read a fragment with no publicKeyMultibase as the key', async () => {
    const ladderOnly = await keyClassLog({
      ladder: { member: `${DID}#zLadderRef` }
    })
    expect(ladderVmKeyMultibases({ doc: ladderOnly[0]!.state })).toEqual(
      new Set(['zLadderRef'])
    )
    expect(accountLogDids({ log: ladderOnly }).ladderDids).toEqual(
      new Set(['did:key:zLadderRef'])
    )
    // The rung walk keys the ladder by the same reading, so the genesis
    // rung lands under the fragment.
    const [head] = await attributeLadderRungsPerVersion(ladderOnly)
    expect([...head!.keys()]).toEqual(['zLadderRef'])

    const withClient = await keyClassLog({
      client: { member: `${DID}#zClientRef` },
      ladder: agreeingLadder
    })
    expect(enrolledClientKeyMultibases({ doc: withClient[0]!.state })).toEqual(
      new Set(['zClientRef'])
    )
    expect(accountLogDids({ log: withClient }).clientDids).toEqual(
      new Set(['did:key:zClientRef'])
    )
  })

  it('read a publicKeyMultibase whose id carries no fragment as the key', async () => {
    const log = await keyClassLog({
      client: { member: { id: DID, publicKeyMultibase: 'zClientOnly' } },
      ladder: agreeingLadder
    })
    const doc = log[0]!.state
    expect(enrolledClientKeyMultibases({ doc })).toEqual(
      new Set(['zClientOnly'])
    )
    expect(accountLogDids({ log }).clientDids).toEqual(
      new Set(['did:key:zClientOnly'])
    )
    // The fragmentless id is still an enrolled client to the rung walk, so
    // the genesis shape (no client published) does not apply: no rung named.
    const [head] = await attributeLadderRungsPerVersion(log)
    expect(head!.size).toBe(0)
  })

  it('name no key for a member whose fragment and publicKeyMultibase disagree', async () => {
    const log = await keyClassLog({
      client: { member: `${DID}#zClient`, method: method('zClient', 'zOther') },
      ladder: { member: `${DID}#zLadder`, method: method('zLadder', 'zElse') }
    })
    const doc = log[0]!.state
    expect(enrolledClientKeyMultibases({ doc })).toEqual(new Set())
    expect(ladderVmKeyMultibases({ doc })).toEqual(new Set())
    expect(accountLogDids({ log })).toEqual({
      clientDids: new Set(),
      ladderDids: new Set()
    })
    // With the client unnamed the entry reads as publishing no client, and
    // with the ladder unnamed there is no ladder to anchor: nothing is
    // attributed under either reading of the mismatched members.
    const [head] = await attributeLadderRungsPerVersion(log)
    expect(head!.size).toBe(0)
  })

  it('agree with the rung walk and the census on a well-formed document', async () => {
    const log = await keyClassLog({ client: agreeing, ladder: agreeingLadder })
    const doc = log[0]!.state
    expect(enrolledClientKeyMultibases({ doc })).toEqual(new Set(['zClient']))
    expect(ladderVmKeyMultibases({ doc })).toEqual(new Set(['zLadder']))
    expect(accountLogDids({ log })).toEqual({
      clientDids: new Set(['did:key:zClient']),
      ladderDids: new Set(['did:key:zLadder'])
    })
    // A client is published in the same entry, so the entry is the bind
    // shape rather than the ladder-anchored genesis: no rung is named.
    const [head] = await attributeLadderRungsPerVersion(log)
    expect(head!.size).toBe(0)
  })

  it('keep ladder recognition id-keyed: an id-less embedded delegation member is no ladder VM', () => {
    expect(
      ladderVmKeyMultibases({
        doc: { capabilityDelegation: [{ publicKeyMultibase: 'zAnonymous' }] }
      })
    ).toEqual(new Set())
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

    const ladderKeys = ladderVmKeyMultibases({ doc })
    expect(ladderVmIds({ doc })).toEqual([`${DID}#zLadder`])
    expect(ladderKeys).toEqual(new Set(['zLadder']))
    expect(inventory.ladderKeys).toEqual(ladderKeys)
    expect(inventory.enrolledClientKeys).toEqual(
      enrolledClientKeyMultibases({ doc })
    )

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

  it('reads both key classes under the one key-multibase rule', async () => {
    // A ladder VM and an enrolled client whose fragment and resolved
    // `publicKeyMultibase` disagree name no key, and a ladder VM reference
    // nothing backs names its key by fragment alone -- the same answers the
    // rung attribution and the did:key census give over this document.
    const base = inventoryDocument()
    const doc = {
      ...base,
      verificationMethod: [
        ...(base.verificationMethod as Array<Record<string, unknown>>).filter(
          method => method.id !== `${DID}#zLadder`
        ),
        {
          id: `${DID}#zLadder`,
          type: 'Multikey',
          controller: DID,
          publicKeyMultibase: 'zOther'
        },
        {
          id: `${DID}#zClient2`,
          type: 'Multikey',
          controller: DID,
          publicKeyMultibase: 'zElse'
        }
      ],
      capabilityInvocation: [`${DID}#zClient`, `${DID}#zClient2`],
      capabilityDelegation: [
        `${DID}#zClient`,
        `${DID}#zClient2`,
        `${DID}#zLadder`,
        `${DID}#zUnbacked`
      ]
    }
    const log = [{ versionId: '1-v1', state: doc }] as unknown as DIDLog
    const inventory = await webvhResourceLogController({
      did: DID,
      log
    }).inventoryAt()
    expect(inventory.ladderKeys).toEqual(new Set(['zUnbacked']))
    expect(inventory.ladderKeys).toEqual(ladderVmKeyMultibases({ doc }))
    expect(inventory.inventoryKeys.has('zOther')).toBe(false)
    expect(inventory.enrolledClientKeys).toEqual(new Set(['zClient']))
    expect(inventory.enrolledClientKeys).toEqual(
      enrolledClientKeyMultibases({ doc })
    )
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
