/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `./testing` account builder against the real server: each shape is
 * read back from the verified account document and the user key roster, so
 * a wallet's test that starts from a shape starts from the state the
 * ceremonies really leave.
 */
import { WasClient } from '@interop/was-client'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { ladderVmAgent } from '../../src/clientAnnex/index.js'
import {
  rosterWrapsRecipient,
  userKeyRosterDescriptorStore,
  userKeyRosterLogSigner
} from '../../src/keys/index.js'
import { webvhResourceLogController } from '../../src/resourceLog/index.js'
import { KEY_MAP_COLLECTION } from '../../src/space/index.js'
import {
  buildEnrolledClientAccount,
  buildPassphraseAccount,
  buildRecoveryCodeAccount,
  buildSecondCredentialAccount
} from '../../src/testing/index.js'
import type { EstablishedAccount } from '../../src/testing/index.js'
import {
  credentialKeyAgreementMethods,
  enrolledClientKeyMultibases,
  ladderVmKeyMultibase,
  ladderVmKeyMultibases,
  MULTIKEY_COMMITMENT_VM_TYPE,
  verifyAccountLog
} from '../../src/webvh/index.js'
import {
  bootServer,
  transientVisit
} from './fixtures/credentialAnchoredAccount.js'

/**
 * The account's verified document.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}
 * @returns {Promise<object>}
 */
async function accountDoc({ account }: { account: EstablishedAccount }) {
  const { doc } = await verifyAccountLog({
    did: account.accountDid,
    spaceId: account.spaceId,
    host: account.serverUrl
  })
  return doc
}

/**
 * The roster's current descriptor, read by a transient visit on the
 * account's credential under its generation delegation.
 *
 * @param options {object}
 * @param options.account {EstablishedAccount}
 * @returns {Promise<object>}
 */
async function rosterDescriptor({ account }: { account: EstablishedAccount }) {
  const visit = await transientVisit({ account })
  const { accountDid: did, spaceId, serverUrl: host } = account
  const read = await userKeyRosterDescriptorStore({
    storageServerUrl: host,
    zcapClient: visit.zcapClient,
    spaceId,
    resolveController: async () =>
      webvhResourceLogController({
        did,
        log: (await verifyAccountLog({ did, spaceId, host })).log
      }),
    pinStore: visit.pinStore,
    signer: userKeyRosterLogSigner({
      keyAgent: await ladderVmAgent({ ladderSeed: account.ladderSeed })
    }),
    capability: visit.generationDelegation
  }).read()
  if (read === null) {
    throw new Error('test: the account has no roster')
  }
  return read.descriptor
}

describe('the ./testing account builder against the real server', () => {
  let server: Awaited<ReturnType<typeof bootServer>>

  beforeAll(async () => {
    server = await bootServer()
  })

  afterAll(async () => {
    await server.close()
  })

  it('builds a passphrase account: one low-entropy credential, no enrolled client', async () => {
    const account = await buildPassphraseAccount({
      serverUrl: server.serverUrl
    })
    const doc = await accountDoc({ account })

    expect([...ladderVmKeyMultibases({ doc })]).toEqual([
      await ladderVmKeyMultibase({ ladderSeed: account.ladderSeed })
    ])
    const members = credentialKeyAgreementMethods({
      doc,
      did: account.accountDid
    })
    expect(members).toHaveLength(1)
    expect(members[0]).toMatchObject({ type: MULTIKEY_COMMITMENT_VM_TYPE })
    expect(members[0]!.ladderCommitment).toEqual(expect.any(String))
    expect(members[0]!.publicKeyMultibase).toBeUndefined()
    expect(enrolledClientKeyMultibases({ doc }).size).toBe(0)
    expect(doc.capabilityInvocation ?? []).toEqual([])

    const roster = await rosterDescriptor({ account })
    expect(
      rosterWrapsRecipient({
        descriptor: roster,
        recipientId: account.standing.recipientKid
      })
    ).toBe(true)
  })

  it('adds a second standing credential beside the first', async () => {
    const account = await buildSecondCredentialAccount({
      serverUrl: server.serverUrl
    })
    const doc = await accountDoc({ account })

    expect(ladderVmKeyMultibases({ doc })).toEqual(
      new Set([
        await ladderVmKeyMultibase({ ladderSeed: account.ladderSeed }),
        await ladderVmKeyMultibase({ ladderSeed: account.second.ladderSeed })
      ])
    )
    const members = credentialKeyAgreementMethods({
      doc,
      did: account.accountDid
    })
    expect(members).toHaveLength(2)
    for (const member of members) {
      expect(member).toMatchObject({ type: MULTIKEY_COMMITMENT_VM_TYPE })
      expect(member.ladderCommitment).toEqual(expect.any(String))
    }

    const roster = await rosterDescriptor({ account })
    for (const recipientId of [
      account.standing.recipientKid,
      account.second.standing.recipientKid
    ]) {
      expect(rosterWrapsRecipient({ descriptor: roster, recipientId })).toBe(
        true
      )
    }

    // The blocking annex rung commit landed: a transient visit on the SECOND
    // credential enrolls into the pointed generation with its own rung 0 and
    // reads a capability-gated Resource under the generation delegation.
    const secondVisit = await transientVisit({
      account: { ...account, ...account.second }
    })
    expect(await secondVisit.readRoster()).toBe(200)
  })

  it('issues a recovery code: a verbatim key, its wrap, and its ladder VM', async () => {
    const account = await buildRecoveryCodeAccount({
      serverUrl: server.serverUrl
    })
    const { client, recoveryKid } = account.recovery
    const doc = await accountDoc({ account })

    const members = credentialKeyAgreementMethods({
      doc,
      did: account.accountDid
    })
    expect(members).toHaveLength(2)
    const codeMember = members.find(
      member => member.publicKeyMultibase === client.keyAgreementKeyMultibase
    )
    expect(codeMember).toMatchObject({ type: 'Multikey' })
    expect(codeMember!.ladderCommitment).toEqual(expect.any(String))
    expect(ladderVmKeyMultibases({ doc })).toContain(
      client.ladderVmKeyMultibase
    )

    const roster = await rosterDescriptor({ account })
    expect(
      rosterWrapsRecipient({ descriptor: roster, recipientId: recoveryKid })
    ).toBe(true)
  })

  it('self-enrolls a client that holds the account authority', async () => {
    const account = await buildEnrolledClientAccount({
      serverUrl: server.serverUrl
    })
    const { client } = account
    const doc = await accountDoc({ account })

    expect(enrolledClientKeyMultibases({ doc })).toEqual(
      new Set([client.signingKeyMultibase])
    )
    expect(doc.capabilityInvocation ?? []).toHaveLength(1)

    const roster = await rosterDescriptor({ account })
    expect(
      rosterWrapsRecipient({
        descriptor: roster,
        recipientId: client.agents.keyAgreementKey.id!
      })
    ).toBe(true)

    // The enrolled client root-invokes as `<accountDid>#<signing key>`: a
    // write into the account Space only the did:webvh controller may make.
    const was = new WasClient({
      serverUrl: account.serverUrl,
      zcapClient: client.zcapClient
    })
    await was
      .space(account.spaceId)
      .collection(KEY_MAP_COLLECTION.id, { encryption: 'plaintext' })
      .resource('builder-probe')
      .put(new TextEncoder().encode('{}'), { contentType: 'application/json' })
  })
})
