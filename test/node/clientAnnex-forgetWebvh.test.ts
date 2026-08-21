/**
 * Unit tests for the ladder-signed forget entry
 * (`forgetWebvhClient` in `src/unlock/standingWebvh.ts`) against an in-memory
 * store: the one atomic reveal-and-remove entry (the forgotten client's whole
 * document footprint out, the acting rung in with its hash kept committed),
 * its idempotent re-run, the last-durable-client refusal, the fail-closed
 * attribution for a foreign ladder, and the revealed-rung residue being
 * consumed by the credential's next self-enrollment.
 */
import { describe, expect, it } from 'vitest'
import {
  defaultWebvhLogVerifier,
  deriveNextKeyHash,
  readLogFromString,
  resolveDIDFromLog
} from '@interop/did-method-webvh'
import { generateLadderSeed, ladderRung } from '../../src/clientAnnex/ladder.js'
import {
  forgetWebvhClient,
  LastDurableClientForgetError,
  selfEnrollWebvhClient
} from '../../src/clientAnnex/ladderAnchored.js'
import {
  publishUnlockKey,
  unlockKeyVmId
} from '../../src/unlock/standingWebvh.js'
import type { StandingUnlockKeys } from '../../src/unlock/standingWebvh.js'
import { LadderAttributionError } from '../../src/clientAnnex/ladder.js'
import {
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase,
  type ClientWebvhUpdateKeys,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-forget'

/**
 * Provisions a fresh in-memory did:webvh log for one enrolled client.
 */
async function provisionedLog(): Promise<{
  idStore: WebvhIdStore
  log: () => string | undefined
  updateKeys: ClientWebvhUpdateKeys
  did: string
}> {
  const { idStore, log } = memoryIdStore()
  const updateKeys = await mintClientWebvhUpdateKeys()
  const { did } = await ensureDidWebvh({
    idStore,
    wasServerUrl: WAS_URL,
    spaceId: SPACE_ID,
    clientKeys: { ...CANONICAL_CLIENT_KEYS[0] },
    updateKeys
  })
  return { idStore, log, updateKeys, did }
}

/**
 * Resolves the store's current log with full verification.
 */
async function resolved(log: () => string | undefined) {
  const result = await resolveDIDFromLog(readLogFromString(log()!), {
    verifier: defaultWebvhLogVerifier
  })
  expect(result.meta.error).toBeUndefined()
  return result
}

/**
 * A standing passphrase-shaped credential: a fresh ladder and its
 * commitment-published posture (rung 0 committed, key-agreement key hashed).
 */
async function standingCredential() {
  const ladderSeed = generateLadderSeed()
  const rung0 = await ladderRung({ ladderSeed, index: 0 })
  const keyAgreementKeyMultibase =
    CANONICAL_CLIENT_KEYS[9].keyAgreementKeyMultibase
  const unlockKeys: StandingUnlockKeys = {
    keyAgreement: {
      commitment: await keyAgreementCommitment({ keyAgreementKeyMultibase })
    },
    updateKeyMultibase: rung0.keyMultibase
  }
  return { ladderSeed, rung0, unlockKeys }
}

/**
 * A freshly minted ordinary client's public halves plus its update seeds.
 */
async function mintedNewClient(index: number) {
  const seeds = await mintClientWebvhUpdateKeys()
  return {
    seeds,
    keys: {
      ...CANONICAL_CLIENT_KEYS[index]!,
      updateKeyMultibase: await updateKeyMultibase({ seed: seeds.updateSeed }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: seeds.stagedSeed
      })
    }
  }
}

/**
 * An account with a bound credential and one self-enrolled second client (the
 * remembered browser the forget removes): after the self-enrollment, rung 0
 * is spent and rung 1 stands committed.
 */
async function boundAndEnrolled() {
  const provisioned = await provisionedLog()
  const credential = await standingCredential()
  await publishUnlockKey({
    idStore: provisioned.idStore,
    updateKeys: provisioned.updateKeys,
    unlockKeys: credential.unlockKeys
  })
  const enrolled = await mintedNewClient(3)
  await selfEnrollWebvhClient({
    store: provisioned.idStore,
    ladderSeed: credential.ladderSeed,
    newClientKeys: enrolled.keys,
    newClientUpdateSeeds: enrolled.seeds,
    expectedDid: provisioned.did
  })
  return { ...provisioned, credential, enrolled }
}

describe('forgetWebvhClient', () => {
  it('removes the client in one ladder-signed entry and keeps the rung committed', async () => {
    const { idStore, log, did, credential, enrolled } = await boundAndEnrolled()
    const entriesBefore = readLogFromString(log()!).length

    const removed = await forgetWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      forgottenClient: {
        signingKeyMultibase: enrolled.keys.signingKeyMultibase,
        updateKeyMultibase: enrolled.keys.updateKeyMultibase
      },
      expectedDid: did
    })
    expect(removed.did).toBe(did)
    // ONE atomic entry: no separate reveal-and-commit.
    expect(readLogFromString(log()!).length).toBe(entriesBefore + 1)

    const state = await resolved(log)
    const signingVmId = `${did}#${enrolled.keys.signingKeyMultibase}`
    const kaVmId = `${did}#${enrolled.keys.keyAgreementKeyMultibase}`
    // The client's whole footprint is out: both verification methods, all
    // five relations, its update key, and both its standing commitments (the
    // staged hash recovered by log attribution).
    expect(
      state.doc?.verificationMethod?.map(method => method.id)
    ).not.toContain(signingVmId)
    expect(
      state.doc?.verificationMethod?.map(method => method.id)
    ).not.toContain(kaVmId)
    expect(state.doc?.authentication ?? []).not.toContain(signingVmId)
    expect(state.doc?.assertionMethod ?? []).not.toContain(signingVmId)
    expect(state.doc?.capabilityInvocation ?? []).not.toContain(signingVmId)
    expect(state.doc?.capabilityDelegation ?? []).not.toContain(signingVmId)
    expect(state.doc?.keyAgreement ?? []).not.toContain(kaVmId)
    expect(state.meta.updateKeys).not.toContain(
      enrolled.keys.updateKeyMultibase
    )
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(enrolled.keys.updateKeyMultibase)
    )
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(enrolled.keys.stagedUpdateKeyMultibase)
    )

    // The acting rung (rung 1 -- rung 0 was spent by the self-enrollment)
    // stands revealed with its own hash kept committed, and the first
    // client and the credential's posture are untouched.
    const rung1 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 1
    })
    expect(state.meta.updateKeys).toContain(rung1.keyMultibase)
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(rung1.keyMultibase)
    )
    expect(state.doc?.capabilityInvocation).toContain(
      `${did}#${CANONICAL_CLIENT_KEYS[0].signingKeyMultibase}`
    )
    expect(state.doc?.keyAgreement).toContain(
      unlockKeyVmId({ did, keyAgreement: credential.unlockKeys.keyAgreement })
    )

    // Idempotent: a re-run finds nothing left and publishes nothing.
    await forgetWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      forgottenClient: {
        signingKeyMultibase: enrolled.keys.signingKeyMultibase,
        updateKeyMultibase: enrolled.keys.updateKeyMultibase
      },
      expectedDid: did
    })
    expect(readLogFromString(log()!).length).toBe(entriesBefore + 1)
  })

  it('lets the next self-enrollment consume the revealed rung', async () => {
    const { idStore, log, did, credential, enrolled } = await boundAndEnrolled()
    await forgetWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      forgottenClient: {
        signingKeyMultibase: enrolled.keys.signingKeyMultibase,
        updateKeyMultibase: enrolled.keys.updateKeyMultibase
      },
      expectedDid: did
    })

    const next = await mintedNewClient(4)
    await selfEnrollWebvhClient({
      store: idStore,
      ladderSeed: credential.ladderSeed,
      newClientKeys: next.keys,
      newClientUpdateSeeds: next.seeds,
      expectedDid: did
    })
    const state = await resolved(log)
    const rung1 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 1
    })
    const rung2 = await ladderRung({
      ladderSeed: credential.ladderSeed,
      index: 2
    })
    expect(state.meta.updateKeys).toContain(next.keys.updateKeyMultibase)
    expect(state.meta.updateKeys).not.toContain(rung1.keyMultibase)
    expect(state.meta.nextKeyHashes).not.toContain(
      await deriveNextKeyHash(rung1.keyMultibase)
    )
    expect(state.meta.nextKeyHashes).toContain(
      await deriveNextKeyHash(rung2.keyMultibase)
    )
  })

  it('refuses to forget the last enrolled durable client', async () => {
    const { idStore, updateKeys, did } = await provisionedLog()
    const credential = await standingCredential()
    await publishUnlockKey({
      idStore,
      updateKeys,
      unlockKeys: credential.unlockKeys
    })

    let refused: unknown
    try {
      await forgetWebvhClient({
        store: idStore,
        ladderSeed: credential.ladderSeed,
        forgottenClient: {
          signingKeyMultibase: CANONICAL_CLIENT_KEYS[0].signingKeyMultibase,
          updateKeyMultibase: await updateKeyMultibase({
            seed: updateKeys.updateSeed
          })
        },
        expectedDid: did
      })
    } catch (err) {
      refused = err
    }
    expect(refused).toBeInstanceOf(LastDurableClientForgetError)
    // The name is the stable contract consumers match on.
    expect((refused as Error).name).toBe('LastDurableClientForgetError')
  })

  it('fails closed for a ladder the log does not attribute', async () => {
    const { idStore, did, enrolled } = await boundAndEnrolled()
    await expect(
      forgetWebvhClient({
        store: idStore,
        ladderSeed: generateLadderSeed(),
        forgottenClient: {
          signingKeyMultibase: enrolled.keys.signingKeyMultibase,
          updateKeyMultibase: enrolled.keys.updateKeyMultibase
        },
        expectedDid: did
      })
    ).rejects.toThrow(LadderAttributionError)
  })
})
