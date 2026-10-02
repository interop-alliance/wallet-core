/**
 * The ceremony event channel over the recovery-code ceremonies: issuance,
 * revocation, and both spend variants. Each run emits one outcome matching
 * what it returned or threw, its landed stages under the reserved shape, and
 * nothing derived from the code or the fresh credential.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { captureLogger } from '@interop/logger'
import { generateRecoveryCode } from '../../src/recovery/recoveryCode.js'
import { recoveryClientFromCode } from '../../src/recovery/recoveryCode.js'
import {
  publishRecoveryKey,
  recoverWebvhClient,
  RecoveryKeyNotCommittedError,
  removeRecoveryKey
} from '../../src/recovery/recoveryWebvh.js'
import { recoverWebvhLadderAnchored } from '../../src/clientAnnex/recoveryLadderAnchored.js'
import { generateLadderSeed } from '../../src/unlock/unlockRecord.js'
import {
  ensureDidWebvh,
  keyAgreementCommitment,
  mintClientWebvhUpdateKeys,
  updateKeyMultibase,
  type WebvhIdStore
} from '../../src/webvh/didWebvh.js'
import { setLogger } from '../../src/log.js'
import { memoryIdStore } from './fixtures/memoryIdStore.js'
import { CANONICAL_CLIENT_KEYS } from './fixtures/clientKeys.js'

const WAS_URL = 'http://localhost:8080'
const SPACE_ID = 'space-recovery-events'
const FIXTURE_GENERATION =
  'did:webvh:QmAnnexScid:was.example:space:aux-space:gen-aaaaaaaaaaaaaaaa'

let capture: ReturnType<typeof captureLogger>
let previousLogger: ReturnType<typeof setLogger>

beforeEach(() => {
  capture = captureLogger('wc')
  previousLogger = setLogger(capture.logger)
})

afterEach(() => {
  setLogger(previousLogger)
})

/**
 * The captured events of one ceremony, in emit order.
 *
 * @param ceremony {string}
 * @returns {Array<object>}
 */
function eventsOf(ceremony: string) {
  return capture.events.filter(event => event.data?.ceremony === ceremony)
}

/**
 * The outcome events of one ceremony.
 *
 * @param ceremony {string}
 * @returns {Array<object>}
 */
function outcomesOf(ceremony: string) {
  return eventsOf(ceremony).filter(event => event.msg === 'ceremony outcome')
}

/**
 * The stage ids one ceremony's events reported, in order.
 *
 * @param ceremony {string}
 * @returns {string[]}
 */
function stagesOf(ceremony: string): string[] {
  return eventsOf(ceremony)
    .filter(event => event.msg === 'ceremony stage')
    .map(event => String(event.data?.stage))
}

/**
 * A fresh in-memory account log with one enrolled client.
 */
async function provisionedLog() {
  const { idStore, log } = memoryIdStore({ spaceId: SPACE_ID })
  const updateKeys = mintClientWebvhUpdateKeys()
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
 * A minted ordinary client's public halves and update seeds.
 */
async function mintedClient() {
  const seeds = mintClientWebvhUpdateKeys()
  return {
    seeds,
    keys: {
      ...CANONICAL_CLIENT_KEYS[3]!,
      updateKeyMultibase: await updateKeyMultibase({ seed: seeds.updateSeed }),
      stagedUpdateKeyMultibase: await updateKeyMultibase({
        seed: seeds.stagedSeed
      })
    }
  }
}

/**
 * A store whose first `did.jsonl` PUTs answer with a stale validator, so the
 * entry built on that head loses its compare-and-swap.
 */
function stalePutEtag({
  idStore,
  puts
}: {
  idStore: WebvhIdStore
  puts: number
}): WebvhIdStore {
  let count = 0
  return {
    ...idStore,
    async putIdResource(options: Parameters<WebvhIdStore['putIdResource']>[0]) {
      const written = await idStore.putIdResource(options)
      count += 1
      return count <= puts ? { etag: '"stale"' } : written
    }
  }
}

/**
 * Issues a code on a fresh account.
 */
async function issuedCode() {
  const provisioned = await provisionedLog()
  const code = await recoveryClientFromCode({ code: generateRecoveryCode() })
  await publishRecoveryKey({
    idStore: provisioned.idStore,
    signer: { kind: 'enrolled', updateKeys: provisioned.updateKeys },
    recovery: {
      keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
      updateKeyMultibase: code.updateKeyMultibase
    },
    ladderSeed: code.ladderSeed
  })
  const replacement = await recoveryClientFromCode({
    code: generateRecoveryCode()
  })
  return { ...provisioned, code, replacement }
}

/**
 * Every value derived from the code or a fresh credential that must never
 * appear in an event.
 */
function forbiddenValues(values: Array<string | undefined>): string[] {
  return values.filter((value): value is string => typeof value === 'string')
}

/**
 * Asserts no captured event's data carries any of `values`.
 */
function expectAbsent(values: string[]): void {
  const serialized = JSON.stringify(capture.events.map(event => event.data))
  for (const value of values) {
    expect(serialized).not.toContain(value)
  }
}

describe('recovery-code issuance and revocation events', () => {
  it('emits one clean outcome and the entry stage per call', async () => {
    const { code, did } = await issuedCode()

    expect(stagesOf('recovery-code-issuance')).toEqual(['inventory-entry'])
    const outcomes = outcomesOf('recovery-code-issuance')
    expect(outcomes).toHaveLength(1)
    expect(outcomes[0]!.level).toBe('info')
    expect(outcomes[0]!.data).toMatchObject({
      ceremony: 'recovery-code-issuance',
      outcome: 'clean'
    })
    expect(typeof outcomes[0]!.data?.run).toBe('string')
    expectAbsent(
      forbiddenValues([
        code.keyAgreementKeyMultibase,
        code.updateKeyMultibase,
        code.ladderVmKeyMultibase,
        code.clientDid,
        did
      ])
    )
  })

  it('reports the split issuance as one run per part', async () => {
    const { idStore, updateKeys } = await provisionedLog()
    const code = await recoveryClientFromCode({ code: generateRecoveryCode() })
    const recovery = {
      keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
      updateKeyMultibase: code.updateKeyMultibase
    }
    for (const part of ['key', 'authority'] as const) {
      await publishRecoveryKey({
        idStore,
        signer: { kind: 'enrolled', updateKeys },
        recovery,
        ladderSeed: code.ladderSeed,
        part
      })
    }
    expect(stagesOf('recovery-code-issuance')).toEqual([
      'key-entry',
      'authority-entry'
    ])
    const runs = outcomesOf('recovery-code-issuance').map(
      event => event.data?.run
    )
    expect(runs).toHaveLength(2)
    expect(runs[0]).not.toBe(runs[1])
  })

  it('emits a clean revocation with its removal stage', async () => {
    const { idStore, updateKeys, code } = await issuedCode()
    await removeRecoveryKey({
      idStore,
      signer: { kind: 'enrolled', updateKeys },
      recovery: {
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      }
    })
    expect(stagesOf('recovery-code-revocation')).toEqual(['inventory-removal'])
    expect(outcomesOf('recovery-code-revocation')).toHaveLength(1)
    expect(outcomesOf('recovery-code-revocation')[0]!.data?.outcome).toBe(
      'clean'
    )
  })
})

describe('recovery-code spend events (remembered)', () => {
  /**
   * Spends the fixture's code on `store` with a fresh client.
   */
  async function spend({
    store,
    code,
    replacement,
    recovered
  }: {
    store: WebvhIdStore
    code: Awaited<ReturnType<typeof issuedCode>>['code']
    replacement: Awaited<ReturnType<typeof issuedCode>>['replacement']
    recovered: Awaited<ReturnType<typeof mintedClient>>
  }) {
    return recoverWebvhClient({
      store,
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      newClientKeys: recovered.keys,
      newClientUpdateSeeds: recovered.seeds,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase,
        ladderVmKeyMultibase: replacement.ladderVmKeyMultibase
      },
      onCommitted: async () => undefined
    })
  }

  it('emits clean on an acting spend and noop on the completed re-run', async () => {
    const { idStore, code, replacement } = await issuedCode()
    const recovered = await mintedClient()

    const first = await spend({ store: idStore, code, replacement, recovered })
    expect(first.committed).toBe(true)
    const firstEvents = eventsOf('recovery-code-spend')
    expect(
      firstEvents
        .filter(event => event.msg === 'ceremony stage')
        .map(event => event.data)
    ).toEqual([
      expect.objectContaining({ stage: 'reveal-commit' }),
      expect.objectContaining({ stage: 'successor-persisted' }),
      expect.objectContaining({ stage: 'add-retire' })
    ])
    expect(firstEvents.some(event => event.data?.prior === true)).toBe(false)
    const [firstOutcome] = outcomesOf('recovery-code-spend')
    expect(firstOutcome!.data?.outcome).toBe('clean')
    expect(firstOutcome!.level).toBe('info')

    capture.events.splice(0)
    const rerun = await spend({ store: idStore, code, replacement, recovered })
    expect(rerun.committed).toBe(false)
    expect(
      eventsOf('recovery-code-spend')
        .filter(event => event.msg === 'ceremony stage')
        .map(event => event.data)
    ).toEqual([
      expect.objectContaining({ stage: 'reveal-commit', prior: true }),
      expect.objectContaining({ stage: 'add-retire', prior: true })
    ])
    const [rerunOutcome] = outcomesOf('recovery-code-spend')
    expect(rerunOutcome!.data?.outcome).toBe('noop')
    expect(rerunOutcome!.level).toBe('debug')
    expect(rerunOutcome!.data?.run).not.toBe(firstOutcome!.data?.run)

    expectAbsent(
      forbiddenValues([
        code.keyAgreementKeyMultibase,
        code.updateKeyMultibase,
        code.clientDid,
        replacement.keyAgreementKeyMultibase,
        replacement.updateKeyMultibase,
        recovered.keys.updateKeyMultibase
      ])
    )
  })

  it('emits refused before a not-committed refusal propagates', async () => {
    const { idStore } = await provisionedLog()
    const code = await recoveryClientFromCode({ code: generateRecoveryCode() })
    const replacement = await recoveryClientFromCode({
      code: generateRecoveryCode()
    })
    await expect(
      spend({
        store: idStore,
        code,
        replacement,
        recovered: await mintedClient()
      })
    ).rejects.toThrow(RecoveryKeyNotCommittedError)
    const outcomes = outcomesOf('recovery-code-spend')
    expect(outcomes).toHaveLength(1)
    expect(outcomes[0]!.level).toBe('warn')
    expect(outcomes[0]!.data).toMatchObject({
      outcome: 'refused',
      errorName: 'RecoveryKeyNotCommittedError'
    })
    expect(outcomes[0]!.err).toBeInstanceOf(RecoveryKeyNotCommittedError)
    expect(stagesOf('recovery-code-spend')).toEqual([])
  })

  it('emits failed when the persist seam throws, leaving the landed stage', async () => {
    const { idStore, code, replacement } = await issuedCode()
    const recovered = await mintedClient()
    await expect(
      recoverWebvhClient({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        newClientKeys: recovered.keys,
        newClientUpdateSeeds: recovered.seeds,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase,
          ladderVmKeyMultibase: replacement.ladderVmKeyMultibase
        },
        onCommitted: async () => {
          throw new Error('disk full')
        }
      })
    ).rejects.toThrow('disk full')
    expect(stagesOf('recovery-code-spend')).toEqual(['reveal-commit'])
    const outcomes = outcomesOf('recovery-code-spend')
    expect(outcomes).toHaveLength(1)
    expect(outcomes[0]!.level).toBe('error')
    expect(outcomes[0]!.data).toMatchObject({
      outcome: 'failed',
      errorName: 'Error'
    })
  })

  it('emits each stage once and one outcome across a lost-then-won CAS', async () => {
    const { idStore, code, replacement } = await issuedCode()
    const recovered = await mintedClient()
    let commits = 0
    const outcome = await recoverWebvhClient({
      store: stalePutEtag({ idStore, puts: 1 }),
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      newClientKeys: recovered.keys,
      newClientUpdateSeeds: recovered.seeds,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase,
        ladderVmKeyMultibase: replacement.ladderVmKeyMultibase
      },
      onCommitted: async () => {
        commits += 1
      }
    })
    expect(outcome.committed).toBe(true)
    // The seam ran once per attempt, so the conflict was really lost once.
    expect(commits).toBe(2)
    expect(stagesOf('recovery-code-spend')).toEqual([
      'reveal-commit',
      'successor-persisted',
      'add-retire'
    ])
    const outcomes = outcomesOf('recovery-code-spend')
    expect(outcomes).toHaveLength(1)
    expect(outcomes[0]!.data?.outcome).toBe('clean')
    // The caught conflict itself emits nothing.
    expect(
      capture.events.some(
        event => event.data?.errorName === 'WebvhLogConflictError'
      )
    ).toBe(false)
  })
})

describe('recovery-code spend events (transient, ladder-anchored)', () => {
  it('emits clean with no account identifier and nothing credential-derived', async () => {
    const { idStore, code, replacement, did } = await issuedCode()
    const ladderSeed = generateLadderSeed()
    const credentialKeyAgreement = {
      commitment: await keyAgreementCommitment({
        keyAgreementKeyMultibase:
          CANONICAL_CLIENT_KEYS[3]!.keyAgreementKeyMultibase
      })
    }
    capture.events.splice(0)
    await recoverWebvhLadderAnchored({
      store: idStore,
      recovery: {
        updateSeed: code.updateSeed,
        keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
        updateKeyMultibase: code.updateKeyMultibase
      },
      ladderSeed,
      credentialKeyAgreement,
      replacement: {
        keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
        updateKeyMultibase: replacement.updateKeyMultibase,
        ladderVmKeyMultibase: replacement.ladderVmKeyMultibase
      },
      onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION })
    })
    expect(stagesOf('recovery-code-spend')).toEqual([
      'reveal-commit',
      'successor-persisted',
      'add-retire'
    ])
    const outcomes = outcomesOf('recovery-code-spend')
    expect(outcomes).toHaveLength(1)
    expect(outcomes[0]!.data?.outcome).toBe('clean')
    expectAbsent(
      forbiddenValues([
        did,
        code.clientDid,
        code.keyAgreementKeyMultibase,
        code.updateKeyMultibase,
        credentialKeyAgreement.commitment,
        FIXTURE_GENERATION
      ])
    )
  })

  it('emits refused when a resume names a head the served log never reached', async () => {
    const { idStore, code, replacement } = await issuedCode()
    const credentialKeyAgreement = {
      commitment: await keyAgreementCommitment({
        keyAgreementKeyMultibase:
          CANONICAL_CLIENT_KEYS[3]!.keyAgreementKeyMultibase
      })
    }
    capture.events.splice(0)
    await expect(
      recoverWebvhLadderAnchored({
        store: idStore,
        recovery: {
          updateSeed: code.updateSeed,
          keyAgreementKeyMultibase: code.keyAgreementKeyMultibase,
          updateKeyMultibase: code.updateKeyMultibase
        },
        ladderSeed: generateLadderSeed(),
        credentialKeyAgreement,
        replacement: {
          keyAgreementKeyMultibase: replacement.keyAgreementKeyMultibase,
          updateKeyMultibase: replacement.updateKeyMultibase,
          ladderVmKeyMultibase: replacement.ladderVmKeyMultibase
        },
        resume: { builtOnHead: { scid: 'QmElsewhere', versionId: '9-x' } },
        onCommitted: async () => ({ clientAnnexDid: FIXTURE_GENERATION })
      })
    ).rejects.toThrow(/has not reached the head/)
    expect(stagesOf('recovery-code-spend')).toEqual([])
    const outcomes = outcomesOf('recovery-code-spend')
    expect(outcomes).toHaveLength(1)
    expect(outcomes[0]!.level).toBe('warn')
    expect(outcomes[0]!.data).toMatchObject({
      outcome: 'refused',
      errorName: 'BuiltOnHeadNotReachedError'
    })
  })
})
