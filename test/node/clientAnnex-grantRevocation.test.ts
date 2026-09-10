/**
 * Unit tests for the recorded-grant revocation
 * (`src/clientAnnex/grantRevocation.ts`): how a server refusal is read
 * against the verified account document (`classifyGrantRevocationRefusal`),
 * and the POST policy around it (`revokeRecordedGrant`: one local skip for a
 * hard-expired grant, everything else POSTed, `AlreadyRevokedError` success,
 * a classifiable plain refusal counted, and every other failure rethrown).
 */
import { describe, expect, it, vi } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import {
  classifyGrantRevocationRefusal,
  embeddedParentCapability,
  isClientAnnexDid,
  revokeRecordedGrant
} from '../../src/clientAnnex/grantRevocation.js'
import { REVOCATION_CLOCK_SKEW_MS } from '../../src/webvh/standingZcap.js'
import {
  accountSignerCheck,
  ENROLLED_SIGNER,
  GONE_SIGNER,
  LADDER_SIGNER,
  recordedGrant,
  SIGNER_FIXTURE
} from '../../src/testing.js'

const { annexDid: ANNEX_DID, oldAnnexDid: OLD_ANNEX_DID } = SIGNER_FIXTURE

describe('classifyGrantRevocationRefusal', () => {
  const NOW = Date.parse('2026-09-10T00:00:00Z')
  // The ladder VM that signed the current generation delegation, and the
  // enrolled client key, are the two `capabilityDelegation` members.
  const check = accountSignerCheck()

  const currentGeneration = {
    controller: ANNEX_DID,
    signerKeyId: LADDER_SIGNER
  }

  it('reads a refusal past expires as expired, with or without a check', () => {
    const expired = recordedGrant({ expires: '2026-09-09T00:00:00Z' })
    expect(classifyGrantRevocationRefusal({ zcap: expired, now: NOW })).toBe(
      'expired'
    )
    expect(
      classifyGrantRevocationRefusal({
        zcap: expired,
        signerCheck: check,
        now: NOW
      })
    ).toBe('expired')
  })

  it('reads a refusal inside the skew band around expires as expired', () => {
    const justAhead = new Date(NOW + REVOCATION_CLOCK_SKEW_MS / 2).toISOString()
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({ expires: justAhead }),
        now: NOW
      })
    ).toBe('expired')
  })

  it('does not read an absent or unparseable expires as expired', () => {
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({ expires: 'soon' }),
        now: NOW
      })
    ).toBeUndefined()
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({ expires: undefined as unknown as string }),
        now: NOW
      })
    ).toBeUndefined()
  })

  it('cannot read a refusal without a check', () => {
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({ signerKeyId: GONE_SIGNER }),
        now: NOW
      })
    ).toBeUndefined()
  })

  it('reads an orphaned account-signed grant', () => {
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({ signerKeyId: GONE_SIGNER }),
        signerCheck: check,
        now: NOW
      })
    ).toBe('orphaned')
  })

  it('cannot read a refusal of an account-signed grant whose signer is still enrolled', () => {
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({ signerKeyId: ENROLLED_SIGNER }),
        signerCheck: check,
        now: NOW
      })
    ).toBeUndefined()
  })

  it('cannot read a refusal of a legacy grant that recorded no signer', () => {
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant(),
        signerCheck: check,
        now: NOW
      })
    ).toBeUndefined()
  })

  it('reads a grant whose embedded parent was signed by a key the document dropped', () => {
    // The current-key-set rule on the PARENT: a generation delegation
    // replaced within its generation (a revocation remint, a signer-death
    // renewal) leaves the old one signed by a struck key, whatever the
    // pointer still says.
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({
          signerKeyId: `${ANNEX_DID}#z6MkVisit`,
          parent: { controller: ANNEX_DID, signerKeyId: GONE_SIGNER }
        }),
        signerCheck: check,
        now: NOW
      })
    ).toBe('signer-gone')
  })

  it('reads an annex-signed grant whose generation was swapped', () => {
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({
          signerKeyId: `${OLD_ANNEX_DID}#z6MkVisit`,
          parent: {
            controller: OLD_ANNEX_DID,
            signerKeyId: LADDER_SIGNER
          }
        }),
        signerCheck: check,
        now: NOW
      })
    ).toBe('generation-swapped')
  })

  it('cannot read a refusal when the document points at no generation', () => {
    // Fail-open: no pointer is no evidence about the generation.
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({
          signerKeyId: `${ANNEX_DID}#z6MkVisit`,
          parent: currentGeneration
        }),
        signerCheck: { ...check, clientAnnexDid: undefined },
        now: NOW
      })
    ).toBeUndefined()
  })

  it('cannot read a refusal of a grant whose embedded parent carries no proof key', () => {
    // Fail-open, as wallet-core's revocation reads it: an uncheckable chain
    // is not a dead one.
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({
          signerKeyId: `${ANNEX_DID}#z6MkVisit`,
          parent: { controller: ANNEX_DID }
        }),
        signerCheck: check,
        now: NOW
      })
    ).toBeUndefined()
  })

  it('takes no pointer reading on an embedded parent that is not an annex delegation', () => {
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({
          signerKeyId: 'did:key:zOther#zOther',
          parent: {
            controller: 'did:key:zOther',
            signerKeyId: ENROLLED_SIGNER
          }
        }),
        signerCheck: check,
        now: NOW
      })
    ).toBeUndefined()
  })

  it('cannot read a refusal of an annex-signed grant under the pointed generation', () => {
    // The visit key is never in the account document, so the orphaned
    // reading must not apply to a grant whose generation still stands.
    expect(
      classifyGrantRevocationRefusal({
        zcap: recordedGrant({
          signerKeyId: `${ANNEX_DID}#z6MkVisit`,
          parent: currentGeneration
        }),
        signerCheck: check,
        now: NOW
      })
    ).toBeUndefined()
  })
})

describe('revokeRecordedGrant', () => {
  const NOW = Date.parse('2026-09-10T00:00:00Z')
  const check = accountSignerCheck()
  function refusing(name: string) {
    const revoke = vi.fn(async () => {
      throw Object.assign(new Error(name), { name })
    })
    return revoke
  }

  it('skips the POST for a grant expired beyond the skew margin', async () => {
    const revoke = vi.fn(async () => {})
    await expect(
      revokeRecordedGrant({
        revoke,
        zcap: recordedGrant({ expires: '2026-09-09T00:00:00Z' }),
        now: NOW
      })
    ).resolves.toBe('expired')
    expect(revoke).not.toHaveBeenCalled()
  })

  it('POSTs a grant expired by less than the skew margin', async () => {
    const revoke = vi.fn(async () => {})
    const justPast = new Date(NOW - REVOCATION_CLOCK_SKEW_MS / 2).toISOString()
    await expect(
      revokeRecordedGrant({
        revoke,
        zcap: recordedGrant({ expires: justPast }),
        now: NOW
      })
    ).resolves.toBe('revoked')
    expect(revoke).toHaveBeenCalledTimes(1)
  })

  it('POSTs an orphaned-looking grant and reads the refusal as orphaned', async () => {
    const revoke = refusing('ValidationError')
    await expect(
      revokeRecordedGrant({
        revoke,
        zcap: recordedGrant({ signerKeyId: GONE_SIGNER }),
        signerCheck: check,
        now: NOW
      })
    ).resolves.toBe('orphaned')
    expect(revoke).toHaveBeenCalledTimes(1)
  })

  it('reads AlreadyRevokedError as already revoked', async () => {
    await expect(
      revokeRecordedGrant({
        revoke: refusing('AlreadyRevokedError'),
        zcap: recordedGrant(),
        now: NOW
      })
    ).resolves.toBe('already-revoked')
  })

  it('rethrows a plain refusal the client cannot read', async () => {
    await expect(
      revokeRecordedGrant({
        revoke: refusing('ValidationError'),
        zcap: recordedGrant({ signerKeyId: ENROLLED_SIGNER }),
        signerCheck: check,
        now: NOW
      })
    ).rejects.toMatchObject({ name: 'ValidationError' })
  })

  it('rethrows every other failure', async () => {
    await expect(
      revokeRecordedGrant({
        revoke: refusing('TypeError'),
        zcap: recordedGrant({ signerKeyId: GONE_SIGNER }),
        signerCheck: check,
        now: NOW
      })
    ).rejects.toMatchObject({ name: 'TypeError' })
  })
})

describe('embeddedParentCapability', () => {
  it('reads the last chain link when it is embedded, and nothing otherwise', () => {
    const parent = { id: 'urn:zcap:parent' }
    expect(
      embeddedParentCapability({
        proof: { capabilityChain: ['urn:zcap:root:x', parent] }
      } as unknown as IZcap)
    ).toBe(parent)
    expect(
      embeddedParentCapability({
        proof: [{ capabilityChain: ['urn:zcap:root:x'] }]
      } as unknown as IZcap)
    ).toBeUndefined()
    expect(embeddedParentCapability({} as IZcap)).toBeUndefined()
  })
})

describe('isClientAnnexDid', () => {
  it('recognizes an annex did:webvh and nothing else', () => {
    expect(
      isClientAnnexDid('did:webvh:scid:h:space:s1:gen-AAAAAAAAAAAAAAAA')
    ).toBe(true)
    expect(isClientAnnexDid('did:webvh:scid:h:x')).toBe(false)
    expect(isClientAnnexDid('did:key:zOther')).toBe(false)
  })
})
