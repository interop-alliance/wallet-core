/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The house staleness policy for standing recorded zcaps
 * (`webvh/standingZcap.ts`): the composed three-axis predicate every re-mint
 * pass and renewal stage asks -- expiry, signer death under the
 * current-key-set rule, and the caller's retiring set read as a projected
 * post-edit document -- in both its shapes, over a delegation in hand and
 * over the `keyId` / `expires` scalars a registry entry records.
 */
import { describe, expect, it } from 'vitest'
import type { IZcap } from '@interop/data-integrity-core'
import {
  recordedZcapStale,
  standingZcapStale,
  ZCAP_RENEWAL_WINDOW_MS
} from '../../src/webvh/standingZcap.js'
import type { PublishedKeyDocument } from '../../src/webvh/listClients.js'

const NOW = Date.parse('2026-08-15T00:00:00Z')
const STANDING_KEY = 'zStandingKey'
const RETIRED_KEY = 'zRetiredKey'
const ACCOUNT_DID = 'did:webvh:scid:example.com:space:sp:id'

/**
 * A fresh expiry: past the renewal window, so the expiry axis is quiet and
 * each test isolates the axis it is about.
 */
const FRESH = new Date(NOW + ZCAP_RENEWAL_WINDOW_MS + 60_000).toISOString()

const doc: PublishedKeyDocument = {
  verificationMethod: [
    { id: `${ACCOUNT_DID}#${STANDING_KEY}`, publicKeyMultibase: STANDING_KEY }
  ],
  capabilityDelegation: [`${ACCOUNT_DID}#${STANDING_KEY}`]
}

describe('recordedZcapStale', () => {
  it('reads a standing key with a fresh expiry as current', () => {
    expect(
      recordedZcapStale({
        doc,
        delegationKeyId: `${ACCOUNT_DID}#${STANDING_KEY}`,
        expires: FRESH,
        now: NOW
      })
    ).toBe(false)
  })

  it('flags the expiry axis whatever the document says', () => {
    expect(
      recordedZcapStale({
        doc,
        delegationKeyId: `${ACCOUNT_DID}#${STANDING_KEY}`,
        expires: new Date(NOW + 1000).toISOString(),
        now: NOW
      })
    ).toBe(true)
    // An unrecorded expiry is uncheckable, so not assumed healthy.
    expect(
      recordedZcapStale({
        doc,
        delegationKeyId: `${ACCOUNT_DID}#${STANDING_KEY}`,
        now: NOW
      })
    ).toBe(true)
  })

  it('flags a signer the document no longer lists under capabilityDelegation', () => {
    expect(
      recordedZcapStale({
        doc,
        delegationKeyId: `${ACCOUNT_DID}#${RETIRED_KEY}`,
        expires: FRESH,
        now: NOW
      })
    ).toBe(true)
  })

  it('flags an unrecorded signer as uncheckable when a document is supplied', () => {
    expect(recordedZcapStale({ doc, expires: FRESH, now: NOW })).toBe(true)
  })

  it('skips the signer-death axis when no document is supplied', () => {
    // The caller holding no verified document opts out of the axis rather
    // than asserting the grant healthy: the other two still apply.
    expect(
      recordedZcapStale({
        delegationKeyId: `${ACCOUNT_DID}#${RETIRED_KEY}`,
        expires: FRESH,
        now: NOW
      })
    ).toBe(false)
    expect(recordedZcapStale({ expires: FRESH, now: NOW })).toBe(false)
  })

  it('flags a key the caller names as retiring, though the document still lists it', () => {
    // The projected post-edit reading: a ceremony acting before the entry
    // that strikes the key lands.
    expect(
      recordedZcapStale({
        doc,
        delegationKeyId: `${ACCOUNT_DID}#${STANDING_KEY}`,
        expires: FRESH,
        retiringKeyMultibases: [STANDING_KEY],
        now: NOW
      })
    ).toBe(true)
    // Named in verification-method form, matched on the multibase.
    expect(
      recordedZcapStale({
        doc,
        delegationKeyId: `did:key:${STANDING_KEY}#${STANDING_KEY}`,
        expires: FRESH,
        retiringKeyMultibases: [`${ACCOUNT_DID}#${STANDING_KEY}`],
        now: NOW
      })
    ).toBe(true)
  })

  it('leaves a standing key the retiring set does not name', () => {
    expect(
      recordedZcapStale({
        doc,
        delegationKeyId: `${ACCOUNT_DID}#${STANDING_KEY}`,
        expires: FRESH,
        retiringKeyMultibases: [RETIRED_KEY],
        now: NOW
      })
    ).toBe(false)
  })
})

describe('standingZcapStale', () => {
  /**
   * A delegation in hand, in the shape the predicate reads: an `expires` and
   * a single proof naming the signing verification method.
   */
  function delegation({
    keyId,
    expires
  }: {
    keyId?: string
    expires?: string
  }): IZcap {
    return {
      ...(expires !== undefined ? { expires } : {}),
      ...(keyId !== undefined ? { proof: { verificationMethod: keyId } } : {})
    } as unknown as IZcap
  }

  it('reads the expiry and proof key off the zcap, agreeing with the scalar shape', () => {
    expect(
      standingZcapStale({
        zcap: delegation({
          keyId: `${ACCOUNT_DID}#${STANDING_KEY}`,
          expires: FRESH
        }),
        doc,
        now: NOW
      })
    ).toBe(false)
    expect(
      standingZcapStale({
        zcap: delegation({
          keyId: `${ACCOUNT_DID}#${RETIRED_KEY}`,
          expires: FRESH
        }),
        doc,
        now: NOW
      })
    ).toBe(true)
  })

  it('flags a proofless zcap as uncheckable against a document', () => {
    expect(
      standingZcapStale({ zcap: delegation({ expires: FRESH }), doc, now: NOW })
    ).toBe(true)
  })

  it('carries the retiring axis through', () => {
    expect(
      standingZcapStale({
        zcap: delegation({
          keyId: `${ACCOUNT_DID}#${STANDING_KEY}`,
          expires: FRESH
        }),
        doc,
        retiringKeyMultibases: [STANDING_KEY],
        now: NOW
      })
    ).toBe(true)
  })
})
