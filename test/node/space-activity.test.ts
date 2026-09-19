/**
 * Unit tests for the `wallet-activity` payload builders whose wire shape two
 * wallets must agree on byte for byte (`src/space/activity.ts`): today the
 * Import row a backup-bundle import writes -- its derived id, its fixed
 * summary, and the two optional members it omits rather than writes as
 * `undefined`.
 */
import { describe, expect, it } from 'vitest'
import { contentCid } from '@interop/was-client/sync'
import {
  ACTIVITY_TYPE,
  addHistoryContentImported
} from '../../src/space/activity.js'

const TARGET_DID = 'did:webvh:QmTarget:example.com'

const manifest = {
  'ubc-version': '0.1',
  meta: {
    created: '2026-09-17T10:00:00.000Z',
    createdBy: {
      controller: 'did:webvh:QmSource:example.com',
      client: { name: 'Freewallet', url: 'https://wallet.example.com' }
    }
  },
  spec: {
    id: 'https://w3id.org/pws/wallet-profile',
    version: '0.1',
    url: 'https://w3id.org/pws/wallet-profile'
  }
}

describe('addHistoryContentImported', () => {
  it('builds the full row, stop causes included', () => {
    const activity = addHistoryContentImported({
      targetDid: TARGET_DID,
      manifest,
      provenance: 'unverified',
      collections: {
        'private-credentials': {
          accepted: 12,
          skipped: 1,
          failed: 10,
          stoppedBy: 'QuotaExceededError'
        },
        contacts: { accepted: 3, skipped: 0, failed: 0 }
      },
      stoppedAt: {
        collectionId: 'private-credentials',
        cause: 'QuotaExceededError'
      },
      created: '2026-09-19T12:00:00.000Z'
    })
    expect(activity).toEqual({
      id: contentCid({
        controller: 'did:webvh:QmSource:example.com',
        created: '2026-09-17T10:00:00.000Z'
      }),
      type: ['Import'],
      summary: 'Imported content from a backup bundle.',
      actor: { id: TARGET_DID },
      object: {
        manifest,
        provenance: 'unverified',
        stoppedAt: {
          collectionId: 'private-credentials',
          cause: 'QuotaExceededError'
        },
        collections: {
          'private-credentials': {
            accepted: 12,
            skipped: 1,
            failed: 10,
            stoppedBy: 'QuotaExceededError'
          },
          contacts: { accepted: 3, skipped: 0, failed: 0 }
        }
      },
      created: '2026-09-19T12:00:00.000Z'
    })
    expect(activity.type).toEqual([ACTIVITY_TYPE.Import])
  })

  it('omits stoppedAt and stoppedBy rather than writing them undefined', () => {
    const activity = addHistoryContentImported({
      targetDid: TARGET_DID,
      manifest,
      provenance: 'unverified',
      collections: {
        'wallet-activity': { accepted: 4, skipped: 0, failed: 0 }
      },
      created: '2026-09-19T12:00:00.000Z'
    })
    expect(activity.object).not.toHaveProperty('stoppedAt')
    const collections = (
      activity.object as {
        collections: Record<string, object>
      }
    ).collections
    expect(collections['wallet-activity']).not.toHaveProperty('stoppedBy')
    expect(Object.keys(collections)).toEqual(['wallet-activity'])
  })

  it('derives a stable id from the manifest alone', () => {
    const first = addHistoryContentImported({
      targetDid: TARGET_DID,
      manifest,
      provenance: 'unverified',
      collections: { contacts: { accepted: 1, skipped: 0, failed: 0 } },
      created: '2026-09-19T12:00:00.000Z'
    })
    const second = addHistoryContentImported({
      targetDid: TARGET_DID,
      manifest,
      provenance: 'unverified',
      collections: { contacts: { accepted: 9, skipped: 2, failed: 1 } },
      created: '2026-09-20T08:30:00.000Z'
    })
    expect(second.id).toBe(first.id)
    expect(first.id).toBe(
      contentCid({
        controller: 'did:webvh:QmSource:example.com',
        created: '2026-09-17T10:00:00.000Z'
      })
    )
  })

  it('derives a different id from a different export time', () => {
    const other = addHistoryContentImported({
      targetDid: TARGET_DID,
      manifest: {
        ...manifest,
        meta: { ...manifest.meta, created: '2026-09-18T10:00:00.000Z' }
      },
      provenance: 'unverified',
      collections: {},
      created: '2026-09-19T12:00:00.000Z'
    })
    expect(other.id).not.toBe(
      contentCid({
        controller: 'did:webvh:QmSource:example.com',
        created: '2026-09-17T10:00:00.000Z'
      })
    )
  })

  it('defaults created to now', () => {
    const before = Date.now()
    const activity = addHistoryContentImported({
      targetDid: TARGET_DID,
      manifest,
      provenance: 'unverified',
      collections: {}
    })
    const created = Date.parse(activity.created as string)
    expect(created).toBeGreaterThanOrEqual(before)
    expect(created).toBeLessThanOrEqual(Date.now())
  })
})
