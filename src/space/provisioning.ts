/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * One-shot wallet Space provisioning: the single mechanism both wallet apps run
 * when they are the wallet that creates (or re-ensures) a Space, walking the
 * full `WALLET_SPACE_PROVISION_ROSTER` -- the synced feeds plus the non-synced
 * system collections (`id`, `key-map`) -- so a Space's layout never depends on
 * which app happened to provision it.
 */
import type { WasClient } from '@interop/was-client'
import { ensureSpaceAndCollection } from '@interop/was-client/sync'

import {
  WALLET_SPACE_NAME,
  WALLET_SPACE_PROVISION_ROSTER
} from './collections.js'
import type { SpaceProvisionSpec } from './collections.js'

/**
 * Ensures the controller's Space exists and every collection in the wallet
 * Space roster is configured, concurrently -- each collection depends only on
 * the Space existing, and every step is an idempotent upsert, so an interrupted
 * run is completed by simply re-running. The Space is (re)configured with the
 * app-neutral `WALLET_SPACE_NAME` and each collection with its roster display
 * name. Runs full-tier -- the client invokes its own root capability -- so this
 * belongs only in the wallet that holds the Space's controller; an enrolled
 * client joining a Space another wallet provisioned must not call it (a
 * re-declaration could clobber collection configuration other clients depend
 * on).
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.controllerDid {string}   the Space controller
 * @returns {Promise<void>}
 */
export async function provisionWalletSpace({
  was,
  spaceId,
  controllerDid
}: {
  was: WasClient
  spaceId: string
  controllerDid: string
}): Promise<void> {
  await Promise.all(
    WALLET_SPACE_PROVISION_ROSTER.map(spec =>
      ensureCollection({ was, spaceId, controllerDid, spec })
    )
  )
}

async function ensureCollection({
  was,
  spaceId,
  controllerDid,
  spec: { collectionId, name, encryption, isPublic }
}: {
  was: WasClient
  spaceId: string
  controllerDid: string
  spec: SpaceProvisionSpec
}): Promise<void> {
  try {
    await ensureSpaceAndCollection({
      was,
      spaceId,
      controllerDid,
      collectionId,
      collectionName: name,
      encryption,
      isPublic,
      spaceName: WALLET_SPACE_NAME
    })
  } catch (err) {
    // An encrypted collection whose descriptor already carries key epochs (a
    // share, or a recovery escrow) refuses the bare `edv` re-declaration: the
    // PUT would drop the append-only epochs and the server rejects it. A
    // name-only configure merges the current description forward, re-stating
    // the standing descriptor (epochs included) verbatim -- the idempotent form
    // of "ensure it exists". The original error is still logged on a successful
    // retry: the retry also masks failures that were never the epoch refusal
    // (including a failed Space-description PUT, which `ensureSpaceAndCollection`
    // performs FIRST), and those should stay visible even when the narrower
    // configure happens to land.
    if (encryption === 'edv') {
      try {
        await was.space(spaceId).collection(collectionId).configure({ name })
        console.warn(
          `Collection "${collectionId}" was ensured via the name-only retry; ` +
            'the full ensure had failed with:',
          err
        )
        return
      } catch {
        // Fall through to the wrapped throw below, keeping the original
        // (full-ensure) error as the cause.
      }
    }
    throw new Error(
      `Error provisioning collection "${collectionId}" in space "${spaceId}".`,
      { cause: err }
    )
  }
}
