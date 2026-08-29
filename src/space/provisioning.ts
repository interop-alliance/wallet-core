/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * One-shot wallet Space provisioning: the single mechanism every wallet client
 * runs to create (or re-ensure) a Space, walking the full
 * `WALLET_SPACE_PROVISION_ROSTER` -- the synced feeds plus the non-synced
 * system collections (`id`, `key-map`) -- so a Space's layout never depends on
 * which app happened to provision it.
 */
import type { SpaceDescription, WasClient } from '@interop/was-client'
import { ensureSpace, ensureSpaceAndCollection } from '@interop/was-client/sync'

import {
  WALLET_SPACE_NAME,
  WALLET_SPACE_PROVISION_ROSTER
} from './collections.js'
import type { SpaceProvisionSpec } from './collections.js'

/**
 * Ensures the Space exists and every collection in the wallet Space roster is
 * configured, concurrently -- each collection depends only on the Space
 * existing, and every step is create-if-absent (`ensureSpaceAndCollection` is
 * non-clobbering: an existing Space description, encryption descriptor, or
 * access policy is never overwritten), so an interrupted run is completed by
 * simply re-running. A Space created here gets the app-neutral
 * `WALLET_SPACE_NAME` and each collection its roster display name. Runs
 * controller-tier, but is safe for ANY client the server authorizes as the
 * controller -- the wallet that holds the Space's own root authority AND an
 * enrolled client signing under the account's did:webvh -- because on an
 * already-provisioned Space it only reads; an enrolled client re-running it
 * heals a torn signup's missing collections without touching settled
 * configuration.
 *
 * This declares the encrypted collections but installs no key material: every
 * encrypted collection's descriptor must then get its epoch[0] from
 * `ensureWalletSpaceEpochs` (`@interop/wallet-core/keys`), the EDV-bearing
 * second step kept out of this module so the root barrel stays crypto-free.
 * Reads and writes on an encrypted collection are refused fail-closed until
 * that install lands.
 *
 * @param options {object}
 * @param options.was {WasClient}
 * @param options.spaceId {string}
 * @param options.controllerDid {string}   the Space controller; used only when
 *   the Space does not exist yet
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
  // The Space is ensured ONCE, before the fan-out, and its description is
  // threaded into every branch. Ensuring it inside the fan-out instead had
  // each of the roster's branches describe and configure the same Space
  // concurrently -- nine reads and nine racing writes where one of each does,
  // since none of them can observe another's create.
  const spaceDescription = await ensureSpace({
    was,
    spaceId,
    controllerDid,
    spaceName: WALLET_SPACE_NAME
  })
  await Promise.all(
    WALLET_SPACE_PROVISION_ROSTER.map(spec =>
      ensureCollection({ was, spaceId, controllerDid, spaceDescription, spec })
    )
  )
}

async function ensureCollection({
  was,
  spaceId,
  controllerDid,
  spaceDescription,
  spec: { collectionId, name, encryption, isPublic }
}: {
  was: WasClient
  spaceId: string
  controllerDid: string
  spaceDescription: SpaceDescription
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
      spaceDescription,
      spaceName: WALLET_SPACE_NAME
    })
  } catch (err) {
    throw new Error(
      `Error provisioning collection "${collectionId}" in space "${spaceId}".`,
      { cause: err }
    )
  }
}
