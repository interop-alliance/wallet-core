/**
 * A projection store whose every PUT is refused: reads pass through to the
 * fixture's store, and a write throws. Shared by the suites that check a
 * ceremony's rule for a failed `did:web` projection PUT (warned and
 * published past on the seam's `'before'` timing, thrown after the entry on
 * `'after'`, and never attempted on a settled ladder-signed strike).
 */
import type { WebvhIdStore } from '../../../src/webvh/didWebvh.js'

/**
 * @param options {object}
 * @param options.idStore {WebvhIdStore}   the fixture's store
 * @returns {WebvhIdStore}   the refusing wrapper
 */
export function refusingStore({
  idStore
}: {
  idStore: WebvhIdStore
}): WebvhIdStore {
  return {
    ...idStore,
    getIdResourceRaw: read => idStore.getIdResourceRaw(read),
    async putIdResource() {
      throw new Error('the projection PUT was refused')
    }
  }
}
