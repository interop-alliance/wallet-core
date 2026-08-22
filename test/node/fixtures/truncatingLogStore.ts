/**
 * A read-counting wrapper over a ceremony fixture's account-log store which,
 * from the `fromRead`-th `did.jsonl` read onwards, serves a valid PREFIX of
 * the published log (the last `dropEntries` entries dropped -- a truncated
 * `did.jsonl` text is still a valid log, which is exactly what makes the
 * chain-head pin the only thing that catches it). Shared by every suite that
 * checks a ceremony refuses a served prefix before it publishes anything.
 */
import type { WebvhIdStore } from '../../../src/webvh/didWebvh.js'

/**
 * @param options {object}
 * @param options.idStore {WebvhIdStore}   the fixture's store
 * @param options.dropEntries {number}   how many trailing entries to drop
 * @param [options.fromRead] {number}   the 1-based read from which the
 *   prefix is served (default 1 -- every read)
 * @returns {object}   the wrapped `store` and its `reads` counter
 */
export function truncatingLogStore({
  idStore,
  dropEntries,
  fromRead = 1
}: {
  idStore: WebvhIdStore
  dropEntries: number
  fromRead?: number
}): { store: WebvhIdStore; counter: { reads: number } } {
  const counter = { reads: 0 }
  const store: WebvhIdStore = {
    ...idStore,
    async getIdResourceRaw(options: { resourceId: string }) {
      const served = await idStore.getIdResourceRaw(options)
      if (served === undefined) {
        return served
      }
      counter.reads += 1
      if (counter.reads < fromRead) {
        return served
      }
      const lines = served.text.trimEnd().split('\n')
      return { ...served, text: `${lines.slice(0, -dropEntries).join('\n')}\n` }
    }
  }
  return { store, counter }
}
