/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Enrolled-client display labels: the `key-map/client-labels.json` record, a
 * plain-JSON map from a client's signing-key multibase to the human-chosen
 * label a "your wallets" surface shows. The did:webvh document is the roster
 * of record and deliberately carries key material only, so labels live
 * beside the account's other key-map resources instead -- private,
 * capability-gated, and shared by every enrolled client (each wallet app
 * reads and writes the same record).
 *
 * The record is display metadata with no authority: a missing or malformed
 * record degrades to unlabeled rows, an entry whose key the document no
 * longer lists is simply never shown, and writes are last-write-wins (a lost
 * race costs at most a label). I/O runs through the two-method
 * {@link ClientLabelsStore} seam a wallet app satisfies with its own
 * remote-store class.
 */

/**
 * The Space-side seam: the single `client-labels.json` resource in the
 * private `key-map` collection.
 */
export interface ClientLabelsStore {
  /**
   * The parsed JSON body of `client-labels.json`, or `undefined` when it has
   * never been written.
   */
  get(): Promise<unknown>
  /**
   * Writes (upserts) `client-labels.json`.
   */
  put(options: { content: object }): Promise<void>
}

/**
 * The version-1 labels record: signing-key multibase to label.
 */
export interface ClientLabelsRecord {
  version: 1
  labels: Record<string, string>
}

/**
 * Reads the labels record, degrading to an empty record when it is missing
 * or malformed (labels are display metadata; a broken record must never
 * block a listing).
 *
 * @param options {object}
 * @param options.store {ClientLabelsStore}
 * @returns {Promise<ClientLabelsRecord>}
 */
export async function readClientLabels({
  store
}: {
  store: ClientLabelsStore
}): Promise<ClientLabelsRecord> {
  let body: unknown
  try {
    body = await store.get()
  } catch {
    return { version: 1, labels: {} }
  }
  if (body === null || typeof body !== 'object') {
    return { version: 1, labels: {} }
  }
  const { version, labels } = body as { version?: unknown; labels?: unknown }
  if (version !== 1 || labels === null || typeof labels !== 'object') {
    return { version: 1, labels: {} }
  }
  const parsed: Record<string, string> = {}
  for (const [key, value] of Object.entries(labels)) {
    if (typeof value === 'string') {
      parsed[key] = value
    }
  }
  return { version: 1, labels: parsed }
}

/**
 * Sets (or renames) one client's label, read-modify-write over the stored
 * record. A blank label removes the entry instead of storing whitespace.
 *
 * @param options {object}
 * @param options.store {ClientLabelsStore}
 * @param options.signingKeyMultibase {string}
 * @param options.label {string}
 * @returns {Promise<ClientLabelsRecord>}   the record as written
 */
export async function setClientLabel({
  store,
  signingKeyMultibase,
  label
}: {
  store: ClientLabelsStore
  signingKeyMultibase: string
  label: string
}): Promise<ClientLabelsRecord> {
  const trimmed = label.trim()
  if (!trimmed) {
    return removeClientLabel({ store, signingKeyMultibase })
  }
  const record = await readClientLabels({ store })
  const updated: ClientLabelsRecord = {
    version: 1,
    labels: { ...record.labels, [signingKeyMultibase]: trimmed }
  }
  await store.put({ content: updated })
  return updated
}

/**
 * Drops one client's label (revocation hygiene -- the label of a
 * disconnected client points at nothing). A record without the entry is a
 * no-op that writes nothing.
 *
 * @param options {object}
 * @param options.store {ClientLabelsStore}
 * @param options.signingKeyMultibase {string}
 * @returns {Promise<ClientLabelsRecord>}   the record as stored
 */
export async function removeClientLabel({
  store,
  signingKeyMultibase
}: {
  store: ClientLabelsStore
  signingKeyMultibase: string
}): Promise<ClientLabelsRecord> {
  const record = await readClientLabels({ store })
  if (!(signingKeyMultibase in record.labels)) {
    return record
  }
  const labels = { ...record.labels }
  delete labels[signingKeyMultibase]
  const updated: ClientLabelsRecord = { version: 1, labels }
  await store.put({ content: updated })
  return updated
}
