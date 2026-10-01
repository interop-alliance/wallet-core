/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The directory's typed refusal.
 */

/**
 * A write refused because the entry at the party's id carries another
 * `kind` than the one the writing flow writes: a consent for an agent
 * finding an `app` entry, or a wallet-client write finding an agent. A
 * consent that meets it fails closed. Matched by `err.name`, since a caller
 * may hold a second copy of this package.
 */
export class ConnectionKindMismatchError extends Error {
  /**
   * The kind the writing flow writes.
   */
  expectedKind: string
  /**
   * The kind the stored entry carries.
   */
  foundKind: string

  /**
   * @param options {object}
   * @param options.expectedKind {string}
   * @param options.foundKind {string}
   */
  constructor({
    expectedKind,
    foundKind
  }: {
    expectedKind: string
    foundKind: string
  }) {
    super(
      `The connections entry at this party's id is a "${foundKind}" entry; ` +
        `this write is for a "${expectedKind}" entry, so it was refused.`
    )
    this.name = 'ConnectionKindMismatchError'
    this.expectedKind = expectedKind
    this.foundKind = foundKind
  }
}
