/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The resource-log refusal taxonomy, carried over from the roster's WC-1
 * detached-signature design onto the log design. Two adversarial classes plus
 * two admission refusals:
 *
 * - {@link ResourceLogIntegrityError} -- fabrication: the served log fails
 *   verification on its own terms (parse shape, SCID, chain hashes, proofs,
 *   or the external-authorization rule). Whoever produced it could not make a
 *   log the account's clients would have made.
 * - {@link ResourceLogContinuityError} -- a served log that verifies but
 *   conflicts with what this client has already accepted: a rollback behind
 *   the chain-head pin, a fork off the pinned history, or an SCID/method
 *   switch outside a verified handover. The log may be internally consistent;
 *   it is not the continuation of the history this client pinned.
 * - {@link ResourceLogClosedError} -- an append refused because the verified
 *   head is a terminal handover entry. Not an attack: the log's own authors
 *   closed it, and a verifier of this profile must refuse to extend a closed
 *   log even though nothing currently emits terminal entries.
 * - {@link ResourceLogLicenseError} -- a ladder-signed append outside the
 *   ceremony-tail license. An admission refusal, not log corruption: the
 *   append (attempted, or already served) is not licensed, and the same
 *   append can become licensed after a inventory-changing controller-document
 *   entry -- callers must not treat it with the reject-the-whole-log
 *   severity of the integrity class.
 */

/**
 * A served log failed verification: malformed entries, a non-verifying SCID,
 * a broken hash chain, a failing proof, or a signer the controller document
 * does not back at the entry's anchored version. Fabrication-class: refused
 * as something no enrolled client produced.
 */
export class ResourceLogIntegrityError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'ResourceLogIntegrityError'
  }
}

/**
 * A served log conflicts with this client's chain-head pin: `rollback` (the
 * served head is behind the pinned head -- possibly replication lag; the pin
 * is never regressed and the caller may retry), `fork` (the served log
 * diverges from the pinned history -- both logs are transferable evidence of
 * equivocation, so the served entries ride along), `scid-switch` /
 * `method-switch` (a different log identity or format under the pinned
 * location, outside a verified handover).
 */
export class ResourceLogContinuityError extends Error {
  reason: 'rollback' | 'fork' | 'scid-switch' | 'method-switch'
  pinnedHead: string
  /**
   * On a `fork`, the full served log retained as evidence: every entry is
   * signed, so a conflicting pair of logs under one SCID is transferable,
   * independently verifiable proof of equivocation.
   */
  servedEntries?: unknown[]
  constructor({
    reason,
    pinnedHead,
    servedEntries
  }: {
    reason: 'rollback' | 'fork' | 'scid-switch' | 'method-switch'
    pinnedHead: string
    servedEntries?: unknown[]
  }) {
    super(
      `The served resource log is not a continuation of the pinned history ` +
        `(${reason}; pinned head ${pinnedHead}).`
    )
    this.name = 'ResourceLogContinuityError'
    this.reason = reason
    this.pinnedHead = pinnedHead
    this.servedEntries = servedEntries
  }
}

/**
 * A ladder-signed append outside the ceremony-tail license: it is not the
 * log's first entry, and it does not anchor at a inventory-changing controller
 * document version no verified entry already anchors at or past. Above all
 * this refuses the silent-rekey shape -- a ladder-signed rotation against an
 * unchanged document. Write-time admission class: the log is not corrupt and
 * whoever signed the append genuinely holds the credential; the append is
 * merely unlicensed, and a retry after a inventory-changing document entry may
 * succeed.
 */
export class ResourceLogLicenseError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'ResourceLogLicenseError'
  }
}

/**
 * An append was refused because the log's verified head is a terminal
 * handover entry: the log is closed and names a successor, and this profile
 * forbids extending a history its authors have closed.
 */
export class ResourceLogClosedError extends Error {
  nextLog: { method: string; scid: string }
  constructor({ nextLog }: { nextLog: { method: string; scid: string } }) {
    super(
      'The resource log is closed by a terminal handover entry; appends must ' +
        'go to its successor log.'
    )
    this.name = 'ResourceLogClosedError'
    this.nextLog = nextLog
  }
}
