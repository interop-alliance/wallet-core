/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one refusal class the resource-log layer still owns after the generic
 * client side moved to `@interop/vh-resource-log` -- the ceremony-tail
 * license refusal -- and the shared read-side classification of that
 * library's taxonomy ({@link isResourceLogRefusal}: which refusals a caller
 * must not paper over with a cached copy). The generic taxonomy
 * (`ResourceLogIntegrityError`, `ResourceLogContinuityError`,
 * `ResourceLogClosedError`, `LogNotConfirmedError`, and the store port's
 * `ResourceLogConflictError`) is the library's; wallet-core re-exports none
 * of it -- one owner per name. Like every class in that taxonomy, this one
 * assigns its `name` string explicitly and is matched by `err.name` across
 * package boundaries (the WC-64 rule; minified class names do not survive
 * bundling), which is also why the predicate compares names rather than
 * constructors and why this file stays import-free.
 */

/**
 * A ladder-signed append outside the ceremony-tail license: it is not the
 * log's first entry, and it does not carry an inventory-changing controller
 * document version no verified entry already carries at or past. Above all
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
 * Whether a resource-log refusal is one a caller must NOT paper over with a
 * cached copy: a fabricated log (`ResourceLogIntegrityError`), or a log that
 * is not the continuation of the pinned history
 * (`ResourceLogContinuityError`) -- EXCEPT continuity reason `rollback`.
 *
 * This is the one implementation of the rollback carve-out ARCHITECTURE.md
 * states once as policy. A rollback is reconcilable divergence, possibly
 * nothing worse than replication lag: the pin is never regressed and nothing
 * rolled back is adopted, so serving the cached copy while a lagging replica
 * catches up is exactly the offline case, and refusing there would lock a
 * healthy account out of its own start. A `fork` or an SCID/method switch is
 * a refusal like fabrication.
 *
 * `ResourceLogLicenseError` is deliberately absent, so a license refusal on a
 * READ lands in the soft transport class (warn, serve cached). Ratified
 * behavior, not omission: the log is not corrupt and the signer genuinely
 * holds the credential, so the append is unlicensed rather than forged. The
 * two shapes that argues against -- a compromised still-listed key holder,
 * and a genuine unlicensed entry N masking a forged entry N+1 under whole-log
 * first-failure semantics -- were weighed and accepted (WC-149). The
 * pre-write half of the license is where the class does its work: a
 * conformant writer is refused before an unlicensed entry can land.
 *
 * Matched on `err.name` rather than `instanceof`: these errors are raised
 * inside app-injected seams that can resolve to a different copy of this
 * package (linked, or duplicated through a dependency tree), and an
 * `instanceof` miss would drop a security refusal into a caller's
 * warn-and-proceed branch. Callers add only the names the generic taxonomy
 * does not carry.
 *
 * @param err {unknown}
 * @returns {boolean}
 */
export function isResourceLogRefusal(err: unknown): boolean {
  const candidate = err as { name?: unknown; reason?: unknown } | null
  if (candidate?.name === 'ResourceLogIntegrityError') {
    return true
  }
  return (
    candidate?.name === 'ResourceLogContinuityError' &&
    candidate.reason !== 'rollback'
  )
}
