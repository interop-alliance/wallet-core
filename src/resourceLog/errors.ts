/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The one refusal class the resource-log layer still owns after the generic
 * client side moved to `@interop/vh-resource-log`: the ceremony-tail license
 * refusal. The generic taxonomy (`ResourceLogIntegrityError`,
 * `ResourceLogContinuityError`, `ResourceLogClosedError`,
 * `LogNotConfirmedError`, and the store port's `ResourceLogConflictError`)
 * is the library's; wallet-core re-exports none of it -- one owner per name.
 * Like every class in that taxonomy, this one assigns its `name` string
 * explicitly and is matched by `err.name` across package boundaries (the
 * WC-64 rule; minified class names do not survive bundling).
 */

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
