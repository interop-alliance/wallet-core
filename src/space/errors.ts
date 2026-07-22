/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A user-facing error whose `message` is safe to show verbatim. Carries the name
 * `'HumanReadableError'` so an app that classifies errors by `name` (rather than
 * by `instanceof`, which fails across module realms) treats a wallet-core error
 * the same as its own. Thrown by `parseWasLinkPayload` for every malformed /
 * wrong-version / non-link input.
 */
export class HumanReadableError extends Error {
  constructor(message: string) {
    super(message)
    this.message = message
    this.name = 'HumanReadableError'
  }
}
