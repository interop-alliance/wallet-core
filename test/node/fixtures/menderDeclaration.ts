/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * A declaration builder for the mender tests: every field a table row needs,
 * defaulted, so a test states only the members its case turns on.
 */
import type { InvariantDeclaration } from '../../../src/menders/index.js'

export function declaration<Deps>(
  partial: Partial<InvariantDeclaration<Deps>> &
    Pick<InvariantDeclaration<Deps>, 'id' | 'authority'>
): InvariantDeclaration<Deps> {
  return {
    statement: `${partial.id} holds`,
    standsOn: ['client-less', 'enrolled'],
    triggers: ['remembered-login-chain'],
    ceremonies: [],
    evidence: ['verified-log'],
    warn: `Could not converge ${partial.id}; the next login retries`,
    ...partial
  }
}
