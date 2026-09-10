/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/menders` subpath: the mender registry keyed by
 * invariant. A wallet declares its own table of invariants (data: what must
 * hold between ceremonies) and its own registrations (code: what converges a
 * violated one); this module carries the structure both wallets share.
 *
 * - the vocabularies: `AUTHORITIES`, `TRIGGERS`, `CHAIN_TRIGGERS`,
 *   `ACCOUNT_SHAPES`, `EVIDENCE`, `MEND_OUTCOMES`, `GAP_KINDS`, and
 *   `INVARIANT_IDS`, each an `as const` array with its union
 * - the types: `InvariantDeclaration`, `RegistrationSite`, `Registration`,
 *   `MendOutcome`, `MendReportEntry`, `MendReport`, `InvariantGap`,
 *   `LoginRoute`
 * - the readers: `menderRegistry` (`all`, `byId`, `sites`, `admits`,
 *   `dueAt`), which refuses a duplicated id, an undeclared report, or a
 *   guard on a non-routing site at construction, and `heldAuthorities`, the
 *   held set a session's account-ceremony context derives
 * - the runner: `runMenderBlock`, one try, warn, and skip discipline over
 *   one chain trigger's registrations, `mendReportAccumulator`, the
 *   pre-session report collector its `onOutcome` feeds, and `errorNameOf`,
 *   the name a report carries for a thrown value of any shape
 * - the derived sets a wallet's audit tests pin:
 *   `transientReachableInvariants`, `deriveGaps`, `undeclaredGaps`, and
 *   `undeclaredInvariants`
 *
 * Nothing here executes a ceremony. The runner calls the convergers a
 * wallet registers and nothing else; the ceremonies stay explicit sequenced
 * code, and the registry describes the menders from the outside.
 */
export {
  deriveGaps,
  transientReachableInvariants,
  undeclaredGaps,
  undeclaredInvariants
} from './derive.js'
export { INVARIANT_IDS } from './ids.js'
export type { InvariantId } from './ids.js'
export { heldAuthorities, menderRegistry } from './registry.js'
export type { MenderRegistry, ResolvedAuthority } from './registry.js'
export {
  errorNameOf,
  MEND_REPORT_SHAPE_ERROR,
  mendReportAccumulator,
  runMenderBlock
} from './runner.js'
export type { MendReportAccumulator } from './runner.js'
export type {
  InvariantDeclaration,
  InvariantGap,
  LoginRoute,
  MendOutcome,
  MendReport,
  MendReportEntry,
  Registration,
  RegistrationSite
} from './types.js'
export {
  ACCOUNT_SHAPES,
  AUTHORITIES,
  CHAIN_TRIGGERS,
  EVIDENCE,
  GAP_KINDS,
  MEND_OUTCOMES,
  TRIGGERS
} from './vocabulary.js'
export type {
  AccountShape,
  Authority,
  ChainTrigger,
  Evidence,
  GapKind,
  MendOutcomeKind,
  Trigger
} from './vocabulary.js'
