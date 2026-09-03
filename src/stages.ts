/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The ceremony stage tokens more than one subpath emits, and nothing else.
 * This module imports nothing, so any layer may take a name from it and a
 * progress display importing one pulls in no ceremony code. A vocabulary only
 * one subpath emits stays with that subpath (`clientAnnex/stages.ts`).
 */

/**
 * The KMS-authentication stage, emitted at the join where a genesis waits on
 * the binding it folds into its entry. Both genesis ceremonies emit it at
 * that same boundary, which is why the name lives here rather than in either
 * of them.
 *
 * It fires whether or not the caller supplied a thunk, since it is a stage
 * boundary of the ceremony rather than a report that a key was minted. It
 * marks the join and not the thunk's own completion: the KMS stage overlaps
 * Space provisioning, and a thunk that finished first would mark out of
 * order.
 */
export const KMS_AUTHENTICATION_STAGE = 'kms-authentication'
