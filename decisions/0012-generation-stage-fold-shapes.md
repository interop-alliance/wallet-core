# 0012: The annex-generation stage is not parameterized by entry-fold shape

- Status: accepted
- Date: 2026-08-25
- Driving work: the same extraction as decisions/0011. Its consumer
  enumeration found the annex-generation block (mint the generation
  under a bootstrap identity, embed the ladder-signed generation
  delegation, flip the annex Space's controller, publish the
  `#DelegatedClients` pointer) hand-composed in three app-side places
  beyond the establishment's own stage, and the question was whether one
  shared primitive should absorb all of them.
- Affects: wallet-core `/clientAnnex` (the exported generation-stage
  primitive and `establishCredentialAnchoredAccount`'s stage 3) and
  `/recovery` (`recoverWebvhLadderAnchored`, which keeps its inline
  fold); freewallet's add/change-method ceremonies as consumers of the
  primitive.

## Context

The block exists in two structurally different fold shapes.

In the common shape, the `#DelegatedClients` pointer publishes as its
own account-log entry, strictly last in the block, so pointer-present
implies every prior sub-step landed and a torn run re-runs cleanly.
The credential-anchored establishment's stage 3 and the
add/change-method ceremonies' annex block have this shape.

The transient recovery spend has the other shape: its pointer move
rides the add-and-retire entry itself, atomically. That entry retires
the pre-recovery credential's ladder VM in the same breath, and a
pointer written as a separate later entry would open a window where the
account document names a generation that no surviving record's sibling
delegation targets -- neither the spent code nor the fresh credential
could enroll a client during it. The atomic placement is a safety
property of the recovery ceremony, not a stylistic variant.

## Decision

The shared generation-stage primitive implements the separate-pointer-
entry shape only, and same-shape folds consume it: the establishment's
stage 3 and the add/change-method ceremonies' annex block. The
transient recovery spend keeps its inline fold, with the atomic
pointer-move rationale stated at that ceremony. The primitive takes no
fold-shape flag.

## Rejected Alternatives

- **A shape-parameterized primitive.** A flag selecting where the
  pointer entry lands would put two entry-fold semantics in one
  function, and the recovery shape's safety property would become a
  flag value a caller can get wrong instead of a structural fact of
  that ceremony's one log append.
- **The recovery spend adopts the separate-entry shape.** Reopens the
  unenrollable window described above; rejected outright.
- **Every fold stays inline (no primitive).** Leaves the block's
  ordering rules in multiple hand-ordered copies, where a correction
  lands in one wallet or one ceremony only -- the defect class the
  parent extraction exists to end.

## Consequences

- The block has exactly two homes: the shared primitive and the
  recovery spend's inline fold. An ordering correction to the shared
  shape does not automatically reach the recovery fold; a change to
  either must be checked against the other by hand, and this record is
  the pointer that says so.
- Same-shape consumers stop diverging: before this decision, one
  hand-composed copy already ordered promotion before the generation
  block, and a test fixture composed the stages in a third order.
- The primitive's contract stays simple enough to state in one
  sentence, which is what makes its consumers auditable.

## Revisit Criteria

1. A third ceremony needs the atomic shape. The remedy is a second
   primitive for that shape (sharing sub-step helpers with the first),
   not a shape flag on this one.
2. The recovery spend's entry fold changes for its own reasons (for
   example, the add-and-retire entry stops retiring ladder VMs), which
   would dissolve the safety property that keeps its fold inline.
