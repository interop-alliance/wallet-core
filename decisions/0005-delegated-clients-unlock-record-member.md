# 0005: The delegatedClients sealed member of the unlock record

- Status: accepted
- Date: 2026-08-19
- Terminology note (2026-08-21): "companion" was since renamed to
  `clientAnnex` ("the client annex"); this record keeps the original
  term. See freewallet roadmap item FW-222.
- Driving work: the public-computer login redesign for the browser
  wallet -- a transient login must reach the companion
  (delegated-clients) log with nothing but the unlock credential, so
  the unlock record gains a second pre-minted delegation beside the
  account-log bridge
- Affects: wallet-core `keyring`/`unlock` (the unlock record codec,
  the bind and re-mint ceremonies) and the unlock-methods registry
  shape; was-client paths helpers (the target construction); every
  unlock record freewallet and dcw write for a standing credential

## Context

The standing credential's bridge delegation targets the account log's
`did.jsonl` only -- deliberately narrow, so credential use stays loud.
The companion log lives elsewhere: flat per-generation collections
inside a stable auxiliary companion Space, capability-gated. A
transient login needs GET and PUT there before it is enrolled
anywhere, and the authority must survive GC swaps without rewriting
every unlock record per cycle. A Space boundary is the one stable
attenuation prefix the zcap target grammar offers, which fixes the
delegation's target shape; the remaining questions were where the
delegation rides and how its staleness is tracked.

## Decision

The unlock record carries a second self-contained
`SealedRecordMember` beside `bridge`, named `delegatedClients`, with
sealed plaintext `{ delegation }`. It is additive within record
version 2.

- Optionality matches `ladder`: absent on recovery codes, which need
  no companion authority. Parsing uses `ladder`'s tolerant handling,
  not `bridge`'s hard refusal.
- The `binding` MAC does not cover it, and the v2 context label
  stays. The member sits under the frame proof like the bridge it
  mirrors; a host-swapped target is bounded by the account document's
  independent service entry, and a wrong Space yields nothing the
  transient login's self-computed ladder keys verify.
- The delegation targets the auxiliary companion Space's
  trailing-slash subtree URL
  (`https://<host>/space/<companionSpaceId>/`), actions GET and PUT.
  Generation coverage comes from generation-id-bounded attenuation over the
  flat `gen-` collection names (@interop/zcap 11.1.0's
  trailing-slash-base semantics), so no GC cycle ever rewrites the
  record or the registry.
- The target is built with was-client's paths helpers. The shipped
  bridge builder's root-anchored URL form is known drift this member
  must not copy; the trailing slash is load-bearing for the
  attenuation semantics.
- The unlock-methods registry entry tracks the member's staleness as
  a second scalar pair beside the bridge's --
  `delegatedClientsKeyId` and `delegatedClientsExpires`, absent for
  recovery codes, mirroring the member's optionality. The re-mint
  stays one atomic pass: both members resealed, one registry-entry
  rewrite. The sibling rots on exactly the bridge's axis (same
  signer, same current-key-set rule, same 30-day renewal window), so
  there is no lifecycle reason to split them.

Recorded with the decision: backwards compatibility was not the
constraint. The greenfield stance applied and rewriting the record
shapes was on the table; version 2 survives because nothing needs
changing, not because it had to be preserved.

## Rejected Alternatives

- Generalizing `bridge` into a keyed map of delegations: a shape
  break on every parse and re-mint site, with no third consumer in
  sight.
- A version-3 binding whose MAC covers the companion Space id: a
  permanent context-label bump that breaks reseal-without-decrypting
  unless the Space id also moves into the cleartext frame.
- Reshaping the registry's staleness tracking into a delegations
  list: uniform only if a third delegation ever appears; a
  discriminant field the two-member reality does not need.

## Consequences

- Record version 2 stays the wire shape; readers that predate the
  member ignore it (tolerant parse), and recovery-code records are
  unchanged.
- The subtree target hands the credential standing GET and PUT over
  the whole auxiliary Space. The Space holds nothing but companion
  logs, so everything the member authorizes is loud by construction.
- The credential-rotation and revocation-cascade re-mint paths now
  reseal two members; a re-mint that handles only `bridge` is
  incomplete.
- The binding MAC not covering the member means a hostile host can
  swap the sealed delegation without tripping the MAC; the bound is
  the document's service entry plus key-verification failure, and it
  is accepted as stated.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A third pre-minted delegation needs to ride the unlock record;
   adopt the keyed-map shape then, as a record version bump, not a
   reinterpretation of version 2.
2. The auxiliary-Space venue changes (generations stop being flat
   collections under one stable Space), which would invalidate the
   generation-independent target this member exists to carry.
