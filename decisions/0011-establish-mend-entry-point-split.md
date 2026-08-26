# 0011: The credential-anchored ceremony's establish/mend entry-point split

- Status: accepted
- Date: 2026-08-25
- Driving work: extracting the credential-anchored establishment (the
  ceremony every WAS signup runs) and its torn-state menders out of
  freewallet's app layer into a shared wallet-core ceremony, so the
  sibling mobile wallet consumes the same stage order and an ordering
  correction lands once. The design review surfaced that the menders had
  already grown a third hand-ordered copy at a login call site, which is
  the failure mode the extraction exists to end.
- Affects: wallet-core `/clientAnnex` (the exported entry points
  `establishCredentialAnchoredAccount`, `mendCredentialAnchoredAccount`,
  and `ensureCredentialClientAnnexGeneration`); freewallet and dcw as
  callers of all three.

## Context

The establishment's stages invoke at the Space root under the ladder
VM's bare did:key -- the bootstrap identity that exists before any
client does. Its final stage promotes the Space controller to the
account did:webvh, after which those bootstrap root invocations stop
verifying under the current-key-set rule. Two of the ceremony's tear
states arise only on a promoted account (a run torn between the record
re-bind and the promotion; an incomplete roster-and-epochs state behind
a promoted controller), so mending them requires post-promotion
authority: signatures by the ladder VM, invocation under a
caller-supplied capability such as a transient visit's generation
delegation. The establishment's bootstrap stages must not learn to hold
that authority.

A third entry point already existed with a different contract again:
the generation-readiness ensure
(`ensureCredentialClientAnnexGeneration`) runs on every transient
visit, healthy or not -- its renew-precedes-mint behavior is what the
App Connect grant path depends on -- while tear mending fires only when
a tear is detected.

## Decision

The ceremony's shared surface is three entry points, one per authority
and trigger contract, all in `/clientAnnex`:

- `establishCredentialAnchoredAccount`: the ordered establishment,
  bootstrap authority throughout, every stage an ensure.
- `mendCredentialAnchoredAccount`: a converging ensure over the
  ceremony's tear taxonomy. Arms take caller-supplied post-promotion
  authority, fire per-arm at most once per invocation, and report
  outcomes (existing errors carried as report members) rather than
  throwing per arm, so callers map refusals onto their own taxonomies.
- `ensureCredentialClientAnnexGeneration`: the every-visit
  generation-readiness ensure, unchanged, composed by callers before
  the roster-side mend arms.

The taxonomy-spanning mender is convergence-named ("mend"), not
"repair": in the shared glossary a repair is the mender of last resort,
always qualified by its torn state, and the individual arms are those
menders underneath. The name also stays true if a later migration fires
the same function from an ordinary read's encounter with a torn state
instead of from a login path.

## Rejected Alternatives

- **One mode-forked orchestrator.** A flag selecting establish-vs-mend
  behavior would put both authority models (bootstrap root, delegated
  post-promotion) in one function and make the "every stage is an
  ensure" claim conditional on the mode.
- **The mend swallows the generation-readiness ensure.** Fusing them
  would either run tear detection on every healthy visit or hide the
  readiness ensure's per-visit contract inside an entry point that
  sounds exceptional. It would also re-couple the mender to a
  login-shaped composition exactly as mender triggers are being
  decoupled from login scheduling. A thin wrapper sequencing readiness
  and mend behind one call remains an additive option; fusion does not.
- **The menders stay app-side login branches.** Any other entry into a
  torn account (a durable resume, a recovery tail, a step-up, the
  sibling wallet) silently lacks them; the duplicated detection had
  already demonstrated this by growing a third copy.

## Consequences

- Callers keep one piece of glue the entry points cannot own: after a
  converged pre-promotion arm, the caller re-fetches the refreshed
  unlock record through its own keyring layer and re-enters, carrying a
  caller-side single-shot marker so a host serving a stale record
  cannot drive an unbounded establish/re-fetch/re-enter loop.
- Refusal classes and login copy stay app-side, fed by the mend's
  outcome report; wallet-core learns no app error taxonomy.
- The split is what lets an encounter-triggered caller invoke the mend
  alone, without the every-visit readiness contract riding along.
- Two entry points where one call might have served: the transient
  composition makes two shared-ceremony calls in a fixed order, and
  that order (mend's pre-promotion arm, readiness, roster arms) is the
  caller's to get right until a sequencing wrapper is added.

## Revisit Criteria

1. A second consumer beyond freewallet demonstrates the two-call
   composition being mis-ordered in practice; the remedy is the
   additive sequencing wrapper, not fusion.
2. A storage-server primitive lands that lets bootstrap authority
   survive controller promotion, collapsing the two authority models
   the split exists to separate.
