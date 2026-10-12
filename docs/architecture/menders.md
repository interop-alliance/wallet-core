<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, and the glossary are in ../../ARCHITECTURE.md;
     the permanent wire-level constants are in wire-constants.md; this file
     holds one topic in full. -->

# The mender registry and the ceremony event channel

## Public surface

The `menders` module is the mender registry keyed by invariant. It holds the
declaration and registration types, the closed vocabularies, the invariant-id
census, the `menderRegistry` readers, the derived-set helpers a wallet's audit
tests pin, and the runner (`runMenderRegistration`, `runMenderBlock`,
`mendReportAccumulator`).

The `ceremonyEvents.ts` root leaf is the ceremony event channel over the
`Logger` seam. It holds `ceremonyEvents`, the per-run emitter (`runId`, `stage`,
`outcome`, `run`) a ceremony's entry point mints, `menderEvent`, the one emit of
a landed mend report entry, and `servedIdentifier`, the sanitizer for a
server-served identifier in event detail.

## The mender registry

A mender is what finishes a torn ceremony or converges ordinary drift, and it
owns no pivot of its own: it detects one violated invariant from durable state
and makes the invariant hold again. The `menders` subpath is the registry that
describes the menders from the outside, keyed by invariant rather than by
ceremony or by login stage. Its unit is the invariant, a present-tense predicate
over the account's server-held state (for a few entries, over the client's local
state) that must hold between ceremonies. Each wallet declares its own table of
invariants against the shared `INVARIANT_IDS` census (`menders/ids.ts`, numbered
in the order the design table assigned them) and registers its own convergers;
wallet-core carries the structure, the vocabularies, the readers, and the
runner, and executes no ceremony itself.

Two closed vocabularies carry the registry (`menders/vocabulary.ts`):

- The authority a converger needs, one of `none` (no account authority: local
  cleanup, reads, writes the visit's own generation delegation covers),
  `account` (either account-authority kind converges it), `enrolled` (an
  enrolled client's key), or `ladder` (a standing credential's ladder). At the
  two chain triggers it is a runtime filter against the held set the session's
  account-ceremony context derives (`heldAuthorities`); everywhere else it is a
  declaration-time claim the entry's own call site checks.
- The trigger, where an invariant is checked today, one of
  `remembered-login-chain` and `transient-login-chain` (the two login chains a
  runner batches registrations for), `login-routing` (invoked by name at a
  routing call site before or during session assembly, and allowed to refuse the
  login), `ceremony-tail` (executed inside a ceremony's own sequenced code,
  reporting through the registry only, and backed by a report-only site as a
  routing trigger is), or `encounter` (run where an ordinary read or write meets
  the state it converges, inside a live session, such as the directory's writer
  sweep at its listing read).

An `encounter` site carries `reachedBy`, the session kinds (`remembered`,
`transient`) that reach its read or write. A `ceremony-tail` site carries the
same member for the ceremony it closes, since a tail on a ceremony only a
remembered session runs (the forget ceremony, update-key rotation) reaches no
credential-only visit. The type requires it on both, and `menderRegistry`
refuses at construction an encounter or tail site with an empty `reachedBy`. It
also refuses a declaration that lists `encounter` or `ceremony-tail` among its
triggers when no site of that trigger reports it, beside the existing refusals
of a duplicated id, an undeclared report, and a guard on a non-routing site. A
tail site has no `converge`, since the ceremony's own sequenced code converges;
the site only says which invariants the tail reports and which session kinds
reach it. Neither an encounter nor a tail site evaluates a declaration's `when`,
which filters chain registrations alone. `transientReachableInvariants` counts
an encounter or tail site only when its `reachedBy` names `transient` and the
ladder held set admits every invariant it reports, the test a transient chain
registration meets. The rule trusts each declaration's `authority`: one claiming
more than what converges it on a transient visit hides a real gap. `deriveGaps`
exempts no trigger: an invariant no site reports derives `none`, and one
reported only at sites a transient visit does not reach (a remembered chain
sweep, an encounter it never meets, a tail on a ceremony it never runs or whose
authority it does not hold) derives `unreachable`.

The menders wallet-core builds, with the invariants each reports, by number in
the census. Their full accounts stay in the topic docs the entries name.

- **Space-controller promotion** -- entry point `ensurePromotedSpaceController`;
  module `genesis`; invariants 12; [account-genesis.md](account-genesis.md).
- **Credential-anchored mend** -- entry point `mendCredentialAnchoredAccount`;
  module `clientAnnex`; invariants 10, 12, 13, 14;
  [account-genesis.md](account-genesis.md).
- **Transient readiness ensure** -- entry point
  `ensureCredentialClientAnnexGeneration`; module `clientAnnex`; invariants 15;
  [account-genesis.md](account-genesis.md).
- **Annex GC pass** -- entry point `runClientAnnexGc`; module `clientAnnex`;
  invariants 15, 19; [account-genesis.md](account-genesis.md).
- **Login-time roster sweep** -- entry point `checkUserKeyRosterAtLogin`,
  `convergeUserKeyRosterToAccount`; module `clients`; invariants 1, 2, 3, 37;
  [keys-and-descriptor-logs.md](keys-and-descriptor-logs.md).
- **Directory writer sweep** -- entry point `sweepConnectionWriters`; module
  `connections`; invariants 35;
  [connections-directory.md](connections-directory.md).

The runner's discipline (`runMenderRegistration`, `runMenderBlock`) is stated in
"The mender runner's discipline" above. The derived sets a wallet's audit tests
pin (`transientReachableInvariants`, `deriveGaps`, `undeclaredGaps`,
`undeclaredInvariants`) are what turn a stated residue with no mender into a
declared gap rather than an undocumented one. The annex GC pass's swap leaves no
such gap for invariant 15 (`annex-generation-is-reachable`). Its fresh genesis
restates the old generation's standing set, and a credential that set does not
carry mints a restating generation at its next visit, transient (the readiness
ensure) or remembered (the GC pass's readmission swap); see
[account-genesis.md](account-genesis.md).

## The mender runner's discipline

`runMenderRegistration` (`menders/runner.ts`) is the one try, warn, and skip
discipline over a single registration. It admits nothing, so its caller checks
the authority first. A wallet runs an encounter registration through it from the
encounter's own call site. `runMenderBlock` applies it over a login chain. It
runs the registrations `dueAt` one chain trigger in list order, admitting each
only when the session holds every reported invariant's declared authority and
every reported declaration's `when(route)` predicate admits this login route. An
optional seed registration runs first, and its failure aborts the block: nothing
behind it runs. Past the seed, a registration that throws warns once per
reported invariant with that declaration's own `warn` string, through the
`Logger` the wallet supplies for the block, and the block continues; the report
carries `err.name` alone, since a thrown message can name a DID or a Space id.
Each entry emits exactly one `'ceremony mender'` event (`menderEvent`), so a
wallet's mend report and the event channel read the same values. The event
carries `errorName` and no `err`. Given a `mends` accumulator, the runner
reports each entry into it, and the accumulator emits the event through its own
`logger`. Without one, the runner emits through the block's `Logger`.
`onOutcome` runs after a registration's entries are reported, once per entry.
`runMenderRegistration` takes the same optional `mends` and never rejects. It
resolves with the entries and whether `converge` threw. A routing site reports
through the same accumulator, so recording an entry and emitting its event are
one call (`report(entry, { err })`). A `ceremony-tail` entry has a report-only
site and no `converge`, so nothing here can fire one outside its ceremony's own
order. `matchesReports` is the one rule for whether a site's entries name its
`reports`, in that order and no others: the runner holds a converging
registration's return to it, and a report-only site holds the entries it records
to the same rule.

## The ceremony event channel

The ceremony event channel (`ceremonyEvents.ts`) is the diagnostics twin of
these outcome objects. Each entry point in the ceremony inventory in
ARCHITECTURE.md but `rotateWebvhUpdateKey` mints one emitter per run
(`ceremonyEvents`), outside any compare-and-swap retry, and reports through the
module's `Logger`: a debug `'ceremony stage'` event as each stage's write lands
(with `prior: true` on a stage that found its own prior completion), and one
`'ceremony outcome'` event per run, at info (`clean`), debug (`noop`), warn
(`partial`, `refused`), or error (`failed`). A throw classifies as `refused`
when its `err.name` is one of that ceremony's typed refusals, and `failed`
otherwise. Each converted ceremony exports its stage ids as a typed union beside
its outcome type. A shared tail run inside another ceremony (the user key
cascade) emits nothing of its own, so one user action yields one outcome. A run
torn by tab death leaves stages and no outcome. Detail is scalars only, carries
no unlock-credential-derived value and, on transient paths, no account
identifier. No production code branches on an event; the outcome objects and
typed errors stay the contract. The vocabulary, the keys, and the level map are
`decisions/0022-ceremony-event-vocabulary.md`; the events beside structured
outcomes are `decisions/0023-structured-outcomes-also-emit-as-events.md`; where
they are emitted from is
`decisions/0024-ceremony-events-emit-from-entry-points.md`. The console fallback
in `log.ts` drops debug, so an unwired consumer sees info and above.
