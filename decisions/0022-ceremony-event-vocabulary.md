# 0022: The ceremony event vocabulary

- Status: accepted
- Date: 2026-09-29
- Driving work: the design for a ceremony-outcome event channel over the logging
  seam, approved 2026-09-29. Extracted at that design's approval, from its list
  of permanent public surface needing individual sign-off and from the open
  questions that shaped it.
- Affects: `@interop/wallet-core` (the new root-level `src/ceremonyEvents.ts`
  helpers, the console fallback in `src/log.ts`, the mender runner
  `src/menders/runner.ts`, the ceremony entry points that gain emits),
  freewallet (its app-implemented ceremonies, its mender report sites, and the
  e2e fixture that reads the events), dcw (its twin emit item, and its
  console-backed mender logger), did-cli-typescript (an unwired consumer of the
  console fallback).

## Context

Every ceremony reports to its caller through a typed outcome object or a typed
refusal. Nothing outside the caller can see which ceremonies ran, which stage
each reached, or which mender fired. The logging seam carries free-form per-site
warns, so a reader of the ring buffer or the dev NDJSON file would have to know
every site's prose to answer those questions.

The channel adds structured events over the existing `Logger` port. A log line's
shape is permanent public surface once readers query it: the dev tooling, the
e2e fixture, and any later diagnostics export all key on it. So the keys, the
messages, and the level of each outcome are fixed here, once, for every repo
that emits.

Two constraints shaped the choice. The `Logger` port is frozen at four two-arg
methods, so the vocabulary has to ride `msg` and `data`. And wallet-core already
owns the ceremony ids (`CEREMONY_IDS`), the mender invariant ids
(`INVARIANT_IDS`), and the outcome set (`MEND_OUTCOMES`), so the channel names
things by those rather than minting parallel sets.

## Decision

Ceremony events are ordinary `LogEvent`s with a static `msg` and reserved `data`
keys. The helpers in `src/ceremonyEvents.ts` (`ceremonyEvents` and
`menderEvent`) are the one way to emit them.

Three messages, one per event kind:

- `'ceremony stage'` at debug, data `{ ceremony, run, stage, ...detail }`. It
  says the stage is complete as of now. A stage that found its own earlier
  completion carries `detail.prior: true`.
- `'ceremony outcome'`, data `{ ceremony, run, outcome, ...detail }`, plus
  `errorName` and `err` on `refused`, on `failed`, and on a `noop` classified
  from a pending throw. At most one per run, and exactly one on a run that
  returns or throws. A run torn by tab death emits stages and no outcome.
- `'ceremony mender'`, data `{ invariant, outcome, ...detail }`, plus
  `errorName` on `refused` and `failed`. It also carries `err` where the
  emitting site holds the thrown value. A ceremony-tail entry adds the scalar
  `ceremony` naming the ceremony that just ran, and its `run` where the site
  holds it. A chain or routing entry carries no `ceremony`. The report entry's
  `ceremonies` array is not carried. One event per reported invariant entry.

The reserved keys are `ceremony`, `run`, `stage`, `outcome`, `invariant`, and
`errorName`, with `err` placed at `data.err` from a named parameter. Two detail
keys are reserved as well. `prior` is the boolean above. `reason` is a site
reason code from a closed per-site set (for example `'generation-unavailable'`
or `'unverified'`). A thrown error's name travels as `errorName` and does not go
into `reason`.

A run is one call of a ceremony's public entry point, outside any CAS-retry
wrapper. Each run gets a short random `run` id. A caught and retried log
conflict emits nothing.

The outcome set is `MEND_OUTCOMES`, and the level map is:

- `clean` at info
- `noop` at debug
- `partial` at warn
- `refused` at warn
- `failed` at error

An epoch skip the roster's own delivery covered on the same run is `clean`,
since it leaves nothing for a caller to act on (2026-09-29, Dmitri).

A `noop` mender entry emits at debug too. A default console stays quiet on a
healthy login, and a filtered session can tell a check that held from one that
never ran.

The ids the channel carries are `CEREMONY_IDS` (including `account-deletion`,
`wallet-wipe`, `content-migration`, and `backup-export`) and `INVARIANT_IDS`.
Both are signed off where they are defined. Stage ids are not signed-off
surface. Each converted ceremony exports its stage ids as a typed const union,
and another repo may depend on a stage id only through that export. A rename is
then a compile error in the dependent test.

`detail` is scalars only (`string | number | boolean | undefined`), with the
reserved keys excluded by type and dropped at runtime. Fan-out loops emit one
aggregate event with counts. Every helper method catches internally and does not
throw.

wallet-core's console fallback drops debug events. A consumer that never calls
`setLogger` receives info, warn, and error only. This amends the fallback
recipe, which forwarded every level to the matching console method.

A refusal is classified by `err.name` against a per-ceremony list, not by
`instanceof`. The rule is: `refused` when the ceremony declined on a failed
precondition or a user cancel, and what already landed is safe for a re-run to
build on; `failed` when something broke after it started committing. A throw a
caller polls through, meaning "not ready yet, retry", is listed separately as
pending and classifies as `noop`, so an ordinary wait logs at debug. Enrollment
completion's `EnrollmentPendingError` is the one such throw today. For the two
app-implemented ceremonies scoped by this work:

- Content migration: `refused` on `ContentMigrationInProgressError`,
  `BundleInvalidError`, `AccountSpaceArchiveMissingError`,
  `BundleRecipientMissingError`, and `AbortError`. `partial` on a returned
  report that stopped early or left rows unmigrated. `failed` otherwise,
  including a `QuotaExceededError` from the Import activity write.
- Backup export: `refused` on the pre-flight errors
  `BackupCapabilityMissingError`, `BackupCapabilityUnsupportedError`,
  `BackupAnnexCommitError`, and `BackupRemoteStorageMissingError`. A user cancel
  (`AbortError`) is `refused` too, even after the stream has started, as in
  content migration. Every other failure after the establishment or once the
  stream has started is `failed` (`BackupCredentialNotListedError`,
  `BackupContinuityError`, `BackupRegistryChangedError`,
  `BackupSpaceExportError`, `AccountSpaceArchiveMissingError`).
- Account deletion follows the same rule. A `deleted` result is `clean`, and
  `deleted-unverified` is `partial`. A `refused` or `wrong-passphrase` result is
  `refused`. A thrown `PasskeyCancelledError` or `PasskeyPrfUnsupportedError` is
  `refused`. Anything else is `failed`.

A precondition refusal that throws a plain `Error` is classified `failed`, by
decision. This covers the unattributed update-key check, the self-revocation and
pending-rotation refusals, and establishment's roster-not-landed case. None of
them gains a named class for this channel.

## Rejected Alternatives

- **A logging-side ceremony or outcome enum.** A second set parallel to
  `CeremonyId` and `MendOutcomeKind` would drift from the one the ceremonies and
  the mender registry use. One vocabulary each.
- **Per-ceremony namespaces (`wc:ceremony:<id>`) in place of data keys.**
  wallet-core logs under one `wc` namespace, and a namespace is a debug-gate
  axis rather than a query axis. NDJSON readers query by data key either way.
  This one is reopenable (see Revisit Criteria).
- **Whole outcome objects, or one event per fan-out item, in `data`.** Outcome
  types carry nested reports that could grow record contents, and per-item
  events are the hot-path shape the logging seam warns against. The flat scalar
  shape is also the mechanized half of redaction.
- **A `mender` data key.** The value is an invariant id, and the runner's warn
  and the ceremony-tail line already key on `invariant`. The message keeps the
  word `mender`.
- **Carrying the report entry's `ceremonies` array on mender events.** On a
  chain or routing entry it is the declaration's static list. On a tail entry it
  names the ceremony that ran. One key would carry two meanings, so tail events
  carry the scalar `ceremony` and the others carry none.
- **The thrown error's name in `detail.reason`.** `errorName` is already
  reserved for it, and the landed report sites use `reason` for their own codes.
- **`partial` at error, for the immediate NDJSON flush.** It is a resumable
  success. The immediate flush is reserved for `failed`, and the loss window for
  `partial` and `refused` is documented.
- **A chain-summary event per login.** It adds a fixed line to every login, and
  the e2e seam already answers whether the chain has finished.
- **`noop` mender entries left silent.** Then a filtered session cannot tell a
  check that held from one that never ran, and the e2e fixture cannot assert a
  healthy check.

## Consequences

- Readers can rely on the three messages, the reserved keys, and the level map.
  A change to any of them is a breaking change to every reader.
- The channel makes no wire commitment. Nothing durable holds an event in
  production, and nothing reads one back.
- A torn run is visible as stages with no outcome. Readers must not treat
  outcome presence as a list of runs.
- A mender that acts by re-running a ceremony emits its mender event, and the
  re-run emits its own ceremony events under its own `run`. A reader
  reconstructing user-initiated runs excludes runs adjacent to a mender event.
- `partial` and `refused` ride the NDJSON sink's flush timer, so a tab that dies
  inside the window loses them.
- freewallet's ceremony-tail reporter replaces its existing info line with the
  helper event and keeps its warn for `failed` and `refused`. That is the one
  retrofit of an existing site.
- An unwired consumer gains info-and-above lines on acting runs. dcw's own
  console-backed mender logger bypasses the debug cutoff, so runner events print
  there at every level, `noop` included. dcw's twin item decides whether that
  logger drops debug.
- freewallet's backup export gains a named `BackupRemoteStorageMissingError` in
  place of a plain `Error`, so the classification can match it.
- The plain-`Error` precondition refusals show up as `failed` at error level.
  That overstates them, and it is accepted. Naming each one would add error
  classes whose only reader is this channel.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A reader needs a per-ceremony debug gate that the single `wc` namespace
   cannot give. Per-ceremony namespaces would then be an additive change beside
   the data keys, not a replacement.
2. A mechanized redact hook lands on the logger seam. The flat scalar shape may
   then be reconsidered, though it would likely stay.
3. A consumer surface (a diagnostics export) needs an event kind the three
   messages do not cover. Add a kind; do not overload an existing message.
4. A plain-`Error` precondition refusal gets a named class for a reason of its
   own (a caller needs to match it). Then it classifies as `refused` from that
   point.
