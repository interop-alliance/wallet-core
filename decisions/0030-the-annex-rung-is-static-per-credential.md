# 0030: The annex rung is static per credential

- Status: accepted
- Date: 2026-10-12
- Driving work: freewallet roadmap item FW-220 (a generation swap locked every
  other standing credential out of the client annex), implemented as wallet-core
  roadmap item WC-294
- Affects: wallet-core `/clientAnnex` (the annex rung derivation, the generation
  mint, the GC swap, the off-cadence retirement swap, the transient readiness
  ensure); freewallet and dcw (every annex generation they mint or swap, and the
  retirement swap's caller); the client annex profile's spec text
- Supersedes: the per-generation companion rung label of `decisions/0003`, and
  the "per-generation HKDF sequence" wording of `decisions/0002`

## Context

A standing credential writes the client annex log with its annex rung, an update
key derived from its ladder seed. Until now the derivation took the generation
id as well (HKDF info `<generationId>/rung/0` under the ladder salt). Two
reasons stood behind that. A revealed annex key must not match the account log's
rung-0 commitment, since the annex log is readable by its storage host. And a
fresh generation needed no state from the deleted log.

The per-generation key made every generation swap a lockout. A swap mints a
fresh generation whose genesis commits the rungs the caller can derive. A wallet
session holds only its own login credential's ladder seed, because another
credential's unlock record opens under that credential's secret alone. So the
quarterly GC swap, the off-cadence retirement swap, and the transient heal's
fresh-generation arm each left every other standing credential unable to write
the fresh generation. That credential's next transient login refused with
`ClientAnnexRungUncommittedError`. The other credentials' hashes for the fresh
generation id are underivable without their seeds, so no swap could restate
them.

The first reason does not need the generation id. A distinct info label already
separates the annex key from the account rungs under the one salt.

## Decision

- A credential's annex rung is static. It is the same key on every generation.
  The derivation takes the ladder seed alone, with HKDF info `annex/rung/0`
  under the existing `LADDER_SALT`, through `ladderDerive`. The three label
  families stay disjoint: `rung/<n>` (one slash, the account rungs), `vm` (no
  slash), and `annex/rung/0` (two slashes, the `annex` prefix). The
  per-generation label family is removed, with no fallback derivation.
- A swap restates the standing set by attribution from the superseded
  generation's log. With one key per credential, that log's current parameters
  ARE the standing credentials' annex commitments. The restated set is every
  `nextKeyHashes` entry plus the hash of every revealed `updateKeys` entry,
  deduplicated (`standingRungHashesOf`). The fresh genesis keeps did:webvh's
  carry-over rule. Its `updateKeys` is the minting key alone, and its
  `nextKeyHashes` holds the minting key's carry-over hash beside the restated
  set. The pre-rotation rule lets a later entry reveal only a key whose hash the
  previous entry committed, which is why the restating happens in
  `nextKeyHashes`.
- A retirement swap excludes the retired rung. `swapClientAnnexGeneration` takes
  a required `retiredLadderSeeds`, derives each retired credential's annex rung,
  and leaves its hash out of the restated set. A swap may not name its own
  minting credential as retired. The restating swap serves a named retirement
  and the quarterly hygiene swap, which passes `[]`.
- A retirement that cannot name the retired credential passes `'unnamed'` and
  takes the non-restating swap. Its genesis commits the minting credential's
  rung alone, so the retired rung dies with the old generation. A restating swap
  there would carry the retired rung forward while reporting it retired, and
  skipping the swap would leave the same residue.
- The transient heal's fresh mint restates too, when it supersedes a readable
  pointed log. It checks the acting rung's admission against that log up front,
  so a credential bound mid-generation mints whether or not its delegation needs
  renewing. A dead generation and a gone Space leave no log, so nothing is
  restated there.
- Nothing is restated at a first generation. The credential-anchored genesis and
  the establishment mint the account's first generation. The transient-recovery
  continuation also restates nothing. A recovery spend retires every
  pre-recovery credential on purpose, and the recovery holds none of their seeds
  to exclude them by.

## Rejected Alternatives

- Forward commitment: keep per-generation keys, and have each write also commit
  the credential's hash for the successor generation. It needs successor
  generation ids that are deterministic and known in advance. It needs a rule
  for a successor id a torn swap consumed. And it costs a second hash per
  credential in every log. The static rung gets the same carry-over with none of
  that. Do not reopen without a property the static rung cannot give.
- Carrying the other credentials' seeds to the swapper. It breaks key custody.
  Each credential's unlock record opens under that credential's secret alone,
  and a session holding every credential's seed would hold every credential.
- Committing the locked-out credentials at their next remembered login (rejected
  2026-08-24). On a credential-anchored account no remembered login may ever
  run, so a lockout that waits on one is a lockout forever. Freewallet's
  `decisions/0010-remembered-login-is-not-a-mender-trigger.md` bars counting a
  remembered login as a mender.

## Consequences

- Breaking for existing data. Every existing generation commits its rungs under
  the old label, so no credential's static rung is admitted there. Each
  credential's next transient visit fails the up-front admission check and mints
  a fresh generation. The first such mint restates the old generation's set,
  which carries only old-label hashes, so the next credential mints again. The
  account converges once each credential has visited. The old-label hashes ride
  along in every later restated set, unused.
- A swap never locks out a credential the old generation committed. A credential
  bound mid-generation with no commit entry is still out of a generation until a
  committed writer commits its hash or it mints a restating generation itself.
- The quarterly swap no longer ends a retired credential's annex rung on its
  own. A strike entry (`retireClientAnnexRung`), a named retirement swap, or an
  unnamed one removes it. A rung none of them removed rides every later swap,
  and nothing mends that: a swap cannot tell a retired credential's hash from a
  standing one, since the account document records no annex commitment to
  attribute it by. It is filed as an open gap (wallet-core WC-295). Its
  credential's unlock record and ladder VM are gone, so the rung can sign an
  annex entry but has no delegation left to reach the annex Space with.
- The same residue covers a retired credential's rung committed under the old
  per-generation label. No fallback derivation exists, so neither a strike nor a
  named exclusion can name that rung, and every later swap restates it. Its
  delegation is gone the same way.
- An unnamed retirement swap, and the GC repair, drop every other standing
  credential from the fresh generation too. Each one re-admits itself at its
  next visit by minting a generation that restates the swapped one's set beside
  its own hash: a transient visit through the readiness ensure's admission
  check, a remembered login through the GC pass's readmission swap. That costs
  one extra mint per credential, not a lockout, and holds a credential that only
  ever logs in remembered to no quarter.
- The annex key is the same across generations, so the storage host can link a
  credential's writes across generations. The annex log was never unlinkable to
  its host (decision 0002), so this adds no new exposure.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The annex log becomes readable by a party other than its host and the
   account, so cross-generation linkability of a credential's annex key starts
   to matter.
2. A credential needs to rotate its annex key without being retired, which a
   single static key per credential cannot express.
