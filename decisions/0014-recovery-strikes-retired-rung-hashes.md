# 0014: A recovery's full retirement strikes each retired credential's rungs

- Status: accepted
- Date: 2026-08-29
- Driving work: WC-154, a review finding on WC-153. Both recovery continuations
  retire every pre-recovery standing credential in their add-and-retire entry,
  on the premise that striking a credential's ladder VM rots its bridge
  delegation. That premise holds only for a ladder-signed bridge.
- Affects: wallet-core `/clientAnnex` (`recoverWebvhLadderAnchored`, the ladder
  attribution helpers) and `/recovery` (`recoverWebvhClient`); every account log
  the two continuations write; the browser wallet's recovery copy and its FW-356
  recovery bullet.

## Context

A standing credential's bridge delegation is a pre-minted PUT on `did.jsonl`
carried inside its unlock record. It is signed by whoever bound the credential.
On a ladder-anchored account that is a ladder VM, and striking the VM ends the
delegation's chain. On an account with enrolled clients a passkey added, or a
recovery code issued, from a remembered session has a bridge the ENROLLED CLIENT
signed, and that client survives the add-and-retire entry.

The entry struck the credential's ladder VM and its `keyAgreement` member and
left its committed rung hashes alone. So a retired credential's holder kept both
halves of a working reveal: a live PUT into the log, and a standing commitment
in `nextKeyHashes` whose preimage only they hold. They could reveal that rung
and sign document updates, republishing their own inventory on an account
someone had just recovered because they thought that credential was compromised.

`removeUnlockKey` already strikes the attributed hashes. It can, because it runs
from a remembered session that holds the credential's registry entry, and the
recorded update key is the walk's anchor. A recovery continuation runs on a cold
browser with nothing but the typed code, so it had no per-credential anchor to
walk from. That gap is what this record closes.

## Decision

Both continuations strike, in the SAME add-and-retire entry, every
`nextKeyHashes` member the verified log attributes to each retired credential,
plus any already-revealed rung of a retired credential still standing in
`updateKeys`.

The anchor is read from the log alone. A credential is named by its
`keyAgreement` verification-method id, which the entry already resolves in order
to strike the member. The entry that FIRST introduced that member is the
credential's bind entry, and one of two shapes names rung 0:

- the entry authorized exactly one update key and that key signed it -- a
  prerotation reveal, the ladder-anchored genesis shape -- so rung 0 is that
  key;
- the entry authorized no key of its own and newly committed exactly one hash --
  the `publishUnlockKey` bind an enrolled client signs, which the recovery-code
  issuance shares -- so rung 0's hash is that hash.

The existing walk (`attributeLadderInventory`, forward from the anchor plus the
backward recovery of spent rungs) runs from there and resolves the credential's
current standing hashes and revealed rungs. For an unspent recovery code the
walk degenerates to exactly its one committed hash.

Amended 2026-09-04 (WC-159): a third bind shape is read, the recovery
add-and-retire entry itself, so the credentials one recovery introduces are
anchorable by the next. It is the HANDOVER of `decisions/0007` read as an
anchor. An entry is that shape when every one of these holds, each failing
closed:

- it authorized exactly one update key, and that key signed it (the successor
  key: the fresh ladder's rung 0 on the transient continuation, the new client's
  update key on the remembered one);
- it struck at least one credential-class `keyAgreement` member (the spent
  code's). A self-enrollment's add entry passes every other clause here, since
  its reveal entry also commits three hashes with the successor's first; this is
  what keeps the arm off it, and off any entry that authorizes a successor
  without spending a credential;
- that key's hash was first committed by an EARLIER entry (the reveal entry),
  FIRST among exactly three additions, or among exactly two on a resumed reveal
  (below);
- this entry retires a key that signed the reveal entry (the spent code's rung),
  and that key signed no entry between the two.

The reveal entry's LAST addition is then the replacement code's rung-0 hash, by
0007's rule that what an entry hands to a successor credential comes last. On a
RESUMED reveal -- a transient continuation torn at its seam and re-run with a
freshly minted ladder seed and the same replacement code, both as its contract
asks -- the second reveal entry adds only the fresh rung pair, the replacement's
hash being committed already. That entry's last addition is the ladder's own
rung 1, and the replacement's hash is the last addition of the ONE
three-addition entry the same retired signer wrote earlier. Every earlier entry
of that signer is read: a two-addition one is another resumed reveal (a
continuation torn at its seam twice leaves one) and is walked past, a
three-addition one committed a replacement, and any other size refuses. More
than one three-addition attempt means the replacement changed between resumes,
and the lookup refuses rather than choose. The forward walk reads the same
two-addition shape the same way, asking only whether some earlier attempt
committed a replacement, so the resumed ladder's rung 1 is claimed there rather
than released as a handover. Which of the entry's members belongs to which
anchor is read off the `keyAgreement` relation's order, which the emitter fixes
and this record ratifies as a positional rule of the log format beside 0007's:
the fresh credential's member is appended before the replacement code's. So:

- a bind that introduces exactly two credential-class members and no enrolled
  client (the transient continuation) anchors its FIRST member on the successor
  key, and only when the log attributes that key to no enrolled client, and its
  SECOND member on the last addition. The two are decoupled: the successor key
  is unambiguous from the bind entry alone, so a replacement lookup that refuses
  leaves the fresh credential anchored and its rung 0 retirable;
- a bind that introduces exactly one credential-class member beside an enrolled
  client (the remembered continuation) anchors that member on the last addition
  alone; the successor key there is the client's;
- a bind of the handover shape whose members match neither case names no anchor,
  and the two older arms are not consulted for it. No emitter writes that shape
  any more: a transient entry that introduced only one member because the fresh
  credential's id already stood (the same passphrase re-bound) is refused by the
  continuation before its reveal entry. A log that carries one from an older
  emitter is refused here, since that one member is the replacement and the
  self-signed-key arm would otherwise anchor it on the fresh credential's
  rung 0.

A continuation resumed with a different replacement code than its reveal entry
committed, which the continuation's contract forbids, reads by variant. The
REMEMBERED one keeps its successor key across the resume, so its second reveal
entry adds only the new replacement's hash under the spent rung; the entry that
committed the successor's hash no longer ends on the replacement the document
carries, the between-entries test refuses, and the next recovery reports that
replacement unclaimed rather than striking a first replacement's orphan on its
behalf. The TRANSIENT one mints a fresh ladder seed per attempt, so its second
reveal entry carries three additions ending on the new replacement's hash, and
the rule anchors the replacement the document carries on it; the first
replacement's hash stands as an inert orphan. Torn again and resumed with that
second replacement, it leaves two three-addition attempts behind a resumed
reveal, and the lookup refuses. The surviving-client protection below stands
unchanged beneath the rule, so a wrong reading of the remembered shape could at
worst withhold a strike; it cannot end a client.

Amended 2026-09-08: the anchor is no longer inferred from an entry's shape.
Every credential-class `keyAgreement` member now carries its own anchor as a
plain member, `ladderCommitment`: `hash(rung 0)` of the credential's ladder, in
the multihash form `nextKeyHashes` already carries. Every bind site writes it
through one builder, `unlockKeyVerificationMethod`, so no emitter can omit it.
`credentialLadderAnchor` reads the member directly. It takes the value from the
entry that introduced the member (each time it appears after not standing), so a
member re-bound after a retirement, under a fresh ladder, anchors on the fresh
commitment rather than a stale one. It checks rather than adopts what later
entries say while the member stands: the property is a document member any
update-key holder can restate, so a value that changes during one continuous
standing run is a retargeting no bind performs, and the member names no anchor
for the rest of that run. The property is a plain JSON member with no JSON-LD
term, a deliberate departure from `decisions/0001`'s context term for
`publicKeyCommitment`: nothing processes the account document as JSON-LD on the
wallet or the server side, and every signature over the document and its log
entries is JCS-canonicalized. The three bind-shape readings above (the
prerotation-reveal arm, the committed-hash arm, and the 2026-09-04 handover arm)
are retired along with the guards built to keep them off an enrolled-client bind
or a self-enrollment's add entry: an entry's shape says nothing about anchoring
any more. The `keyAgreement` relation-order rule below (the fresh credential's
member before the replacement's) is retired with them; emitters still append the
replacement's member second, but nothing reads that order to decide which member
is which. A credential-class member with no `ladderCommitment` -- every log
written before this change, and any other member the property is missing from --
names no anchor and is reported unclaimed, exactly as an ambiguous shape was
before. There is no fallback to the retired readings for such a log.

Amended 2026-09-08, the write side. `publishUnlockKey` is the one path in the
library that rewrites a standing member, and it did so under whatever rung-0
hash its caller supplied, so a torn establishment re-run holding a fresh ladder
seed retargeted the member itself and left the first ladder's VM and commitment
as orphans. It now refuses a bind whose rung-0 hash differs from the standing
member's `ladderCommitment` (`LadderAttributionError`, nothing written); a
member naming the same hash is extended as before, which is what a split bind's
authority entry does. The retargeting refusal above is therefore the read-side
half of one rule: a member's commitment is stable for its whole standing run,
and a value that changes is a foreign writer's. That stability is what lets the
removal and pre-flight paths walk from the member's anchor beside the registry's
recorded key and cross-check the two (`attributeUnlockLadderInventory`): the
registry-anchored inventory must be contained in the member-anchored one, the
member's reading is what the strike acts on, and anchors resolving to different
ladders refuse.

The replacement's anchor is a last-position hash, so the backward walk's climb
rule reaches it. What stops that climb from recovering the spent code's rung and
going on into the fresh credential's ladder is the credential- membership test
in `recoverEarlierRungs`: the replacement's member is published one entry after
the reveal that committed its hash. That guard is load-bearing for this rule and
is named so in the walk's header.

The rule does not pair the two ladder VMs the transient entry publishes. Neither
is claimed seedlessly, as before; the fresh credential's own seed names its VM,
and a seedless retirement of it refuses on the retirement gate
(`decisions/0015`).

Striking the committed hash is what neutralizes a live client-signed bridge.
did:webvh refuses any `updateKeys` member whose hash the previous entry did not
commit (`newKeysAreInNextKeys`), and `nextKeyHashes` is replaced wholesale with
no comparison against the prior list, so a selective strike resolves.

The bias is under-striking, and it is deliberate. Over-striking is silent and
unhealable: the struck credential keeps its verification method and its roster
wrap, unlocks and decrypts normally, and fails only when someone finally types
it. Under-striking leaves a rung standing, which is visible in the log and fixed
by a re-run. So four guards apply, and any of them firing leaves the credential
untouched:

- a bind entry introducing more than one credential-class `keyAgreement` member
  yields no anchor, unless it is the add-and-retire shape the amendment above
  reads. That is what the TRANSIENT continuation's add-and-retire entry writes:
  the fresh credential's member and the replacement code's, together;
- a bind entry that introduces an ENROLLED CLIENT -- a new
  `capabilityInvocation` member, or a `keyAgreement` method the account DID does
  not control -- yields no anchor either, outside that same shape, and no key
  the log attributes to a listed client is ever taken as an anchor. That is what
  the REMEMBERED continuation's add-and-retire entry writes. Its new client's
  key-agreement method is client-marked and so not credential-class, so the
  guard above counts only the replacement code and does not fire, while the one
  key the entry authorizes is the CLIENT's update key. Without this guard the
  replacement code anchors on that client, and the next recovery strikes the
  client's update key and both its commitments while its verification methods
  stay in the document: a client that can never extend the account log again,
  with nothing able to heal it. The amendment's reading of that entry takes only
  the reveal entry's last addition from it, so the guard's reason holds there
  too;
- a walk that refuses or claims nothing yields no strike;
- a hash the entry itself commits (the fresh ladder's, the new client's, the
  replacement code's) is never a candidate;
- every surviving enrolled client's active update key, its carry-over hash and
  its staged hash are never candidates, whatever the walk claimed. This one is
  structural rather than a property of the walk: the surviving clients are
  enumerated from the log by the same attribution the client listing performs
  (`survivingClientKeyProtection`), and an ambiguous staged attribution protects
  every candidate. It closes the mis-anchoring blast radius independently of the
  anchor guards above, which is why both stand. The credential walks run FIRST
  and the hashes they claimed are passed to that attribution as walk-derived, so
  a retiring credential's own rung committed beside a client's staged hash
  cannot make the attribution ambiguous and get itself protected. A walk-derived
  claim never prunes the decision-0007 positional successor of the client's
  update-key hash, its staged hash: a walk anchored on a member that names that
  hash would otherwise strike it and report the credential cleanly retired
  (WC-219, amended 2026-09-08);
- a listed enrolled client whose ACTIVE update key the log cannot attribute
  withholds the whole strike, with a warn naming the client. Nothing of that
  client can be protected, so nothing may be struck. The same shape already
  disables a row's disconnect in the clients surface.

The report is a not-fully-retired report rather than a nothing-happened one. A
credential appears on the outcome's `unclaimedCredentialVmIds` when no anchor or
walk claims it, when it claims nothing, and when ANY single hash or key it
claimed was withheld by a guard. The rest of that credential's claims are still
struck; what the caller must not be told is that a partial retirement was a
whole one. What was struck is reported on `struckRungHashes`. Both are in-memory
outcome members, not wire artifacts.

A resumed run, whose add entry already landed, re-runs the SAME computation over
the log as it stood just before that entry, located by the key the entry
authorized (`retiredCredentialRungsBeforeKey`). Both paths therefore share one
definition of what was struck and what was left, rather than a resume answering
a narrower question and reading clean where the first run warned.

The entry refuses to publish an empty `nextKeyHashes`
(`NextKeyHashesEmptyError`), since an empty list switches prerotation off in
did:webvh. It is non-empty by construction, because the entry commits its own
successors; the assertion is what says so.

## Rejected Alternatives

- **A post-entry sweep entry, driven by the unlock-methods registry.** The
  registry names each credential's recorded update key, which is the anchor
  `removeUnlockKey` already uses, so no new attribution would be needed.
  Rejected on two counts. It leaves a reveal window: between the add-and-retire
  entry and the sweep, every retired credential can still spend its rung, and
  the window is a network round trip on a browser the user may close. And the
  transient variant lands the account client-less, where no remembered login
  ever runs, so a sweep torn before it published would have no mender at all --
  exactly the open-gap class
  `decisions/0010-remembered-login-is-not-a-mender-trigger.md` names.
- **Accept and document the residue.** Rejected. It contradicts the full
  retirement FW-356 settled on ("its ladder VM and its `keyAgreement` member
  struck, roster wrap retired"), and what it accepts is that a phished passkey
  can re-seize an account the user has just recovered from that phishing. A code
  is spent precisely because the other credentials are lost or suspect.
- **Revoke the client-signed bridge delegations too.** Rejected for this item,
  and recorded below as accepted residue rather than as a gap: the transient
  variant holds no authority to revoke a delegation an enrolled client minted,
  and once the rung's hash is struck the bridge can extend nothing.
- **Trust the anchor guards alone, without the surviving-client protection.**
  Rejected. The guards are read from the log's shape, and the first review of
  this change found a shape they missed. A structural protection that never
  depends on the walk being right is what keeps the worst outcome (an enrolled
  client struck out of the log) unreachable rather than merely unlikely.

## Consequences

- A credential retired by a recovery is retired in every sense the log can
  express: member, ladder VM, committed rungs, revealed rungs.
- A client-signed bridge delegation stays live and inert. It is a PUT the server
  would still authorize, carrying an entry no resolver will accept. Nothing
  revokes it; the strike is what ends its usefulness.
- A credential whose bind entry is ambiguous keeps its rungs and is named to the
  caller. Until the 2026-09-04 amendment the reachable case was a credential
  introduced by an earlier recovery's own add-and-retire entry: the transient
  variant's fresh credential and replacement code, or the remembered variant's
  replacement code. A second recovery under-struck those, and for the transient
  variant's fresh credential left its rung 0 standing AUTHORIZED in
  `updateKeys`. The amendment anchors all three, so a second recovery retires
  them whole. What remains reachable is a resumed continuation that changed its
  replacement code, a contract violation: the remembered variant's is refused,
  the transient variant's anchors the replacement the document carries, and a
  transient one torn a second time after the change leaves the replacement
  unclaimed while the fresh credential stays anchored. A re-bind of a standing
  credential's own member by a recovery is no longer a residue: the continuation
  refuses it before its reveal entry (`RecoveryCredentialStandingError`), since
  the entry that should retire that credential would otherwise be the one that
  re-bound it, leaving its earlier rungs standing under a struck ladder VM.
- Added 2026-09-04: the `keyAgreement` relation's order in a recovery
  add-and-retire entry -- the fresh credential's member, then the replacement
  code's -- is load-bearing wire behavior, exactly as the reveal entry's hash
  order is under 0007. Reordering the two is a breaking change to the log
  format, not a refactor. Both continuations write the pair through one body
  (`recovery/continuation.ts`), which appends the replacement's member after the
  variant's own. Amended 2026-09-08: superseded. The anchor no longer reads this
  order -- each member now names its own anchor directly (`ladderCommitment`),
  read by id rather than by position. Both continuations still append the
  replacement's member second, but the order is no longer a log-format
  dependency; a future emitter could append it first without breaking any
  reader.
- Both recovery outcomes carry two new members. The app half consumes them for
  its recovery copy; nothing gates on them.
- The bind-entry reading joins `decisions/0007-ladder-reveal-hash-order.md`'s
  positional rules as a log-format dependency. A ceremony that batches a
  credential's bind with another credential's introduction is already forbidden
  by 0007's batching rule, and now also costs that credential its anchor.
  Amended 2026-09-08: superseded. The anchor is read off each member's own
  `ladderCommitment` now, not inferred from a bind entry's shape, so this
  dependency no longer holds: a batched bind costs a credential no anchor, only
  whatever 0007's own rules already cost it. 0007's append-order rules stay
  load-bearing on their own terms, for the forward and backward walks.
