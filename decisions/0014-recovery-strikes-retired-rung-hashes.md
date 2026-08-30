# 0014: A recovery's full retirement strikes each retired credential's rungs

- Status: accepted
- Date: 2026-08-29
- Driving work: WC-154, a review finding on WC-153. Both recovery
  continuations retire every pre-recovery standing credential in their
  add-and-retire entry, on the premise that striking a credential's ladder VM
  rots its bridge delegation. That premise holds only for a ladder-signed
  bridge.
- Affects: wallet-core `/clientAnnex`
  (`recoverWebvhLadderAnchored`, the ladder attribution helpers) and
  `/recovery` (`recoverWebvhClient`); every account log the two continuations
  write; the browser wallet's recovery copy and its FW-356 recovery bullet.

## Context

A standing credential's bridge delegation is a pre-minted PUT on `did.jsonl`
carried inside its unlock record. It is signed by whoever bound the credential.
On a ladder-anchored account that is a ladder VM, and striking the VM ends the
delegation's chain. On an account with enrolled clients a passkey added, or a
recovery code issued, from a remembered session has a bridge the ENROLLED
CLIENT signed, and that client survives the add-and-retire entry.

The entry struck the credential's ladder VM and its `keyAgreement` member and
left its committed rung hashes alone. So a retired credential's holder kept
both halves of a working reveal: a live PUT into the log, and a standing
commitment in `nextKeyHashes` whose preimage only they hold. They could reveal
that rung and sign document updates, republishing their own inventory on an
account someone had just recovered because they thought that credential was
compromised.

`removeUnlockKey` already strikes the attributed hashes. It can, because it
runs from a remembered session that holds the credential's registry entry, and
the recorded update key is the walk's anchor. A recovery continuation runs on a
cold browser with nothing but the typed code, so it had no per-credential
anchor to walk from. That gap is what this record closes.

## Decision

Both continuations strike, in the SAME add-and-retire entry, every
`nextKeyHashes` member the verified log attributes to each retired credential,
plus any already-revealed rung of a retired credential still standing in
`updateKeys`.

The anchor is read from the log alone. A credential is named by its
`keyAgreement` verification-method id, which the entry already resolves in
order to strike the member. The entry that FIRST introduced that member is the
credential's bind entry, and one of two shapes names rung 0:

- the entry authorized exactly one update key and that key signed it -- a
  prerotation reveal, the ladder-anchored genesis shape -- so rung 0 is that
  key;
- the entry authorized no key of its own and newly committed exactly one hash
  -- the `publishUnlockKey` bind an enrolled client signs, which the
  recovery-code issuance shares -- so rung 0's hash is that hash.

The existing walk (`attributeLadderInventory`, forward from the anchor plus
the backward recovery of spent rungs) runs from there and resolves the
credential's current standing hashes and revealed rungs. For an unspent
recovery code the walk degenerates to exactly its one committed hash.

Striking the committed hash is what neutralizes a live client-signed bridge.
did:webvh refuses any `updateKeys` member whose hash the previous entry did not
commit (`newKeysAreInNextKeys`), and `nextKeyHashes` is replaced wholesale with
no comparison against the prior list, so a selective strike resolves.

The bias is under-striking, and it is deliberate. Over-striking is silent and
unhealable: the struck credential keeps its verification method and its roster
wrap, unlocks and decrypts normally, and fails only when someone finally types
it. Under-striking leaves a rung standing, which is visible in the log and
fixed by a re-run. So four guards apply, and any of them firing leaves the
credential untouched:

- a bind entry introducing more than one credential-class `keyAgreement`
  member yields no anchor. That is what the TRANSIENT continuation's
  add-and-retire entry writes: the fresh credential's member and the
  replacement code's, together;
- a bind entry that introduces an ENROLLED CLIENT -- a new
  `capabilityInvocation` member, or a `keyAgreement` method the account DID
  does not control -- yields no anchor either, and no key the log attributes
  to a listed client is ever taken as an anchor. That is what the REMEMBERED
  continuation's add-and-retire entry writes. Its new client's key-agreement
  method is client-marked and so not credential-class, so the guard above
  counts only the replacement code and does not fire, while the one key the
  entry authorizes is the CLIENT's update key. Without this guard the
  replacement code anchors on that client, and the next recovery strikes the
  client's update key and both its commitments while its verification methods
  stay in the document: a client that can never extend the account log again,
  with nothing able to heal it;
- a walk that refuses or claims nothing yields no strike;
- a hash the entry itself commits (the fresh ladder's, the new client's, the
  replacement code's) is never a candidate;
- every surviving enrolled client's active update key, its carry-over hash and
  its staged hash are never candidates, whatever the walk claimed. This one is
  structural rather than a property of the walk: the surviving clients are
  enumerated from the log by the same attribution the client listing performs
  (`survivingClientKeyProtection`), and an ambiguous staged attribution
  protects every candidate. It closes the mis-anchoring blast radius
  independently of the anchor guards above, which is why both stand. The
  credential walks run FIRST and the hashes they claimed are vouched for as
  latent when that attribution runs, so a retiring credential's own rung
  committed beside a client's staged hash cannot make the attribution
  ambiguous and get itself protected;
- a listed enrolled client whose ACTIVE update key the log cannot attribute
  withholds the whole strike, with a warn naming the client. Nothing of that
  client can be protected, so nothing may be struck. The same shape already
  disables a row's disconnect in the clients surface.

The report is a not-fully-retired report rather than a nothing-happened one. A
credential appears on the outcome's `unclaimedCredentialVmIds` when no anchor
or walk claims it, when it claims nothing, and when ANY single hash or key it
claimed was withheld by a guard. The rest of that credential's claims are still
struck; what the caller must not be told is that a partial retirement was a
whole one. What was struck is reported on `struckRungHashes`. Both are
in-memory outcome members, not wire artifacts.

A resumed run, whose add entry already landed, re-runs the SAME computation
over the log as it stood just before that entry, located by the key the entry
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
  Rejected on two counts. It leaves a reveal window: between the
  add-and-retire entry and the sweep, every retired credential can still spend
  its rung, and the window is a network round trip on a browser the user may
  close. And the transient variant lands the account client-less, where no
  remembered login ever runs, so a sweep torn before it published would have
  no mender at all -- exactly the open-gap class
  `decisions/0010-remembered-login-is-not-a-mender-trigger.md` names.
- **Accept and document the residue.** Rejected. It contradicts the full
  retirement FW-356 settled on ("its ladder VM and its `keyAgreement` member
  struck, roster wrap retired"), and what it accepts is that a phished passkey
  can re-seize an account the user has just recovered from that phishing. A
  code is spent precisely because the other credentials are lost or suspect.
- **Revoke the client-signed bridge delegations too.** Rejected for this item,
  and recorded below as accepted residue rather than as a gap: the transient
  variant holds no authority to revoke a delegation an enrolled client minted,
  and once the rung's hash is struck the bridge can extend nothing.
- **Trust the anchor guards alone, without the surviving-client protection.**
  Rejected. The guards are read from the log's shape, and the first review of
  this change found a shape they missed. A structural protection that never
  depends on the walk being right is what keeps the worst outcome
  (an enrolled client struck out of the log) unreachable rather than merely
  unlikely.

## Consequences

- A credential retired by a recovery is retired in every sense the log can
  express: member, ladder VM, committed rungs, revealed rungs.
- A client-signed bridge delegation stays live and inert. It is a PUT the
  server would still authorize, carrying an entry no resolver will accept.
  Nothing revokes it; the strike is what ends its usefulness.
- A credential whose bind entry is ambiguous keeps its rungs and is named to
  the caller. The reachable case is a credential introduced by an earlier
  recovery's own add-and-retire entry: the transient variant's fresh
  credential and replacement code, or the remembered variant's replacement
  code. A second recovery under-strikes those and says so. For the transient
  variant's fresh credential the residue is more than a commitment: nothing
  retires its rung 0, so that key stands AUTHORIZED in `updateKeys` after the
  recovery, and a second recovery leaves it there. It is inert -- its ladder
  VM is struck and the bridge that ladder VM signed rots with it -- but a
  holder of that credential's ladder seed keeps a live update key. WC-159 owns
  the anchor rule that would close it.
- Both recovery outcomes carry two new members. The app half consumes them for
  its recovery copy; nothing gates on them.
- The bind-entry reading joins `decisions/0007-ladder-reveal-hash-order.md`'s
  positional rules as a log-format dependency. A ceremony that batches a
  credential's bind with another credential's introduction is already
  forbidden by 0007's batching rule, and now also costs that credential its
  anchor.
