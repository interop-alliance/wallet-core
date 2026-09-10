<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# Recovery codes (`recovery`)

A code is a standing credential that retires on spend, and its inventory is
deliberately split. Decryption and delegation stand: its `keyAgreement`
verification method is in the document, unmarked, its ladder VM stands under
`assertionMethod` and `capabilityDelegation`, and its user-key wrap stands in
the roster, all maintained for free by rotation fan-out. Update authority stays
latent: rung 0 joins `updateKeys` nowhere, only its hash is committed, and the
one bridge is a pre-minted PUT-on-`did.jsonl` delegation carried in the code's
unlock record and signed by the code's OWN ladder VM. Any use of a code must
first extend the world-readable log, so recovery is loud by construction. On the
ladder branch the issuance splits its entry so the code's decryption material
precedes its authority: a key entry carrying the `keyAgreement` member, then the
escrow append, then an authority entry carrying the ladder VM and the rung-0
hash (`part`, `decisions/0018`). A tear before the authority entry leaves a dead
code, one that can neither spend nor sign, rather than one that can spend and
cannot decrypt, which the spend's own unwrap through the code's wrap would turn
into account destruction. The enrolled branch escrows first and writes the
merged entry. Spending a code is a two-entry self-enrolling continuation:
**reveal-and-commit** (the pre-committed key reveals itself, commits the new
client's and replacement code's hashes), then **add-and-retire** (new client
fully in; the spent code's method, key, and hash out; the replacement code's
inventory in), followed by mandatory user-key rotation off the spent code. The
replacement's inventory is its whole inventory: its verbatim `keyAgreement`
member AND its ladder VM, under `assertionMethod` and `capabilityDelegation`,
beside the rung-0 hash the reveal entry committed. A replacement published
without the VM could never spend, since the bridge delegation its record carries
is signed by that VM (`decisions/0019`, `decisions/0020`). The transient
continuation therefore publishes TWO ladder VMs in one entry, the fresh
credential's and the replacement's, and nothing in the log pairs either with
either credential. The seedless walk claims neither, so the fresh credential's
VM is named by its own ladder seed, and a seedless retirement of it refuses on
the retirement gate. Both variants retire every PRE-RECOVERY standing credential
outright in that same entry: its ladder VM and its `keyAgreement` member leave
the document, and so does its whole update-key inventory -- the rung hashes it
has standing in `nextKeyHashes`, plus any rung of its own left revealed in
`updateKeys` (`attributeRetiredCredentialRungs`, `decisions/0014`). Striking the
VM alone would rot only a LADDER-signed bridge, and a bridge an enrolled client
minted outlives the strike, so a committed rung left standing would let a
retired credential reveal it and republish its own inventory. Each credential is
anchored from the log alone, since a cold browser can read no registry before
the entry is written: its `keyAgreement` member names its own rung-0 commitment
(`ladderCommitment`, the value `hash(rung 0)` takes in `nextKeyHashes`), and the
walk runs from that hash (`credentialLadderAnchor`). Every bind site writes the
property through one builder (`unlockKeyVerificationMethod`). The anchor is
therefore a property of the member rather than an inference from the shape of
the entry that introduced it (`decisions/0014`, amended 2026-09-08). The
`keyAgreement` relation's order carries no meaning, and a transient continuation
torn at its seam and resumed with a fresh ladder seed anchors both members off
the add-and-retire entry alone. The value is taken from the entry that
introduced the member, since any update-key holder can restate a standing
member. A member retargeted while it stands names no anchor for the rest of that
standing run. The write side holds the same line: `publishUnlockKey`, the one
path here that rewrites a standing member, refuses a bind under another rung-0
hash. A member re-introduced after a strike anchors on its fresh ladder. The
named hash must also be one the log committed for the member: newly added to
`nextKeyHashes` by the introducing entry, by a later entry of the same standing
run (the split issuance's authority entry), or by an earlier entry whose signer
the introducing entry retires (a continuation's reveal entry, signed by the
spent code's rung the add-and-retire entry strikes). A member restating a hash
that already stood, committed for something else, such as an enrolled client's
staged hash, names no anchor. A credential-class member without the property,
one retargeted while standing, or one naming a hash the log never committed for
it, names no anchor and is reported unclaimed. Beside that a structural guard
stands: every surviving enrolled client's active update key, its carry-over hash
and its staged hash are protected whatever the walk claimed
(`survivingClientKeyProtection`), so a mis-anchored walk cannot end a client's
ability to extend the account log. The credential walks run first and their
claims are passed there as walk-derived, so a retiring rung committed beside a
client's staged hash cannot make the attribution ambiguous and get itself
protected. The one hash no such claim may prune is the `decisions/0007`
positional successor of a surviving client's update-key hash, its staged hash,
which stays protected even when a walk claims it (the committed-for-it check is
necessary rather than sufficient, since an approver can name a client's staged
hash before the enrollment it approves commits it). A listed client whose active
update key the log cannot attribute withholds the whole strike, since nothing of
that client could be protected. A credential is reported on the outcome's
`unclaimedCredentialVmIds` when no anchor or walk claims it, when it claims
nothing, and when any single claim of its was withheld, so a partial retirement
is reported rather than read as a whole one. Over-striking is silent and
unhealable, under-striking is visible and re-runnable, so the bias is
under-striking throughout. What was struck comes back on `struckRungHashes`, and
the entry refuses to publish an empty `nextKeyHashes`
(`NextKeyHashesEmptyError`), which would switch prerotation off. A resumed run
re-runs that whole computation over the log as it stood just before the entry,
located by the key the entry authorized. One residue is accepted: a
client-signed bridge delegation is not revoked, only made inert, since the
transient variant holds no revoker authority and a bridge whose rung no longer
stands committed can extend nothing. A continuation resumed with a different
replacement code than its reveal entry committed (a contract violation)
publishes a second reveal entry committing the new replacement's hash; the
replacement the document then carries anchors on its own member, and the first
replacement's hash stands as an inert orphan in `nextKeyHashes`. The two
continuations share one body (`recovery/continuation.ts`,
`recoveryContinuationOnce`). The completed branch reads its report back off the
log through `recoverySpendRetirementFromLog`, exported for an app resume that
never re-enters the continuation. The roster side has no direct mapping from
that. `retiredCredentialVmIds` are `keyAgreement` verification-method ids, not
roster kids, so they cannot name roster recipients. `rosterRecipientsToRetire`
(`keys/`) works by subtraction: the current epoch's kids minus the ones the
caller names to keep, with the rotation's own document-backed resolver dropping
the rest. Every other standing credential is retired whole, and the cost belongs
in the app's recovery copy: a passkey that survived the loss is retired too and
must be re-added. Between the two entries sits a required `onCommitted` persist
seam (`recoverWebvhClient`, `recovery/recoveryWebvh.ts`), refused with a
`TypeError` before any read when absent. It fires after the reveal-and-commit
entry stands and before the add-and-retire entry -- the ceremony's pivot -- is
built, and a throw withholds the pivot, leaving the code unspent. The caller
durably persists the new client's and replacement code's material there, the
pre-pivot persist half of the post-pivot derivability rule (`decisions/0010`).
The idempotent already-complete branch enters no seam and returns
`committed: false`; a caller clears its pending state on the call returning,
whatever `committed` says. A re-run after a tear at the seam must pass the SAME
replacement halves back in, re-derived from the persisted replacement-code
bytes, since a fresh replacement would strand the hash the reveal entry already
committed with no `keyAgreement` method behind it. With the halves reused, the
only torn-run residue is the never-published client's inert orphan hashes, as on
the self-enrollment seam. Both entry builds run over reads under the store's
chain-head pin, advancing as each entry publishes, and the transient
continuation's `recoverWebvhLadderAnchored` runs its own two entry builds the
same way. Its builder (`delegateLogWrite`: PUT on the one `did.jsonl` resource,
one-year TTL per NIST SP 800-57 cryptoperiod guidance) lives here rather than
app-side, since both apps must mint the delegation byte-identically. No ceremony
re-mints another credential's bridge. A bridge is signed by its own credential's
ladder VM, so the only thing that rots one is retiring the credential it belongs
to, which deletes the record with it. What the module keeps is the staleness
scalars a refresh reads -- `recordedZcapStale` (no longer chaining under
`delegationKeyInDocument`, expired, or inside the renewal window) and
`recordedDelegationFields`, which builds the `delegationKeyId` /
`delegationExpires` pair a registry entry records. A credential's own login
refreshes its bridge on those axes, and the app's login-time health check is the
backstop for a bridge left signed by a foreign key.

The pivots, per ceremony. Issuance's depends on the branch. On the ladder branch
it is the authority entry, the third of the three writes, since only it
publishes the ladder VM and commits rung 0; the key entry and the escrow before
it let the code decrypt while it can still sign nothing, the dead-code tear
`decisions/0018` accepts. On the enrolled branch it is the one merged entry, and
the escrow and the code's unlock record before it are inert until the document
backs them. Invariants a torn run can leave violated (numbered as in
`INVARIANT_IDS`, `menders/ids.ts`): 1
`roster-wraps-exactly-the-document-key-set`, 18
`did-web-projection-matches-the-log`, 29
`every-document-key-agreement-entry-has-a-locatable-credential`, and 32
`saved-recovery-codes-locate-their-account`.

The spend's pivot is the add-and-retire entry on both variants, which share the
one body. The transient variant mints the annex Space and generation at the
seam, pre-pivot and inert until the entry's pointer move names them, one orphan
per torn attempt. Invariants a torn run can leave violated (numbered as in
`INVARIANT_IDS`, `menders/ids.ts`): 1
`roster-wraps-exactly-the-document-key-set`, 3
`collection-epochs-name-the-current-user-key`, 4
`unlock-registry-opens-under-the-current-user-key`, 18
`did-web-projection-matches-the-log`, 23 `no-client-key-record-stays-pending`,
24 `recovery-spend-is-completed`, and 30
`no-unlock-space-outlives-its-credential`.

The revocation's pivot is the removal entry, one on either signer arm. The
retirement gate fires before it, so a refusal writes nothing. The roster
rotation off the code's wrap is the caller's and post-pivot. The ladder arm's
`did:web` projection PUT precedes the entry as it does in client revocation,
fail-closed and re-derived. Invariants a torn run can leave violated (numbered
as in `INVARIANT_IDS`, `menders/ids.ts`): 1
`roster-wraps-exactly-the-document-key-set`, 2
`governed-log-heads-anchor-past-the-membership-change`, 3
`collection-epochs-name-the-current-user-key`, 4
`unlock-registry-opens-under-the-current-user-key`, 8
`standing-delegations-verify-under-the-current-document`, 18
`did-web-projection-matches-the-log`, and 32
`saved-recovery-codes-locate-their-account`.
