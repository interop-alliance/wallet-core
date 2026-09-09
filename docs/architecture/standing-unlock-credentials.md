<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# Standing unlock credentials (`unlock`)

Every unlock method -- a passphrase, a passkey PRF output, a recovery code -- is
a standing credential in the recovery-code configuration: a `keyAgreement` entry
in the account document, a user-key wrap in the roster escrowed into every epoch
and kept alive by rotation fan-out, and latent self-enrollment authority. A
fresh browser holding nothing but the credential self-enrolls as an ordinary
full client, with no second party involved. The recovery code's spend-on-use
flow is the special case (`recovery` sits on top of this module).

The pieces, and where each secret lives:

- **The client identity** (`standingClient.ts`): the credential's client seed
  and binding MAC key expand from the method's 32-byte unlock seed under the
  permanent `freewallet/unlock/standing-client/v1` salt, so the expensive
  passphrase stretch runs once and each method's distinct unlock-KDF salt keeps
  identities apart. The identity assembly (agents, multibases, roster kid) is
  shared with the recovery-code derivation (`unlockClientIdentityFromSeed`).
- **The update-key ladder** (`ladder.ts`): latent-and-consumed did:webvh update
  authority. Rungs derive by HKDF from a RANDOM 32-byte ladder seed carried in
  the unlock record, not from the unlock secret: a revealed rung lives verbatim
  in world-readable `updateKeys` forever, where no commitment could protect a
  secret-derived key. Between uses only `hash(rung i)` stands in
  `nextKeyHashes`, and there is no stored counter. The current rung is recovered
  by re-derive-and-scan over the published parameters (`attributeLadderRung`),
  and ambiguity fails closed (`LadderAttributionError`).
- **The ladder VM** (`ladderVmSeed` / `ladderVmKeyMultibase` in `ladder.ts`, the
  document builder `ladderVerificationMethod` and the recognition `ladderVmIds`
  in `webvh`): the STABLE SIBLING, a dedicated Ed25519 key derived once from the
  ladder seed under the same salt with the fixed info label `vm`, published
  verbatim (the seed is random, so the hash-commitment rule permits it) and
  stable across rung spends. Its life is keyed to its credential: installed when
  it becomes standing, struck at its retirement, untouched by enrollment. It is
  listed under `assertionMethod` and `capabilityDelegation` ONLY, and
  recognition is by that relation asymmetry (a `capabilityDelegation` member
  absent from `capabilityInvocation`), which keeps it structurally out of every
  client listing. The annex's per-visit transient VM holds BOTH relations
  (decision 0013), so it never matches the asymmetry. Ladder-anchored genesis
  (`createLadderAnchoredAccountLog`) anchors the log on the ladder alone:
  `updateKeys` = [rung 0], `nextKeyHashes` = [hash(rung 0), hash(rung 1)] (both
  genesis flavors build the pair with `genesisNextKeyHashes`), and the
  credential's `keyAgreement` inventory rides the genesis entry. The first
  self-enrollment's add entry leaves every VM where it is: client in, rung 0
  retired, no VM struck. An account always carries an enrolled client or a
  ladder VM. Because the sibling is derived, removal is not permanent: a
  reinstall republishes the SAME key under the SAME id, and a still-unexpired
  delegation it signed resumes verifying. So delegation revocation, not VM
  removal, is the terminal remedy for ladder-signed delegations, and credential
  rotation is the remedy for a leaked ladder seed. `removeUnlockKey` strikes the
  retiring credential's VM in the same entry as the rest of the ladder's
  inventory, seed in hand or not. Otherwise the retired seed would keep signing
  governed-log appends and account delegations.
- **The unlock record** (`unlockRecord.ts`): the keyring-record frame extended
  with three members the proof also covers. The shell (`wrapped`: controller,
  optional email, pointer, bind timestamp) and the sealed `ladder` member are
  carried VERBATIM through a re-bind. The sealed `bridge` member (the pre-minted
  PUT-on-`did.jsonl` delegation) is the one member a re-bind replaces
  (`remintUnlockRecordDelegations`), and only the record's OWN credential
  re-binds it (`decisions/0019`). The `binding` frame member is an HMAC under
  the credential-derived MAC key over controller, pointer, AND ladder seed,
  verified before the pointer is trusted, so a storage host can neither redirect
  login at another account nor substitute a ladder of its own. The mixed-signer
  policy is the recovery record's: bind-time records verify before decryption,
  re-minted ones come back pending for the caller to settle against the verified
  document.
- **The document inventory** (`unlock/standingWebvh.ts`): one merged add/remove
  edit (`publishUnlockKey` / `removeUnlockKey`) publishes the credential's
  `keyAgreement` entry, installs its ladder VM, and commits its current update
  key's hash. The ADD polarity takes the ladder seed from its caller rather than
  minting one, so a re-run tests presence against the same seed and publishes
  nothing on a completed stage; a self-minted seed would let a torn
  establishment publish a second VM no anchor can later strike. A bind reaching
  a standing member whose `ladderCommitment` is not this ladder's rung-0 hash
  refuses (`LadderAttributionError`, nothing written), since re-adding the
  member under the new hash would leave it unclaimable seedlessly and orphan the
  first ladder's VM and commitment. The converging re-run holds the seed that
  bound the member. A fresh bind is held to the seed the same way: the recorded
  update key must be the seed's rung 0, and an attributed later rung (what a
  registry records after a self-enrollment) refuses before any entry is built.
  Only a seedless bind commits the recorded key's hash unchecked, as does the
  remembered recovery continuation for the replacement code's member. The REMOVE
  polarity treats the recorded update key as a ladder anchor, not truth. It
  resolves the ladder's current inventory from the log
  (`attributeLadderInventory` -- every standing committed hash, plus any
  revealed rung a torn self-enrollment left in `updateKeys` and the hashes its
  reveal entry committed) and strikes all of it in one entry, since a stale
  bind-time rung would leave the live rung commitment standing as a latent
  re-seizure credential. The member's own `ladderCommitment` is the second
  anchor, and the removal walks from both (`attributeUnlockLadderInventory`):
  the member-anchored walk starts at rung 0 and is the reading the strike acts
  on, the registry-anchored one must be contained in it, and two anchors
  resolving to different ladders refuse rather than striking whichever ladder
  one anchor names. A member naming no anchor leaves the registry walk to answer
  alone. A supplied ladder seed must derive the member's named commitment,
  strengthens the attribution, and names the credential's ladder VM, which the
  entry strikes from `verificationMethod`, `assertionMethod`, and
  `capabilityDelegation` when it stands. A removal holding no seed strikes that
  VM by attribution over the log: VM_x belongs to the ladder that signed the
  entry that first published VM_x, that introduced this credential's member
  there, or that committed a hash the ladder knows a priori there. The walk
  first recovers the rungs behind the recorded anchor from the log's positional
  rules, so it is anchor-invariant wherever a rung's hash was committed by an
  entry revealing the previous rung or by a handover, and an ambiguous walk
  fails closed (`LadderAttributionError`). It climbs through an entry that
  installs the credential's own inventory (its member, or a ladder VM not
  standing before) only where the signer's own hash is newly committed there,
  the ladder-anchored genesis shape, since a committed rung revealing itself in
  the bind entry it signs for a newcomer is the acting credential's. One
  reachable shape falls outside that: the last-client transition's
  strike-and-reinstall pair, then a self-enrollment spending the
  already-revealed rung. That reveal-and-commit entry authorizes no key, so the
  backward walk cannot name the rung that signed it, while the member-anchored
  walk reads the history forward and claims the reinstalled VM. Only a member
  naming no anchor is left to the backward walk, where the retirement is refused
  -- the retirement gate (`decisions/0015`, see "Credential retirement" in
  client-revocation.md) and its `UnclaimedLadderVmRetirementError`, which a
  retry holding the credential's ladder seed gets past. Seedless, the walk also
  relies on the reveal entry's ratified hash append order
  (`decisions/0007-ladder-reveal-hash-order.md`) plus the credential's own
  verification-method id (`credentialVmId`), which the removal always passes.
  What a completing entry does not transfer to the enrolled client is
  ladder-owned only on POSITIVE attribution: the seed derives the hash, or the
  credential comes out of that entry still standing, which makes the leftover
  its next rung's commitment. A spend leaves its SUCCESSOR's commitment in that
  position, and a leftover the walk could not attribute is released rather than
  struck. The entry carries the key verbatim for a high-entropy credential. For
  a low-entropy-derived one it carries a `MultikeyCommitment` entry with only
  `publicKeyCommitment` (computed by `keyAgreementCommitment`: the bare sha2-256
  multihash of the key's decoded multikey bytes, base64url no-pad), which
  withholds the key material and gives the roster resolver a document-anchored
  check. It does not reduce offline guessing exposure, which belongs to the
  standing-credential model and its KDF choice. Either flavor also names its
  ladder's rung-0 commitment as `ladderCommitment`, the same hash the bind
  commits in `nextKeyHashes` and the anchor a seedless reader walks the
  credential's ladder from; the roster resolver and every client listing ignore
  it. Both entry flavors are deliberately unmarked, so client listings (keyed on
  `capabilityInvocation`) and revocation removals never see them.
- **Self-enrollment** (`selfEnrollWebvhClient`, composed end to end by
  `selfEnrollClientCore`): the recovery continuation generalized to a
  non-spending credential. Two entries through the delegated bridge: a
  reveal-and-commit entry signed by rung `i` (committing the new ordinary
  client's hashes plus `hash(rung i + 1)`), then an add entry signed by the new
  client's update key that also retires the spent rung. The credential's
  inventory stands afterwards on rung `i + 1`; nothing is spent and no
  replacement exists. A lost compare-and-swap race re-runs, re-attributes, and
  climbs to the winner's committed rung (retry-up-the-ladder), which by
  determinism IS the loser's retry key. The reveal entry is built on a read
  under the store's chain-head pin, advanced as each entry publishes, so a
  served truncated prefix is refused before the reveal entry lands. The add
  entry is built on the head the reveal entry's own publish leaves standing,
  with no read in between; against a store whose PUT serves no ETag it is
  re-read under the same pin instead, so its compare-and-swap never degrades to
  an unconditional write. Between the two entries sits a required persist seam
  (`onCommitted`, refused with a `TypeError` before any read when absent): it
  fires once per attempt, after the reveal-and-commit entry stands and before
  the add entry -- the ceremony's pivot -- is built, and a throw withholds the
  pivot. The caller durably writes the pending client-key record there. At the
  `selfEnrollClientCore` surface the hook also receives the minted-or-resumed
  client seed and update-key seeds, so the record precedes a pivot that names a
  client nothing else can re-derive. That is the pre-pivot persist half of the
  post-pivot derivability rule (`decisions/0010`). The returned `committed` flag
  says whether this call entered the seam (`false` on the idempotent
  already-complete branch, which enters no seam); a caller clears its pending
  record on the call returning, whatever `committed` says.
  `selfEnrollClientCore` also takes an optional `resume` (the pending record's
  seeds plus the head the pivot was built on): it skips the mint, re-derives the
  same key set, and republishes only the missing entries, refusing with
  `BuiltOnHeadNotReachedError` when the served log's SCID differs from the
  recorded head's or lacks an entry at its recorded version -- the fork guard
  for a resume whose chain-head pin write (non-atomic, after the pivot) never
  landed. That marker covers only the pre-pivot half of the gap. A log that
  contains the recorded head but is truncated behind the torn run's own add
  entry is mended by the client's own pin once written, or by another enrolled
  client's pinned read. A throwing hook leaves one accepted residue: the reveal
  entry's committed hashes for the never-persisted client stand as permanent
  inert orphans in `nextKeyHashes`. The composed core then verifies the account
  log under the same pin, performs the first roster read unwrapping the user key
  from the CREDENTIAL's standing wrap, and escrows the new client into the
  roster as its own recipient.

Loudness is the standing compensating control: a self-enrolled client extends
the same world-readable hash-chained log every other client's chain-head pin
checks, so takeover is visible and remediable rather than prevented by an
enrollment gate. What bounds the whole construction, standing: server-held key
material decryptable by an unlock credential is bounded only by that
credential's entropy against a malicious storage host, so the custodian of the
unlock credential must not be the storage host.
