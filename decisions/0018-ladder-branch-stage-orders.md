# 0018: Ladder-branch stage orders, with the escrow placed by signer kind

- Status: accepted
- Date: 2026-09-03
- Driving work: the browser wallet's design for running the
  account-management ceremonies from a credential-only transient session.
  Each ceremony body gains a second binding, where a ladder rung signs
  the account-log entry and the annex verification method invokes under
  the generation delegation.
- Affects: wallet-core `/webvh`, `/unlock`, `/recovery`, `/enrollment`,
  `/clients`, `/clientAnnex` (every ceremony body that publishes an
  account-log entry); the ceremony stage orders both wallets document;
  dcw's enrollment and disconnect call sites.

## Context

Every account-management ceremony used to take an enrolled client's
did:webvh update keys and sign its document entry with them. A transient
session holds no such key. It holds a ladder seed, whose rungs sign
account-log entries through the credential's bridge delegation, and an
annex verification method that invokes inside the account Space's items
subtree under the generation delegation.

Giving each ceremony a second binding raises two questions the bodies
cannot dodge. The first is what the signer looks like as a parameter.
The second is where the roster append sits relative to the document
entry, because the two branches are not free to choose the same place.
An enrolled client's roster append needs no license from the
ceremony-tail license, so it may precede the entry. A ladder-signed
append is admitted only at an inventory-changing document version that
the appending ladder's own rung signed, so it cannot precede the entry
that mints that version.

One further property of the ladder arm constrains the shapes.
`ladderSignedAccountEntry` unions the acting rung and its hash back into
the entry it signs, so an entry cannot remove its own signer.

## Decision

Four points, ratified together.

**One body per ceremony, with the signer as a parameter.** Each ceremony
body takes `signer: AccountLogSigner`, a discriminated union of
`{ kind: 'client', updateKeys }` and `{ kind: 'ladder', ladderSeed }`,
beside its roster store and its HTTP invoker. There is no compatibility
arm; callers pass the client kind until their ladder bindings land.
`rotateWebvhUpdateKey` is the one body that keeps `updateKeys` directly,
since that key is its subject. The ladder arm is
`ladderSignedAccountEntry`, promoted from internal use: a pinned read,
rung attribution, the carry-over precondition, self-reveal of the acting
rung into `updateKeys`, the carry-over hash beside the build's commit
hashes in `decisions/0007` order, a conditional publish, and a pin
advance. An entry the ladder signs keeps its signing rung in
`updateKeys`, so no entry removes its own signer, and a ceremony that
must retire a rung needs a second entry signed by the successor.

**Recovery-code issuance writes the record before the entry.** The
code's unlock record, its unlock Space, and its bridge delegation are
written before any document entry, on both branches. That is
persist-before-publish applied to the code: nothing the entry publishes
may depend on state only a live tab could re-derive.

**The escrow append is placed by signer kind.** One body, one
conditional, two orders.

For a client signer the escrow append precedes the document entry. The
enrolled branch keeps roster-first, which preserves the property the
enrollment module states, that no authorized-but-unwrapped window exists
at any point. A tear there leaves an orphan wrap, which is invisible to
authorization and harmless.

For a ladder signer the escrow append follows the document entry, since
a ladder-signed append is licensed only at an inventory-changing version
its own ladder signed. Two ceremonies take their shape from that.

Recovery-code issuance on the ladder branch splits its entry in two. A
key entry publishes the code's verbatim `keyAgreement` alone. The escrow
append follows, anchored at that version. Then an authority entry
publishes the code's ladder VM and commits its rung-0 hash. The code can
spend only from the second entry, so the code's decryption material
still precedes its authority.

Enrollment approval on the ladder branch runs a commit entry, then the
add entry, then the escrow append. The one-request window between the
add entry and the append is a stated cost of the branch, and it is not
harmless. A client the add entry published holds `assertionMethod` and
its own update key, and an enrolled client's roster append needs no
license, so a client left in that window could append a rotation of its
own. It is bounded three ways. It is one request wide on the happy path.
A tear is mended by a re-run of the approval with the same connect code,
whose stages detect themselves from the standing commitments, and by the
escrow-direction convergence of any later ladder-branch ceremony, since
the document carries the client's key-agreement key verbatim. And the
row it leaves is visible in the Connected wallets listing, where a
disconnect removes it.

**The passphrase change on the ladder branch is two entries.** A bind
entry signed by the old credential's rung publishes the successor's
key-agreement commitment and its ladder VM, and commits the successor's
rung-0 hash. The escrow append follows at that version. Then a strike
entry signed by the successor's rung 0 removes the old credential's
inventory. A single add-and-retire entry is impossible, because the
entry keeps its own signer, so an entry signed by the old rung cannot
strike it. Establish-first is preserved: the new credential's whole
standing configuration lands before the old credential is touched.

Two properties are recorded with these orders.

A ladder-branch rotation append converges in two directions. The retire
direction rotates away any current-epoch recipient the verified document
no longer keys. The escrow direction adds a wrap in every epoch for any
document-listed recipient whose public key the document carries
verbatim and who holds no wrap. Both directions ride one append,
anchored at the acting ceremony's own licensed version, so a roster an
earlier ceremony left torn is mended by the next ladder-branch
ceremony's append in whichever direction the tear needs.

Rung 0 stands revealed in the world-readable `updateKeys` for the
credential's life. Rungs are reused rather than consumed: rung
attribution prefers a revealed rung over a committed one, so a
credential signs every single-entry ceremony with the same rung until an
entry retires it. Prerotation protects that rung across none of these
ceremonies. This is accepted on custody. The rung's private half exists
only in tab memory during a ceremony, derived from the ladder seed just
unsealed from the unlock record, so no attacker holds the rung without
holding the seed, and the seed yields every rung. The attackers who do
arise, a phished credential and an offline grind of the record, hold the
seed, and credential rotation is already their remedy.

## Rejected Alternatives

- **One stage order for both branches.** The draft ran entry-first
  everywhere so that one body had one order. On the enrolled branch that
  trades a tear-free order for nothing the branch needs. Entry-first on a
  tear leaves a fully authorized client whose private key may have died
  with the enrollee's tab, in place of a harmless orphan wrap. It also
  costs one extra world-readable entry per code issued and changes a
  stage order dcw already documents.
- **Two ceremony implementations per user action.** The stated non-goal.
  Every documented residue would need two menders, and the two would
  drift. A placement conditional inside one body is not a second
  implementation.
- **Fusing the ladder branch's issuance entries.** One entry carrying the
  code's `keyAgreement`, its ladder VM, and its rung-0 hash together
  would leave, on a tear before the escrow, a code that can spend and
  cannot decrypt. A spend unwraps every epoch through the spent code's
  own wrap, so spending such a code strikes every standing credential and
  then fails, destroying the account. The split costs one permanent entry
  and keeps every tear in the harmless dead-code class. Publishing the
  ladder VM in the first entry instead was also rejected: a torn issuance
  would then leave a code that cannot spend and can still mint a
  DELETE-only child of the account Space and delete the account.
- **Retiring the acting rung at the end of each ceremony.** Because an
  entry keeps its own signer, retirement takes a second permanent entry
  per ceremony. The ladder scan budget would then become a real
  limitation, forcing credential rotation after a fixed number of
  ceremonies. And the entry that mints a license shot and the entry that
  retires the rung would be different versions, which the append can
  anchor at only one of.

## Consequences

- The signer parameter is a breaking change for every caller. dcw shares
  these bodies and passes the client signer kind until its own ladder
  binding lands, so its stage orders and its documented enrollment order
  are unchanged by this record.
- A passphrase whose escrow append was lost to a tear has one mender
  only: a retry of the same ceremony, holding the same new passphrase.
  The document publishes a commitment rather than the key, so the
  escrow-direction convergence cannot derive the wrap, and the credential
  stands in the document while its own transient login refuses at the
  roster. A passkey and a recovery code publish verbatim and are mended
  by convergence.
- Two ceremonies racing for one license shot at the same version is now
  a real state, so the admitted appends need a register. Each ceremony's
  anchoring entry and the license shape it spends are named in
  wallet-core's ARCHITECTURE.md beside the ceremony-tail license.
- A ceremony torn between its entry and its append leaves that shot
  dead. The two-direction convergence means a later ceremony's append
  mends the roster, so the residue is bounded to the window between the
  two. Whether a dedicated fresh-version entry is wanted where no later
  ceremony comes is open, and belongs to the license's own item.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The ceremony-tail license admits a ladder-signed append before the
   entry that mints its version, which would remove the reason the two
   branches order the escrow differently.
2. The entry-keeps-its-signer rule changes in the did:webvh log layer.
   Both the two-entry passphrase change and the standing revealed rung
   rest on it.
3. A second wallet implements the ladder branch, at which point the
   placement conditional is being read by code this repo does not own and
   the two orders need a conformance statement rather than a record.
4. The escrow-direction convergence gains a way to derive a
   commitment-published credential's wrap, which would give the
   passphrase residue a mender other than the retry.
