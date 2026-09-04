# 0020: A recovery code is a standing credential with a ladder

- Status: accepted
- Date: 2026-09-03
- Driving work: the browser wallet's design for running the
  account-management ceremonies from a credential-only transient session.
  Making every unlock record self-signed (decision 0019) needs every
  unlock credential to hold a ladder, and the recovery code was the one
  credential that did not.
- Affects: wallet-core `/recovery` (the code's key-set derivation, the
  issuance and spend ceremonies, `removeRecoveryKey`), `/unlock` (the
  retirement gate's recovery carve-out), `/clientAnnex` (the ladder
  derivations the code now consumes); both wallets' recovery-code
  issuance, spend, and revocation surfaces; every recovery code already
  issued.

## Context

A recovery code was a minimal wallet client whose whole key set derived
from its 16 bytes: an unlock identity, a client seed, one standalone
did:webvh update key, and a binding MAC key. Its inventory was split
deliberately. Its `keyAgreement` key published verbatim in the account
document and its user key wrap stood in the roster, so decryption
stood. Its authority stayed latent, since the update key joined
`updateKeys` nowhere and only its hash was committed. The one bridge
into the capability profile was a pre-minted PUT-on-`did.jsonl`
delegation carried in the code's unlock record.

That bridge had to be signed by whatever key issued the code, because
the code held no document verification method of its own. Decision 0019
ends that arrangement for every other credential and cannot end it here
without giving the code a ladder. A ladder also gives the code the
verification method its bridge needs as a signer.

The relevant property of the code is its entropy. It is 16 uniform
bytes. That is what already admits verbatim publication of its
`keyAgreement` under the hash-commitment rule, and it is what admits a
code-derived ladder where a passphrase-derived one would be a standing
offline grind oracle against a revealed rung.

## Decision

A recovery code is a standing unlock credential with a ladder. It
differs from a standing passphrase or passkey in one respect: it retires
on spend.

Its key set gains a ladder seed derived from the code bytes, with HKDF
salt `freewallet/recovery/client-keys/v1` and info `ladder-seed`. That
is the sibling of the existing `client-seed` expansion and the direct
replacement of the `update-key` slot in the same family. The
`update-key` expansion and its label are deleted, and the label is never
reused.

Rung 0 of that ladder is the code's committed update key. It derives
exactly as the ladder module derives every rung, from the ladder seed
under the ladder's own salt and rung label. So a spend's
reveal-and-commit entry is the ordinary ladder reveal rather than a
special case.

The code's ladder VM publishes under `assertionMethod` and
`capabilityDelegation`, beside its verbatim `keyAgreement`. It signs the
code's own bridge delegation (decision 0019). The record stays a pure
pointer: the ladder seed derives from the code bytes rather than being
stored in the record, so the record still holds no seed and no key wrap.

Revocation strikes the code's ladder VM beside its verbatim
`keyAgreement` and its committed rung hash. The revoker holds neither
the code bytes nor its ladder seed, so the claim is seedless. Its anchor
is the code's rung-0 update-key multibase, which the registry entry
records at issuance. Ladder attribution takes that multibase as an
anchor beside its other two forms and walks the log from there. A
revocation whose attribution claims no ladder VM refuses, with the same
typed refusal a credential retirement raises. The refusal names the
verification method and the anchor it lacked. Leaving the VM standing
would leave a supposedly revoked code holding a delegation signer.

The ladder VM is not a new exposure. A stolen code already grants full
takeover, since its holder spends it, sets a passphrase of their own,
logs in, and can delete the account from Settings. The DELETE-only child
of the account Space's root that the VM can mint destroys the log any
record of the act would live in. That is why the deletion exception to
loudness exists already, and why the ceremony's own consent surface
stands in for the missing entry. The one licensed roster append
the VM can make wraps only to recipients the verified document lists,
since the recipient resolver drops the rest, and the thief already holds
the code's own wrap. So the code sits in the same class the standing
passphrase and passkey occupy, under the same three-way bound on ladder
delegations: a ladder delegation either needs a loud companion entry to
resolve, or can only write a log, or is a target-exact single-verb read
or delete of one Space of the delegator's own account.

## Rejected Alternatives

- **Keep the standalone `update-key` expansion as the code's rung 0, and
  let the ladder supply only the VM and any later rung.** Every code
  issued before this lands would keep spending. It is a compatibility
  fallback carried on the wire for the life of the format, with a ladder
  whose rung 0 comes from a different derivation than every other rung,
  and a second attribution shape for readers to carry. The greenfield
  rule is that no such fallback is carried. The cost of the alternative
  is permanent; the cost of the decision is one release.
- **Leave the recovery code without a ladder, and let its bridge stay
  foreign-signed.** That is the state decision 0019 exists to end. Every
  code issued from a transient session would die at the next strike of
  its issuer's key, with no ceremony able to re-seal its record.
- **A commitment for the code's `keyAgreement`, matching the
  passphrase.** Not reopened here. The code's entropy admits verbatim
  publication, and the roster's recipient resolver needs a key it can
  wrap to.

## Consequences

- Every recovery code issued before this lands stops spending. Its
  committed update key was derived from the deleted expansion, so the
  reveal entry a spend publishes cannot be signed. The release notes tell
  users to re-issue their codes. The login-time health check cannot
  detect this, because the registry entry for such a code looks healthy,
  so the notes are the whole of the notice.
- Issuance on the ladder branch splits into a key entry, the escrow
  append, and an authority entry carrying the ladder VM and the rung-0
  hash (decision 0018). The code's decryption material precedes its
  authority, so a tear leaves a dead code rather than one that can spend
  and cannot decrypt.
- The recovery carve-out in the retirement gate (decision 0015) ends.
  `removeRecoveryKey` now has a ladder VM to claim and refuses when it
  cannot claim it.
- The registry entry's recorded rung-0 update-key multibase becomes
  load-bearing: it is the anchor a seedless revocation attributes from.
  An entry written without it leaves a revocation that refuses.
- The `client-seed` expansion may become unused. With the bridge signed
  by the code's own ladder VM, the bridge's delegatee can be that VM's
  bare did:key, which is the pattern the deletion ceremony already uses.
  If the build confirms no remaining consumer, that expansion and its
  label are deleted too.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. The code's length or alphabet changes such that it is no longer high
   entropy. Both the verbatim `keyAgreement` and the code-derived ladder
   rest on the 16 uniform bytes.
2. A ladder delegation gains a shape outside the three-way bound above.
   The weighing that found the code's ladder VM not to be a new exposure
   rests on that bound holding.
3. Seedless ladder attribution gains or loses an anchor form. The
   revocation's fail-closed refusal is calibrated to the anchors that
   exist.
4. A code kind arrives that must remain spendable across a derivation
   change, which would reopen the greenfield rejection above as a
   versioned key set rather than as an in-place fallback.
