# 0019: Every unlock record is signed by its own credential

- Status: accepted
- Date: 2026-09-03
- Driving work: the browser wallet's design for running the
  account-management ceremonies from a credential-only transient session.
  Several of those ceremonies strike a key that had signed other
  credentials' unlock records, and the ladder branch has no way to
  re-seal them.
- Affects: wallet-core `/unlock` (the record binders and
  `retireUnlockCredential`'s dependent-record re-mint closure),
  `/recovery` (the record binder and the delegation re-mint core),
  `/clientAnnex` (the last-client transition's record stages); both
  wallets' bind sites for standing unlock records and recovery records.

## Context

An unlock record carries an account pointer, a bridge delegation, and,
where the credential has one, a `delegatedClients` sibling delegation.
The record is sealed to the credential's unlock key-agreement key and
carries a proof. Until now the bridge and the sibling were signed by
whichever key happened to be acting at bind time. On a remembered
session that is the enrolled client's account key. On a transient
session it is the annex verification method or another credential's
ladder VM.

That made a record depend on a signer outside its own credential. Any
ceremony that struck such a signer left every dependent sibling record
with a bridge that verifies nowhere, so the ceremony owed a re-seal of
records it did not own. The enrolled branch could pay that debt, because
an enrolled client's key is listed in the account document and can PUT
into a sibling unlock Space.

The ladder branch cannot. A sibling unlock Space's management zcap is
delegated to the account did:webvh, and the ladder-branch invoker is the
annex verification method, which the account document does not list. The
storage server admits a ladder-signed child of that zcap only as a
target-exact single-verb GET or DELETE. There is no shape in which a
ladder-branch ceremony writes another credential's record. Without a
rule, a client disconnect or a credential retirement run from a
transient session would rot every sibling record and leave every
recovery code issued from such a session dead at the next strike of its
bridge's signer.

## Decision

An unlock record's bridge delegation, and its `delegatedClients` sibling
delegation where it carries one, are signed by the ladder VM of the
credential that record belongs to. The record proof is signed by that
same credential's unlock identity key. This holds at bind time, on both
branches, for standing passphrases, passkeys, and recovery codes alike.

It is always possible, because the new credential's ladder seed is in
hand at every bind. The ceremony that creates the credential mints the
seed, and a re-bind of an existing credential runs from the typed
credential, which derives it.

The consequence is the reason the rule exists. The only account-document
key a record depends on is its own credential's ladder VM, which stands
for exactly as long as that credential does. A record's contents can
therefore be rotted only by retiring the record's own credential, and
that retirement deletes the record and its unlock Space in the same
ceremony.

So no ceremony owes a re-seal of a sibling record. Three stages existed
to pay that debt. They are the retirement's dependent-record re-mint
closure, the revocation cascade's recovery-delegation re-mint, and the
last-client transition's record re-mint stages. None is owed for records
bound after this rule lands, and the ladder branch carries none of
them.

## Rejected Alternatives

- **Refuse before the pivot when a strike would rot a sibling record.**
  A pre-pivot check on every registry entry whose bridge, sibling, or
  proof the struck key had signed, stopping the ceremony and pointing the
  user at a remembered session. It is the rejected step-up ceremony under
  another name, reached from the other side. It makes the account's
  documented leaked-credential remedy conditional on the very enrollment
  the transient branch exists to avoid, on exactly the accounts that are
  the default. It blocks nothing an attacker cannot route around, since a
  credential holder can self-enroll and run the enrolled branch. And it
  degrades with ordinary use: every recovery code issued from a transient
  session would plant a permanent refusal in every later ceremony on that
  account, so a user following the recovery-code advice would lose the
  ability to change their own passphrase. Do not reopen without first
  saying what a user holding only their credential does when the refusal
  fires.
- **A server-admitted ladder-signed PUT child of the management zcap.**
  It would let the ladder branch re-seal a sibling record directly. It is
  a widening of the server's ladder-authority clause, with its own design
  pass and its own sign-offs ahead of it, and it is not needed once the
  dependency is removed.
- **Keep client disconnect, credential retirement, and recovery-code
  issuance on the enrolled branch.** That is the subject of the work
  itself. It leaves the default account unable to run its own
  account-management ceremonies.

## Consequences

- Greenfield. Records bound by earlier code, and recovery codes issued
  before the rule lands, are not migrated. Such a record keeps its
  foreign-signed bridge until its credential is re-bound or its code
  re-issued. The login-time health check's delegation-rot detection is
  the detector for exactly that class, and the remedy it nudges is what
  brings the record onto the rule.
- The last-client transition's `UnrecordedCredentialForgetError` refusal
  survives only for those pre-rule records. A standing credential the
  registry does not name would keep a bridge an enrolled client's account
  key signed, which the removal entry rots with no replacement. Once no
  pre-rule record remains on an account, the refusal has nothing to
  catch.
- A recovery code could not satisfy the rule before, because it held no
  ladder and its bridge had to be signed by whatever key issued it. The
  code gains one (decision 0020).
- Every bind site now needs the credential's ladder seed in hand,
  including the re-bind paths that previously signed with the acting
  session's client. A bind that cannot reach the seed is a defect rather
  than a fallback to a foreign signer.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A ladder-signed PUT into a sibling unlock Space becomes admissible,
   which would restore the option of paying the re-seal debt instead of
   removing it.
2. A credential kind arrives that cannot derive a ladder seed of its own.
   The rule's "always possible" clause rests on every unlock credential
   having one.
3. The account document stops keying a credential's ladder VM to that
   credential's lifetime, which is what makes "rotted only by its own
   retirement" true.
