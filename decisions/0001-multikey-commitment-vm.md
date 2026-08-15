# 0001: MultikeyCommitment verification methods

- Status: accepted
- Date: 2026-08-15
- Driving work: the ratification pass over the wire conventions the
  standing-unlock-credential work introduced in wallet-core
- Affects: wallet-core `webvh` (`keyAgreementCommitment`),
  `unlock/standingWebvh.ts` (the posture VM builder), `keys` (the roster
  resolver's commitment-verification branch); byoe-context (the two term
  definitions); every did:webvh document freewallet and dcw publish with a
  low-entropy standing unlock credential

## Context

A standing unlock credential derived from a low-entropy secret (a
passphrase) must not publish its key-agreement key verbatim in the
did:webvh document: the key derives from the secret, so the published
multibase would be an offline verification target on a world-readable
artifact. The document instead carries a hash commitment to the key, which
the roster resolver verifies against a candidate key at wrap time. The
first implementation reused the `Multikey` VM type and the `nextKeyHashes`
hashing rule (base58btc multihash over the multibase string). The
representation is permanent once a document publishes it, so it needed
explicit ratification before wallet-core 0.42.0 ships.

## Decision

A commitment is an unmarked `keyAgreement` verification method:

```
{ id: <did>#<commitment>, type: MultikeyCommitment,
  controller: <did>, publicKeyCommitment: <commitment> }
```

- The VM type is `MultikeyCommitment`, conceptually inheriting from
  `Multikey` (an rdfs vocab statement is pending).
- The property is `publicKeyCommitment`, named for what the hash does.
- The value is the bare multihash (sha2-256), encoded base64url-no-pad.
  No multibase prefix. The multihash header keeps the algorithm
  self-describing, so verification decodes rather than re-encodes.
- Both terms are defined in byoe-context, and the byoe context is added to
  the did:webvh document's `@context`.
- The `nextKeyHashes` rule in `parameters` is untouched; it keeps its
  base58btc encoding. The two hashing conventions are now deliberately
  independent.

The commitment does not reduce offline-guessing exposure relative to a
verbatim key (one extra sha256 per guess under the fixed KDF salt). What
it provides is the document-anchored integrity check for the roster
resolver plus non-disclosure of the key material itself; the offline
exposure belongs to the standing-credential model and its KDF choice.

## Rejected Alternatives

- Keep `Multikey` as the VM type: a Multikey with no `publicKeyMultibase`
  is type-dishonest, and readers keying on the type would mispair it with
  real keys.
- Reuse the `nextKeyHashes` base58btc rule for the value: couples a
  document term to an unrelated log-parameter convention, and multibase
  adds nothing here. The base prefix is a trivial deterministic reformat,
  unlike the codec and hash dimensions, which stay self-describing via
  the multihash header.
- A `digestMultibase`-style property: nominal reuse only; no published
  context defines such a term on a verification method.
- A document-level extension property or service entry instead of a VM:
  the commitment belongs beside its sibling `keyAgreement` entries, and
  `@interop/did-method-webvh` is confirmed to preserve VM-level extra
  properties through create, update, resolve, and the did:web projection
  (byoe-ecosystem LEARNINGS.md, 2026-08-15).

## Consequences

- byoe-context gains the `MultikeyCommitment` and `publicKeyCommitment`
  terms; their spec home is noted in the companion spec repos when the
  terms are documented.
- The roster resolver verifies commitments by multihash decode, so the
  scheme is hash-agile without a version field.
- Documents published under the pre-ratification encoding are not
  migrated; the greenfield posture applies (re-provision).
- One sub-decision was left open at ratification and is tracked with the
  implementing work: whether the commitment hashes the decoded multikey
  bytes or the multibase string.

## Revisit Criteria

Reopen this decision when one or more of the following holds:

1. A published vocabulary defines a standard commitment verification
   method type; adopting it would be a new term alongside this one, with
   existing documents left intact.
2. sha2-256 must be replaced for a partner or compliance reason; the
   multihash header already carries the algorithm, so this is an
   additive change to the accepted set, not a format change.
