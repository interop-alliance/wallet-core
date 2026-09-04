/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * Seedless ladder-rung attribution over a verified account log: which update
 * keys are rungs of which standing ladder, read from the log alone. The
 * ceremony-tail license's third shape needs it -- shape 3 admits a
 * ladder-signed roster append only when the document version it anchors at was
 * itself signed by a rung of the SAME ladder that signs the append, and a
 * reader on the verify side holds no ladder seed to answer that with.
 *
 * The walk is deliberately narrow and fails closed. A ladder is anchored at
 * the entry that introduces its verification method, in the two shapes that
 * entry can take: the ladder-anchored genesis, where the entry authorizes
 * exactly one update key and that key signed it (rung 0 revealed outright);
 * and the bind another signer publishes, where rung 0 arrives as the one hash
 * the entry newly commits, revealed by whichever later entry authorizes its
 * pre-image. Anything else leaves the ladder unattributed, and an
 * unattributed ladder never satisfies shape 3.
 *
 * Which of the two an entry is takes one question first: whose the key it
 * reveals already is. An entry authorizing exactly one self-signing key is
 * the genesis shape only when no ladder already holds that key and the entry
 * publishes no enrolled client. A ladder-branch bind is the counterexample --
 * the ACTING credential's rung reveals itself in the very entry that
 * introduces another credential's ladder VM and commits its rung-0 hash -- so
 * the newcomer anchors on that commitment and the acting ladder climbs onto
 * the rung it just revealed. Reading it the other way would anchor the
 * newcomer on a key it does not hold and hand the acting ladder a shot at a
 * version the newcomer's bind minted. The remembered recovery spend's
 * add-and-retire entry is the enrolled-client counterexample: it introduces
 * the replacement code's ladder VM while the one key it authorizes is the new
 * CLIENT's update key.
 *
 * An anchored ladder then CLIMBS with the log, by the last-position rule of
 * `decisions/0007-ladder-reveal-hash-order.md` read forward. An entry that
 * authorizes exactly one new update key and was signed by that key is a
 * prerotation reveal; when the key's hash was committed LAST among some
 * earlier entry's additions, and that earlier entry itself authorized exactly
 * one key and was signed by it, the committer was committing for itself, so
 * the revealed key is the next rung of the ladder that earlier key belongs
 * to. The step is taken only while the ladder's own VM still stands in the
 * revealing entry's document. Without the climb a self-enrollment would end
 * the attribution outright -- it retires the spent rung, so the ladder would
 * be frozen at a key the account no longer authorizes -- and a passkey
 * account, which self-enrolls by construction, could never satisfy shape 3.
 *
 * Two states stay out of reach on purpose, and both refuse rather than guess.
 * An entry introducing more than one ladder VM names no rung for any of them.
 * And a hash committed anywhere but last is never climbed: an enrollment
 * approval reuses its rung, so its commit entry authorizes no key at all and
 * the client update key its add entry authorizes sits in the commit's first
 * position rather than its last. Under-attributing costs a refused append,
 * which the ceremony surfaces and a retry cannot mend; over-attributing would
 * hand a ladder a shot minted by an enrolled client's own entry, which is the
 * class the license exists to exclude.
 *
 * The parameter carry-forward here is the did:webvh log format's own rule (an
 * entry that omits `updateKeys` or `nextKeyHashes` keeps the previous entry's)
 * read at layer 0, where the `webvh` layer's reader cannot be imported.
 */
import { deriveNextKeyHash } from '@interop/did-method-webvh'
import type { DIDLog, DIDLogEntry } from '@interop/did-method-webvh'
import { vmFragmentOf } from '@interop/vh-resource-log'
import {
  ladderVmMethods,
  resolvedRelationMethods,
  type AccountDocument
} from './document.js'

/**
 * The rung keys attributed to each standing ladder VM, keyed by the ladder
 * VM's own `publicKeyMultibase`. A ladder the walk could not attribute
 * carries no entry at all, which is what makes an unattributed ladder refuse.
 */
export type LadderRungKeys = Map<string, Set<string>>

/**
 * The update-key multibases that signed one log entry: the fragment of each
 * proof's `did:key:<multibase>#<multibase>` verification method.
 *
 * @param entry {DIDLogEntry | undefined}
 * @returns {Set<string>}
 */
export function entrySignerKeysOf(entry: DIDLogEntry | undefined): Set<string> {
  const keys = new Set<string>()
  for (const proof of entry?.proof ?? []) {
    const id = proof.verificationMethod
    const keyMultibase = id === undefined ? undefined : vmFragmentOf(id)
    if (keyMultibase !== undefined) {
      keys.add(keyMultibase)
    }
  }
  return keys
}

/**
 * The ladder VMs' key multibases in one entry's document.
 *
 * @param doc {AccountDocument | undefined}
 * @returns {Set<string>}
 */
function ladderKeysOf(doc: AccountDocument | undefined): Set<string> {
  const keys = new Set<string>()
  if (!doc) {
    return keys
  }
  for (const method of ladderVmMethods({ doc })) {
    if (typeof method.publicKeyMultibase === 'string') {
      keys.add(method.publicKeyMultibase)
    }
  }
  return keys
}

/**
 * The enrolled clients' signing-key multibases in one entry's document: the
 * `capabilityInvocation` methods, which is what an enrolled client publishes
 * and a ladder VM deliberately does not. Only the SET matters here -- an
 * entry that grows it published a client, and the update key such an entry
 * authorizes is that client's rather than any ladder's rung.
 *
 * @param doc {AccountDocument | undefined}
 * @returns {Set<string>}
 */
function enrolledClientKeysOf(doc: AccountDocument | undefined): Set<string> {
  const keys = new Set<string>()
  if (!doc) {
    return keys
  }
  for (const method of resolvedRelationMethods({
    doc,
    relation: 'capabilityInvocation'
  })) {
    if (typeof method.publicKeyMultibase === 'string') {
      keys.add(method.publicKeyMultibase)
    }
  }
  return keys
}

/**
 * The ladder a key is already a rung of, or `undefined` when no ladder holds
 * it. Asked of the revealed key before the anchoring branch runs, since a key
 * another ladder owns can anchor nothing.
 *
 * @param options {object}
 * @param options.rungsByLadder {LadderRungKeys}
 * @param options.key {string}
 * @returns {string | undefined}
 */
function ownerOfRung({
  rungsByLadder,
  key
}: {
  rungsByLadder: LadderRungKeys
  key: string
}): string | undefined {
  for (const [ladderKey, rungs] of rungsByLadder) {
    if (rungs.has(key)) {
      return ladderKey
    }
  }
  return undefined
}

/**
 * Members of `next` that `previous` does not carry, in order.
 *
 * @param options {object}
 * @param options.next {Iterable<string>}
 * @param options.previous {Set<string>}
 * @returns {string[]}
 */
function addedMembers({
  next,
  previous
}: {
  next: Iterable<string>
  previous: Set<string>
}): string[] {
  const added: string[] = []
  for (const member of next) {
    if (!previous.has(member) && !added.includes(member)) {
      added.push(member)
    }
  }
  return added
}

/**
 * Attributes each standing ladder VM's rung keys, one snapshot per log entry:
 * the returned array is indexed by entry position, and each snapshot names
 * what the log attributes as of that version and no later one. A ladder is
 * anchored at the entry introducing its VM and climbs from there by the
 * last-position rule (the module header states both).
 *
 * A snapshot names a ladder's rungs that the version still authorizes in
 * `updateKeys`, plus any rung that signed the version's own entry -- the one
 * question the ceremony-tail license asks of this map, so a rung retired by
 * the very entry it signed still answers it. A ladder left with no such rung
 * is absent from that snapshot rather than present and empty, as is a ladder
 * the walk refuses, so a caller cannot mistake "no rung attributed" for "this
 * key signed nothing".
 *
 * @param log {DIDLog}   a resolved, caller-verified account log
 * @returns {Promise<LadderRungKeys[]>}   one snapshot per entry, in log order
 */
export async function attributeLadderRungsPerVersion(
  log: DIDLog
): Promise<LadderRungKeys[]> {
  const snapshots: LadderRungKeys[] = []
  const rungsByLadder: LadderRungKeys = new Map()
  // A rung-0 hash a bind entry committed, awaiting the entry that authorizes
  // its pre-image. One owner per hash: a second claimant retires the claim,
  // since neither ladder can then be told from the other.
  const claims = new Map<string, string | null>()
  // Ladder VMs the walk refused, so a later snapshot cannot resurrect one.
  const refused = new Set<string>()
  // A hash an entry committed LAST among its additions, mapped to the ladder
  // whose rung both authorized and signed that entry: the pre-image, when a
  // later entry reveals it, is that ladder's next rung. Spent on sight.
  const climbs = new Map<string, string>()
  let previousLadderKeys = new Set<string>()
  let previousClientKeys = new Set<string>()
  let previousUpdateKeys = new Set<string>()
  let previousNextKeyHashes = new Set<string>()
  let updateKeys: string[] = []
  let nextKeyHashes: string[] = []
  for (const entry of log) {
    if (entry.parameters?.updateKeys) {
      updateKeys = entry.parameters.updateKeys
    }
    if (entry.parameters?.nextKeyHashes) {
      nextKeyHashes = entry.parameters.nextKeyHashes
    }
    const doc = entry.state as AccountDocument | undefined
    const ladderKeys = ladderKeysOf(doc)
    const introduced = addedMembers({
      next: ladderKeys,
      previous: previousLadderKeys
    })
    const addedKeys = addedMembers({
      next: updateKeys,
      previous: previousUpdateKeys
    })
    const addedHashes = addedMembers({
      next: nextKeyHashes,
      previous: previousNextKeyHashes
    })
    const signers = entrySignerKeysOf(entry)

    // A committed rung-0 hash whose pre-image this entry authorizes: the bind
    // shape's second half. The claim is spent whether or not it names a
    // ladder, so a retired claim can never be picked up later.
    for (const key of addedKeys) {
      const hash = await deriveNextKeyHash(key)
      if (!claims.has(hash)) {
        continue
      }
      const owner = claims.get(hash)
      claims.delete(hash)
      if (owner !== null && owner !== undefined && !refused.has(owner)) {
        rungsByLadder.set(
          owner,
          (rungsByLadder.get(owner) ?? new Set()).add(key)
        )
      }
    }

    // The CLIMB: this entry authorizes exactly one new key and that key
    // signed it (a prerotation reveal), and an earlier entry committed the
    // key's hash in last position under a rung of a known ladder. The
    // candidate is spent whether or not the guard below admits it, so a
    // released hash can never be climbed later.
    const revealedRung = addedKeys.length === 1 ? addedKeys[0] : undefined
    if (revealedRung !== undefined && signers.has(revealedRung)) {
      const hash = await deriveNextKeyHash(revealedRung)
      const owner = climbs.get(hash)
      climbs.delete(hash)
      // The ladder's own VM must still stand in THIS entry's document. That
      // is what keeps a recovery spend out: the spent credential's
      // reveal-and-commit entry commits the REPLACEMENT credential's hash
      // last, and the entry revealing that hash is the one that strikes the
      // spent credential's ladder VM.
      if (
        owner !== undefined &&
        !refused.has(owner) &&
        ladderKeys.has(owner) &&
        rungsByLadder.has(owner)
      ) {
        rungsByLadder.set(
          owner,
          (rungsByLadder.get(owner) ?? new Set()).add(revealedRung)
        )
      }
    }

    // WHOSE the revealed key already is, resolved BEFORE the anchoring
    // branch: the claim resolution and the climb above have just credited it
    // where it belongs, so a hit here names a ladder that already holds it.
    // A ladder-branch bind entry is the shape this orders: the ACTING
    // credential's rung reveals itself in the very entry that introduces
    // another credential's ladder VM, and reading that rung as the newcomer's
    // rung 0 would anchor the newcomer on a key it does not hold AND credit
    // the acting ladder with the newcomer's rung-0 commitment below.
    const revealedOwner =
      revealedRung === undefined
        ? undefined
        : ownerOfRung({ rungsByLadder, key: revealedRung })
    // Whether this entry also published an enrolled client. The one key such
    // an entry authorizes is that client's update key (the remembered
    // recovery spend's add-and-retire entry, which introduces the replacement
    // code's ladder VM beside the new client), so it anchors no ladder.
    const introducedClients = addedMembers({
      next: enrolledClientKeysOf(doc),
      previous: previousClientKeys
    })

    // The introduction, the one place a ladder is anchored. A VM introduced
    // beside another names no rung for either.
    let claimedHere: string | undefined
    if (introduced.length > 1) {
      for (const ladderKey of introduced) {
        refused.add(ladderKey)
        rungsByLadder.delete(ladderKey)
      }
    } else if (introduced.length === 1) {
      const ladderKey = introduced[0]!
      refused.delete(ladderKey)
      rungsByLadder.delete(ladderKey)
      const revealed = addedKeys[0]
      // Rung 0 revealed outright, the ladder-anchored genesis shape: one key
      // authorized, signing its own entry, owned by no other ladder and not a
      // client's.
      const revealsOwnRungZero =
        addedKeys.length === 1 &&
        revealed !== undefined &&
        signers.has(revealed) &&
        revealedOwner === undefined &&
        introducedClients.length === 0
      // The commitment arm: the bind another signer publishes, where rung 0
      // arrives as a commitment and is picked up when a later entry reveals
      // its pre-image. It covers the bind an enrolled client signs (which
      // authorizes no key of its own) and the ladder-branch bind another
      // credential's rung signs (which authorizes that rung and nothing
      // else), both of which commit exactly the newcomer's rung-0 hash.
      const commitsRungZero =
        addedHashes.length === 1 &&
        (addedKeys.length === 0 || revealedOwner !== undefined)
      if (revealsOwnRungZero) {
        rungsByLadder.set(ladderKey, new Set([revealed!]))
      } else if (commitsRungZero) {
        const hash = addedHashes[0]!
        // A hash two binds commit is nobody's: retire the claim outright.
        claims.set(hash, claims.has(hash) ? null : ladderKey)
        claimedHere = hash
      } else {
        refused.add(ladderKey)
      }
    }

    // What this entry committed for ITSELF: the last of its newly committed
    // hashes, recorded against the ladder whose rung authorized and signed
    // the entry. Recorded after the introduction branch, so a ladder-anchored
    // genesis stages its own rung 1. An entry that reuses its rung authorizes
    // no key of its own and so records nothing, and a hash the introduction
    // above claimed for the ladder this entry BINDS is that ladder's rung 0
    // rather than the signer's next rung.
    const committedLast = addedHashes[addedHashes.length - 1]
    const signingLadder =
      revealedRung === undefined
        ? undefined
        : ownerOfRung({ rungsByLadder, key: revealedRung })
    if (
      revealedRung !== undefined &&
      signers.has(revealedRung) &&
      signingLadder !== undefined &&
      committedLast !== undefined &&
      committedLast !== claimedHere
    ) {
      climbs.set(committedLast, signingLadder)
    }

    const authorized = new Set(updateKeys)
    const snapshot: LadderRungKeys = new Map()
    for (const [ladderKey, rungs] of rungsByLadder) {
      const standing = [...rungs].filter(
        rung => authorized.has(rung) || signers.has(rung)
      )
      if (standing.length > 0) {
        snapshot.set(ladderKey, new Set(standing))
      }
    }
    snapshots.push(snapshot)
    previousLadderKeys = ladderKeys
    previousClientKeys = enrolledClientKeysOf(doc)
    previousUpdateKeys = new Set(updateKeys)
    previousNextKeyHashes = new Set(nextKeyHashes)
  }
  return snapshots
}
