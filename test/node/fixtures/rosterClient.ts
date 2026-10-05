/**
 * The wallet-client fixture for user key roster tests: a client with BOTH
 * halves a real enrolled client holds -- an Ed25519 signing key (the
 * resource-log entry signer, whose public multibase the did:webvh document
 * backs as a verification method) and an X25519 key-agreement key (the roster
 * recipient)
 * -- plus the document builder that enrolls a set of such clients. Shared by
 * every suite that drives roster reads/rotations, so the "what the account
 * document backs" shape is stated once.
 */
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key'
import { X25519KeyAgreementKey2020 } from '@interop/x25519-key-agreement-key'
import type { IKeyAgreementKey } from '@interop/data-integrity-core'
import { rosterRecipientKid } from '../../../src/keys/rosterRecipientKid.js'
import { userKeyRosterLogSigner } from '../../../src/keys/userKeyRoster.js'
import {
  MULTIKEY_COMMITMENT_VM_TYPE,
  MULTIKEY_VM_TYPE
} from '../../../src/webvh/didWebvh.js'
import type { KeyAgreementDocument } from '../../../src/resourceLog/document.js'
import type { ResourceLogSigner } from '@interop/vh-resource-log'

/**
 * The account DID every roster fixture document resolves to: the controller
 * of a credential-class method, and the id prefix of every method.
 */
export const ROSTER_TEST_DID = 'did:webvh:QmScid:example.com:space:abc:id'

/**
 * A test wallet client: its identity key-agreement key (the roster recipient,
 * id'd in the self-describing did:key form the wallet's client KAK uses), its
 * Ed25519 signing key's public multibase (the document verification method its
 * log entry proofs resolve against), and the {@link ResourceLogSigner} its
 * roster log appends sign with.
 */
export interface RosterTestClient {
  kak: IKeyAgreementKey
  publicKeyMultibase: string
  signingKeyMultibase: string
  logSigner: ResourceLogSigner
}

/**
 * Mints a fresh {@link RosterTestClient}.
 *
 * @returns {Promise<RosterTestClient>}
 */
export async function makeRosterClient(): Promise<RosterTestClient> {
  const signingKey = await Ed25519VerificationKey.generate()
  const signingKeyMultibase = signingKey.publicKeyMultibase as string
  const signingDid = `did:key:${signingKeyMultibase}`
  signingKey.controller = signingDid
  signingKey.id = `${signingDid}#${signingKeyMultibase}`

  // The canonical X25519 twin of the signing key, as a real client's key set
  // derives it -- what the enrollment ceremony's canonicality check requires.
  const kak = await X25519KeyAgreementKey2020.fromEd25519(signingKey)
  const publicKeyMultibase = kak.publicKeyMultibase as string
  const kakDid = `did:key:${publicKeyMultibase}`
  kak.controller = kakDid
  kak.id = `${kakDid}#${publicKeyMultibase}`

  const logSigner = userKeyRosterLogSigner({
    keyAgent: {
      id: signingDid,
      handle: 'roster-test',
      getSigner: () => signingKey.signer(),
      getVerificationKeyPair: () => ({
        type: 'Ed25519VerificationKey2020',
        controller: signingDid,
        publicKeyMultibase: signingKeyMultibase
      })
    }
  })

  return {
    kak: kak as IKeyAgreementKey,
    publicKeyMultibase,
    signingKeyMultibase,
    logSigner
  }
}

/**
 * The locally verified did:webvh document for a set of enrolled clients: per
 * client, a signing-key verification method (what epoch-configuration
 * signatures verify against) and a `keyAgreement` verification method (what
 * the roster recipient resolver answers from), both in the
 * `<did:webvh>#<multibase>` id form the enrollment ceremony publishes.
 *
 * @param clients {Array<Pick<RosterTestClient, 'publicKeyMultibase' | 'signingKeyMultibase'>>}
 * @returns {KeyAgreementDocument}
 */
export function rosterDocumentFor(
  clients: Array<
    Pick<RosterTestClient, 'publicKeyMultibase' | 'signingKeyMultibase'>
  >
): KeyAgreementDocument {
  const did = ROSTER_TEST_DID
  return {
    verificationMethod: clients.flatMap(client => [
      {
        id: `${did}#${client.signingKeyMultibase}`,
        publicKeyMultibase: client.signingKeyMultibase
      },
      {
        id: `${did}#${client.publicKeyMultibase}`,
        publicKeyMultibase: client.publicKeyMultibase
      }
    ]),
    keyAgreement: clients.map(client => `${did}#${client.publicKeyMultibase}`)
  }
}

/**
 * A test client whose roster kid is the production one -- the pair a
 * document's controller marker and key-agreement method carry between them
 * ({@link rosterRecipientKid}).
 *
 * @returns {Promise<RosterTestClient>}
 */
export async function makeMarkedRosterClient(): Promise<RosterTestClient> {
  const client = await makeRosterClient()
  ;(client.kak as { id: string }).id = rosterRecipientKid({
    signingKeyMultibase: client.signingKeyMultibase,
    keyAgreementKeyMultibase: client.publicKeyMultibase
  })
  return client
}

/**
 * A document keying enrolled clients (their key-agreement twins carrying the
 * `did:key` controller marker) beside standing credentials (unmarked,
 * account-controlled, verbatim or commitment).
 *
 * @param options {object}
 * @param options.clients {Array<{ publicKeyMultibase: string,
 *   signingKeyMultibase: string }>}
 * @param [options.credentials] {string[]}   verbatim credential keys
 * @param [options.commitments] {string[]}   credential key commitments
 * @returns {KeyAgreementDocument}
 */
export function markedRosterDocumentFor({
  clients,
  credentials = [],
  commitments = []
}: {
  clients: Array<{ publicKeyMultibase: string; signingKeyMultibase: string }>
  credentials?: string[]
  commitments?: string[]
}) {
  const did = ROSTER_TEST_DID
  const methods = [
    ...clients.map(client => ({
      id: `${did}#${client.publicKeyMultibase}`,
      type: MULTIKEY_VM_TYPE,
      controller: `did:key:${client.signingKeyMultibase}`,
      publicKeyMultibase: client.publicKeyMultibase
    })),
    ...credentials.map(key => ({
      id: `${did}#${key}`,
      type: MULTIKEY_VM_TYPE,
      controller: did,
      publicKeyMultibase: key
    })),
    ...commitments.map((commitment, index) => ({
      id: `${did}#commitment-${index}`,
      type: MULTIKEY_COMMITMENT_VM_TYPE,
      controller: did,
      publicKeyCommitment: commitment
    }))
  ]
  return {
    verificationMethod: methods,
    keyAgreement: methods.map(method => method.id)
  }
}
