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
import { userKeyRosterLogSigner } from '../../../src/keys/userKeyRoster.js'
import type { KeyAgreementDocument } from '../../../src/resourceLog/document.js'
import type { ResourceLogSigner } from '@interop/vh-resource-log'

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
  const kak = await X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
    keyPair: signingKey
  })
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
  const did = 'did:webvh:QmScid:example.com:space:abc:id'
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
