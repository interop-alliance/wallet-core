/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * TEST FIXTURES ONLY, published as the `./testing` subpath so this package
 * and its consumers assert the recorded-grant wire shape against one copy:
 * the delegated zcap `revokeRecordedGrant` reads (the chain in the proof, a
 * parent delegation embedded as its last link), and the account signer check
 * the refusal reading resolves it against.
 *
 * Never import this subpath from production code. Each consumer keeps a lint
 * restriction excluding `@interop/wallet-core/testing` from its non-test
 * globs.
 */
import type { IZcap } from '@interop/data-integrity-core'
import type { AccountSignerCheck } from './clientAnnex/grantRevocation.js'

/**
 * The account the signer-check fixture describes: one enrolled client and
 * one standing credential's ladder VM under `capabilityDelegation`, the
 * document pointing at one annex generation, and an older generation the
 * document no longer names.
 */
export const SIGNER_FIXTURE = {
  accountDid: 'did:webvh:scid:was.example:x',
  enrolledKey: 'z6MkEnrolledClient',
  ladderVm: 'z6MkLadderVm',
  annexDid: 'did:webvh:scid:was.example:space:x:gen-AAAAAAAAAAAAAAAA',
  oldAnnexDid: 'did:webvh:scid:was.example:space:x:gen-BBBBBBBBBBBBBBBB',
  root: 'urn:zcap:root:https%3A%2F%2Fwas.example%2Fspace%2Fx',
  appDid: 'did:key:z6MkAppSubject'
} as const

/**
 * The enrolled client's verification method id, the ladder VM's, and a key
 * the document never listed.
 */
export const ENROLLED_SIGNER = `${SIGNER_FIXTURE.accountDid}#${SIGNER_FIXTURE.enrolledKey}`
export const LADDER_SIGNER = `${SIGNER_FIXTURE.accountDid}#${SIGNER_FIXTURE.ladderVm}`
export const GONE_SIGNER = `${SIGNER_FIXTURE.accountDid}#z6MkGone`

/**
 * A fresh {@link AccountSignerCheck} over {@link SIGNER_FIXTURE}: the
 * enrolled key as the one current signing key, both VMs published under
 * `capabilityDelegation`, and the pointer naming the current annex DID.
 *
 * @returns {AccountSignerCheck}
 */
export function accountSignerCheck(): AccountSignerCheck {
  const { accountDid, enrolledKey, ladderVm, annexDid } = SIGNER_FIXTURE
  return {
    accountDid,
    currentSigningKeys: new Set([enrolledKey]),
    doc: {
      verificationMethod: [
        { id: ENROLLED_SIGNER, publicKeyMultibase: enrolledKey },
        { id: LADDER_SIGNER, publicKeyMultibase: ladderVm }
      ],
      capabilityDelegation: [ENROLLED_SIGNER, LADDER_SIGNER]
    },
    clientAnnexDid: annexDid
  }
}

/**
 * A recorded grant as the delegation suite writes it: a delegated zcap
 * whose chain sits in the proof, with the parent delegation embedded as the
 * chain's last link when there is one (a transient session's grant under
 * its generation delegation).
 *
 * @param [options] {object}
 * @param [options.id] {string}
 * @param [options.controller] {string}   the grantee, the app's did:key
 * @param [options.invocationTarget] {string}
 * @param [options.expires] {string}   an ISO instant; `undefined` leaves it
 *   absent
 * @param [options.signerKeyId] {string}   the delegation proof's
 *   `verificationMethod`
 * @param [options.parent] {object}   the embedded parent delegation
 * @param [options.parent.controller] {string}
 * @param [options.parent.signerKeyId] {string}   absent for a parent that
 *   recorded no proof key
 * @returns {IZcap}
 */
export function recordedGrant({
  id = 'urn:zcap:one',
  controller = SIGNER_FIXTURE.appDid,
  invocationTarget = 'https://was.example/space/x/private-credentials',
  expires = '2026-09-11T00:00:00Z',
  signerKeyId,
  parent
}: {
  id?: string
  controller?: string
  invocationTarget?: string
  expires?: string
  signerKeyId?: string
  parent?: { controller: string; signerKeyId?: string }
} = {}): IZcap {
  const { root } = SIGNER_FIXTURE
  const embedded = parent && {
    id: 'urn:zcap:delegated:generation',
    controller: parent.controller,
    parentCapability: root,
    ...(parent.signerKeyId
      ? { proof: { verificationMethod: parent.signerKeyId } }
      : {})
  }
  return {
    '@context': ['https://w3id.org/zcap/v1'],
    id,
    parentCapability: embedded ? embedded.id : root,
    controller,
    invocationTarget,
    allowedAction: ['GET', 'HEAD'],
    expires,
    proof: {
      capabilityChain: embedded ? [root, embedded] : [root],
      ...(signerKeyId ? { verificationMethod: signerKeyId } : {})
    }
  } as unknown as IZcap
}
