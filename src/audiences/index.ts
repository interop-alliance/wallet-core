/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The `@interop/wallet-core/audiences` subpath: the audience collection's
 * provisioning attributes and the member grant helper. The agent's own grants
 * do not go through it. They arrive through a connection request.
 */
export {
  AUDIENCE_PROVISION_ATTRIBUTES,
  delegateAudienceGrant
} from './audienceGrant.js'
