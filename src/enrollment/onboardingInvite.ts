/*!
 * Copyright (c) 2026 Interop Alliance. All rights reserved.
 */
/**
 * The wallet-onboarding invite's one policy constant. The invite's transport
 * is the generic ephemeral-exchange requester in
 * `@interop/wallet-core/request` (`createEphemeralExchange` /
 * `pollEphemeralExchange`); what stays here is how long a wallet offers the
 * invite for.
 */

/**
 * How long an invite is offered for, comfortably inside the server's
 * ten-minute exchange TTL so the countdown expires before the server does.
 */
export const ONBOARDING_INVITE_TTL_MS = 5 * 60 * 1000
