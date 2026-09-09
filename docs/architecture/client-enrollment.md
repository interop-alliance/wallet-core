<!-- Part of wallet-core's architecture docs. The map, the key hierarchy,
     the ceremony inventory, the permanent wire-level constants, and the
     glossary are in ../../ARCHITECTURE.md; this file holds one topic in full. -->

# The client enrollment ceremony (`enrollment`)

A new client mints its whole key set locally. Only public halves travel, as a
`freewallet-connect:` connect code carried point-to-point, and nothing travels
back over the channel; the account pointer comes from the keyring and the user
key through the roster. The two log entries are a sparse **commit** entry
extending `nextKeyHashes`, then the **add** entry publishing the verification
methods and update key. Where the escrow sits relative to them is decided by the
signer kind (`decisions/0018`). A CLIENT signer keeps the push-not-pull order,
decryption material before authorization: the user key is wrapped to the new
client's KAK in the roster FIRST, so no authorized-but-blind window exists. A
LADDER signer runs commit, add, then escrow, because a ladder-signed roster
append is licensed only at an inventory-changing version its own ladder signed,
which the add entry mints. The one-request window that leaves is the ladder
branch's stated cost: a client the add entry published holds `assertionMethod`
and its own update key while holding no wrap. It is bounded by a re-run with the
same connect code, by the escrow-direction convergence of any later
ladder-branch ceremony, and by the row it leaves in the connected-wallets
listing. A tear between the log entries surfaces as `EnrollmentPendingError`,
and re-running with the same code converges. A code whose key-agreement key is
not the canonical X25519 twin of its signing key is refused
(`assertCanonicalEnrollmentKeys`, run both by the parse, so the refusal reaches
the approver's consent screen, and by `approveEnrollment`, the seam every
approval path funnels through), which is what keeps the controller marker
honest. Persisting the enrollee's key set under the app's unlock layer is the
caller's job: `completeEnrollmentCore` hands back the user key and the epoch to
pin, and stops. `onboardingResponse.ts` adds only a transport around the same
code: the `{ walletOnboarding: { v, code, label? } }` envelope an enrollee POSTs
back to an exchange whose request carried a `WalletOnboardingQuery`. The code
rides verbatim. The optional label is attacker-adjacent text rendered on the
approver's consent screen, so it is control-character-stripped, trimmed, and
refused rather than truncated over its 64-character cap; its durable home is
`key-map/client-labels.json`, which the approver writes. The inviter's side of
that exchange is generic transport in `request/ephemeralExchange.ts`:
`createEphemeralExchange` POSTs the query to the ephemeral-exchange route and
hands back the exchange URL plus the interaction URL the QR code carries, and
`pollEphemeralExchange` polls until the enrollee's envelope lands.
`enrollment/onboardingInvite.ts` keeps the one policy constant,
`ONBOARDING_INVITE_TTL_MS`, how long a wallet offers the invite for inside the
server's ten-minute exchange TTL. The routes are unauthenticated by design, a
capability-URL model where the exchange URL is the secret travelling point to
point through the QR code, so nothing there signs a request. A `404` is the
expired invite and raises the stable-named `EphemeralExchangeGoneError`; every
other failure is transient and retried. The poll takes an optional `timeoutMs`
deadline that aborts the in-flight request and raises
`EphemeralExchangeTimeoutError`, a separate class because the exchange may still
be approvable and only the requester stopped waiting.
