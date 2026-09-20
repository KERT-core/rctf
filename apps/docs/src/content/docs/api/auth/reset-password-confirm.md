---
title: "`<route>POST</route>` Confirm a password reset"
description: "`<route>POST /api/v2/auth/reset-password/confirm</route>`"
order: 5
---

:::aside

::::route-example{def="ConfirmPasswordResetRouteV2" extra="BadJson,BadBody"}

```json body
{
  "password": "a-long-team-password"
}
```

::::

:::

::route-meta{def="ConfirmPasswordResetRouteV2" rateLimit="Password reset confirm bucket. Burst `10`, refill window `100000` ms per IP. Consumed before the token is parsed."}

Finishes the reset started by [request a password reset](/api/auth/reset-password/). The request carries the token from the email and the new password, and sends no auth header, because the team cannot log in yet. This route is available in V2.

Like the request step, it needs an email provider and returns `<response>404 badEndpoint</response>` when `<red>email</red>` is unconfigured. Removing the provider therefore strands tokens that were already sent; they expire on their own within `<red>loginTimeout</red>`.

The per-IP bucket is consumed before the token is parsed. It meters the argon2 work each attempt costs rather than guarding against guessing, which the unguessable token already covers. Exceeding it returns `<response>429 badRateLimit</response>` with the wait in `data.timeLeft`.

::request-body{def="ConfirmPasswordResetRouteV2" title="Request body"}

`resetToken` must decrypt as a `TokenKind.PasswordReset{:ts}` token; anything else, including an expired or [revoked](/api/auth#token-revocation) one, returns `<response>401 badTokenVerification</response>`. A token whose account has since been deleted returns `<response>404 badUnknownUser</response>`. A `password` outside 8-128 characters returns `<response>400 badPassword</response>`.

#### Response

A successful reset returns `<response>200 goodPasswordSet</response>`.

::response-body{def="ConfirmPasswordResetRouteV2" response="goodPasswordSet" title="Response fields"}

Completing a reset raises the [token epoch](/api/auth#token-revocation), so every auth and team token the account was issued earlier stops working and the response hands back a replacement `authToken`. That epoch is also what makes the reset token single use: no marker is stored, and the token that performed the reset was minted before the epoch it set, so a second submission is rejected as revoked. Any reset token minted before some other password change is dead for the same reason, and an unused one expires after `<red>loginTimeout</red>`. An account with no password at all can set its first one here, since the authority behind the token is the mailbox, which recovery already treats as full account access.
