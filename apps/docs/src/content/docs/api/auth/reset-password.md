---
title: "`<route>POST</route>` Request a password reset"
description: "`<route>POST /api/v2/auth/reset-password</route>`"
order: 4
---

:::aside

::route-example{def="ResetPasswordRouteV2" extra="BadJson,BadBody"}

:::

::route-meta{def="ResetPasswordRouteV2" rateLimit="Password reset buckets. Burst `5`, refill window `1500000` ms per IP, plus burst `2`, refill window `3600000` ms per email."}

Starts a password reset for a team that can still read its email inbox. When the request is accepted, rCTF emails a reset link carrying a `TokenKind.PasswordReset{:ts}` token, which is submitted with the new password to [confirm a password reset](/api/auth/reset-password-confirm/). This route is available in V2.

A reset requires an email provider. With `<red>email</red>` unconfigured the route returns `<response>404 badEndpoint</response>` before anything else, leaving [`<red>rctf</red>` `user set-password`](/admin/cli#rctf-user-set-password) as the only way to reset the password of a team that can no longer log in.

The reset limits apply even when captcha is enabled. Both buckets are consumed before the account lookup, so rate-limit behavior cannot reveal whether an address is registered. Exceeding either limit returns `<response>429 badRateLimit</response>` with the wait in `data.timeLeft`.

`captchaCode` is checked against the `recover{:ts}` captcha action. No action was added for resets, so a deployment that protects recovery with captcha protects this route too, and a failed check returns `<response>403 badCaptcha</response>`.

::request-body{def="ResetPasswordRouteV2" title="Request body"}

An address that does not parse returns `<response>400 badEmail</response>`. Valid addresses are lowercased and trimmed before the buckets and the lookup use them.

#### Response

A request that passes validation returns `<response>200 goodVerifySent</response>`. The email links to `<dim><origin></dim>/reset-password?token=<dim><reset-token></dim>`, not the `/verify` page the other messages use.

An address nobody holds gets the same response with no message sent, and a failed send is logged rather than surfaced, so nothing discloses whether an account exists. As with [account recovery](/api/auth/recover/), mailbox access is equivalent to account access.
