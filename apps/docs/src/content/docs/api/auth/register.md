---
title: "`<route>POST</route>` Register a team"
description: "`<route>POST /api/[v2,v1]/auth/register</route>`"
order: 1
---

:::aside

::::tabs{sync="register-version"}

:::tab[V2]

::::route-example{def="RegisterRouteV2" pick="name,email,captchaCode" extra="BadJson,BadBody"}

```json body
{
  "email": "team@example.com",
  "name": "otter-sec"
}
```

::::

:::

:::tab[V1]

::::route-example{def="RegisterRoute" pick="name,email,recaptchaCode" extra="BadJson,BadBody"}

```json body
{
  "email": "team@example.com",
  "name": "otter-sec"
}
```

::::

:::

::::

:::

::route-meta{def="RegisterRouteV2" rateLimit="Registration buckets. Burst `20`, refill window `600000` ms per IP when a verification email would be sent or a password is supplied, plus burst `2`, refill window `3600000` ms per email when a verification email would be sent, plus burst `2`, refill window `3600000` ms per team name when a password is supplied."}

Creates a team account. Most deployments ask the team to prove ownership of an email address before the account becomes usable, so a successful request often sends a verification email instead of returning tokens immediately.

For new clients, prefer the V2 route. The V1 route remains available for clients that already use the original registration fields.

The rate limits apply even when captcha is enabled. A bucket is consumed only on a path that costs something. The per-IP bucket is consumed when rCTF would send a verification email or when a password is supplied, the per-email bucket when rCTF would send a verification email, and the per-name bucket when a password is supplied, before the password is hashed. A CTFtime registration that sends no email and carries no password consumes none of them. Exceeding any bucket returns `<response>429 badRateLimit</response>` with the wait in `data.timeLeft`.

::::tabs{sync="register-version"}

:::tab[V2]

`<route>POST /api/v2/auth/register</route>` uses `captchaCode` for captcha protected registration. If the team can be created immediately, the response includes both an auth token for user routes and a team token for recovery or team scoped auth flows.

V2 also accepts an optional `password`. `email` is required unless the body carries a `ctftimeToken`, because a CTFtime handoff carries no address. Omitting both returns `<response>400 badEmail</response>`.

::request-body{def="RegisterRouteV2" title="Request body"}

#### Response

If email verification is enabled, the route returns `<response>200 goodVerifySent</response>`. The team is not created yet. Submit the verification token to [verify a token](/api/auth/verify/) to finish registration.

If no verification step is needed, the route creates the team immediately and returns `<response>200 goodRegisterV2</response>` with both tokens.

::response-body{def="RegisterRouteV2" response="goodRegisterV2" title="Response fields"}

:::

:::tab[V1]

`<route>POST /api/v1/auth/register</route>` uses `recaptchaCode` for captcha protected registration. If the team can be created immediately, the response includes an auth token.

::request-body{def="RegisterRoute" title="Request body"}

#### Response

If email verification is enabled, the route returns `<response>200 goodVerifySent</response>`. The team is not created yet. Submit the verification token to [verify a token](/api/auth/verify/) to finish registration.

If no verification step is needed, the route creates the team immediately and returns `<response>200 goodRegister</response>` with an `authToken`.

::response-body{def="RegisterRoute" response="goodRegister" title="Response fields"}

:::

::::

For email registration, rCTF checks division ACLs before sending the verification message and chooses the default division allowed for that address, whether or not the request carries a password. The client does not send a division. CTFtime registration bypasses email ACLs.

A pending verification holds the name and the address it was created with until it expires after `<red>loginTimeout</red>`. Registering that name from a different address returns `<response>409 badKnownName</response>`, and registering the same address again resends the original link instead of replacing it, so another submission cannot invalidate a link that is already in flight.

## Registering with a password

Supplying a V2 `password` sets the account password. It does not change how the address is proven:

* Where an email provider is configured, the route returns `<response>200 goodVerifySent</response>` as it does without a password. The team is not created yet, and the password hash is held on the pending verification row until the emailed link is opened at [verify a token](/api/auth/verify/), which creates the team with that hash.
* Where no email provider is configured there is nothing to verify against, so the route creates the team immediately, returns `<response>200 goodRegisterV2</response>` for immediate login, and stores the submitted `email` as-is.
* Password must be 8–128 characters (untrimmed, unnormalized, no composition rules). Invalid lengths return `<response>400 badPassword</response>`.
