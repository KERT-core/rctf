---
title: "`<route>POST</route>` Log in"
description: "`<route>POST /api/[v2,v1]/auth/login</route>`"
order: 5
---

:::aside

::::tabs{sync="login-version"}

:::tab[V2]

::::route-example{def="LoginRouteV2" extra="BadJson,BadBody"}

```json body
{
  "name": "otter-sec",
  "password": "a-long-team-password"
}
```

::::

:::

:::tab[V1]

::route-example{def="LoginRoute" pick="teamToken" extra="BadJson,BadBody"}

:::

::::

:::

::route-meta{def="LoginRouteV2" rateLimit="Login buckets. Burst `10`, refill window `100000` ms per IP, plus burst `5`, refill window `150000` ms per identifier. Both are consumed before the password is checked."}

Both login routes return a `TokenKind.Auth{:ts}` token for user routes. V2 accepts a password with a team name or email. V1 accepts longer-lived credentials (a team or CTFtime handoff token) and remains active because V2 has no replacement for that exchange.

::::tabs{sync="login-version"}

:::tab[V2]

`<route>POST /api/v2/auth/login</route>` authenticates with an identifier and a password.

`identifier` matches against either team name or email address (trimmed, case-insensitive). If a team name conflicts with another account's email, lookup prioritizes the account owning the email address.

::request-body{def="LoginRouteV2" title="Request body"}

#### Response

A successful login returns `<response>200 goodLogin</response>` with a fresh `authToken`.

All failures return `<response>401 badCredentials</response>` and run in constant time (using dummy hash checks when needed) to prevent team enumeration and timing attacks.

::response-body{def="LoginRouteV2" response="goodLogin" title="Response fields"}

:::

:::tab[V1]

`<route>POST /api/v1/auth/login</route>` exchanges a longer lived team credential for an auth token.

::request-body{def="LoginRoute" title="Request body"}

`teamToken` is parsed as `TokenKind.Team{:ts}`. `ctftimeToken` is parsed as `TokenKind.CtftimeAuth{:ts}` and then matched to a team linked to that CTFtime ID.

#### Response

A successful login returns `<response>200 goodLogin</response>` with a fresh `authToken`. Token verification happens before any account data is returned, so expired, malformed, unrecognized, or [revoked](/api/auth#token-revocation) handoff tokens never mint an auth token.

::response-body{def="LoginRoute" response="goodLogin" title="Response fields"}

:::

::::

## Abuse controls on password login

Captcha applies if configured; otherwise, protection relies on per-IP rate limits and a cap of 4 concurrent password verifications to prevent API starvation.

Per-identifier rate limits enforce a soft lockout to prevent multi-IP brute forcing, intentionally accepting the risk of targeted DoS (`<response>429 badRateLimit</response>`). Clients should show `data.timeLeft`.

Because team names are public and no account lockouts or password complexity rules exist, these buckets are the sole defense against online guessing.
