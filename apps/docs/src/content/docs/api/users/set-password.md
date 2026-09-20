---
title: "`<route>PUT</route>` Set password auth"
description: "`<route>PUT /api/v2/users/me/auth/password</route>`"
order: 7
---

:::aside

::::route-example{def="SetPasswordRouteV2" extra="BadJson,BadBody"}

```json body
{
  "password": "a-long-team-password",
  "currentPassword": "the-previous-password"
}
```

::::

:::

::route-meta{def="SetPasswordRouteV2" rateLimit="Password change bucket. Burst `3`, refill window `180000` ms per user. Consumed before anything else in the request."}

This route sets or replaces a team password. It is available in V2. Password must be 8-128 characters, otherwise it returns `<response>400 badPassword</response>`.

If the account already has a password (`hasPassword`), `currentPassword` is required (`<response>401 badCredentials</response>` if invalid); otherwise, it is ignored.

::request-body{def="SetPasswordRouteV2" title="Request body"}

#### Response

A successful request returns `<response>200 goodPasswordSet</response>` and raises the [token epoch](/api/auth#token-revocation), invalidating all prior tokens. Response carries a replacement `authToken`.

::response-body{def="SetPasswordRouteV2" response="goodPasswordSet" title="Response fields"}
