---
title: "`<route>DELETE</route>` Remove password auth"
description: "`<route>DELETE /api/v2/users/me/auth/password</route>`"
order: 8
---

:::aside

::::route-example{def="DeletePasswordRouteV2" extra="BadJson,BadBody"}

```json body
{
  "currentPassword": "the-password-being-removed"
}
```

::::

:::

::route-meta{def="DeletePasswordRouteV2" rateLimit="Password change bucket. Burst `3`, refill window `180000` ms per user. Shared with setting a password, and consumed before anything else in the request."}

This route removes password auth from the authenticated team. It is available in V2.

Unlike most `DELETE{:http}` routes, this one takes a JSON body. `currentPassword` is always required, and a wrong value returns `<response>401 badCredentials</response>`.

If removing password auth would leave the team without an email address, a CTFtime link, and a password, the route returns `<response>409 badZeroAuth</response>`.

::request-body{def="DeletePasswordRouteV2" title="Request body"}

#### Response

A successful request returns `<response>200 goodPasswordRemoved</response>`.

It returns a replacement `authToken` too, because removing a password raises the [token epoch](/api/auth#token-revocation), invalidating prior tokens.

::response-body{def="DeletePasswordRouteV2" response="goodPasswordRemoved" title="Response fields"}
