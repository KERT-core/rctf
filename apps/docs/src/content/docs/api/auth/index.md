---
title: "Authentication"
description: "Registration, verification, recovery, login, and token validation routes."
order: 10
scroll: true
aside: true
---

:::aside

| Route | Endpoint |
| --- | --- |
| [Register a team](/api/auth/register/) | `<route>POST /api/[v2,v1]/auth/register</route>` |
| [Verify a token](/api/auth/verify/) | `<route>POST /api/[v2,v1]/auth/verify</route>` |
| [Recover an account](/api/auth/recover/) | `<route>POST /api/[v2,v1]/auth/recover</route>` |
| [Preview a verification token](/api/auth/verify-info/) | `<route>GET /api/v2/auth/verify-info</route>` |
| [Log in with a password](/api/auth/login/) | `<route>POST /api/v2/auth/login</route>` |
| [Log in with a token](/api/auth/login/) | `<route>POST /api/v1/auth/login</route>` |
| [Test an auth token](/api/auth/test/) | `<route>GET /api/v1/auth/test</route>` |

:::

Authentication in rCTF is based around teams. A team owns the name, email address, score, solves, members, and settings. Browser sessions and API clients act on behalf of a team by sending an auth token in the `Authorization` header.

The API has both V1 and V2 routes. They are available together, and a client may need routes from both versions. V2 routes exist where behavior changed or new response data was added. V1 routes remain current when there is no V2 replacement.

Most authenticated API requests use the `Authorization: Bearer <dim><auth-token></dim>` header.

The other token kinds are used while setting up, recovering, or changing a team account.

| Token kind    | Lifetime             | Used by                                                         |
| ------------- | -------------------- | --------------------------------------------------------------- |
| `Auth`        | No expiry, revocable | `Authorization: Bearer <dim><auth-token></dim>` on user routes. |
| `Team`        | No expiry, revocable | Account recovery, login, and token verification.                |
| `Verify`      | `loginTimeout`       | Email updates and pending registrations. Single use.            |
| `CtftimeAuth` | `loginTimeout`       | CTFtime registration and login handoff.                         |

Tokens are encrypted with AES 256 GCM using `tokenKey`. Rotating `tokenKey` invalidates any auth, team, verify, or CTFtime handoff token issued before the rotation.

Verify tokens also depend on a one time Redis marker. The encrypted token can still decrypt successfully after the marker has been used or expired, but the verification request will not complete.

## Token revocation

Every token carries its mint timestamp. Tokens minted at or before an account's `token_epoch` (Unix timestamp) are rejected.

Setting or removing a password updates the epoch to the current second, ending all active sessions. Therefore, [set password](/api/users/set-password/) and [remove password](/api/users/delete-password/) return a replacement `authToken`.

Limits to note:
* Epoch resolution is 1 second.
* Already-issued [external-auth](/api/external-auth/) codes ignore the epoch and can still be exchanged during their 60-second lifetime.

Only password changes raise the epoch.

## Credential strength

A password is an additional login method, not the stronger one. [Account recovery](/api/auth/recover/) emails a non-expiring team token, meaning mailbox access still provides full account access regardless of a password.

Eliminating this risk requires disabling the email provider, which also removes self-service recovery.
:::note[Version choice]

For new clients, prefer the V2 route when both V1 and V2 exist for the same action. V2 uses the
  newer captcha field name and returns more response data. V1 remains useful for actions that do not
  have a V2 route, such as logging in with a team token or testing an auth token.

:::
