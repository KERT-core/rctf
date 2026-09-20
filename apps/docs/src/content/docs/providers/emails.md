---
title: Email providers
description: Configure email delivery with SMTP, Amazon SES, Postmark, or Mailgun.
order: 2
---

Email providers send verification, recovery, email change, and password reset messages. Where a provider is configured, opening an emailed link is how a registration becomes an account, so delivery sits on the signup path rather than beside it.

:::tip[What we use in practice]
We usually use [Postmark](https://postmarkapp.com/) for events including Malta CTF, idek CTF, DiceCTF, and SekaiCTF. SES is inexpensive at higher volume when the event already uses AWS. SMTP works with any mail service that provides credentials, and Mailgun is another hosted option. Account limits and existing infrastructure usually matter more than the provider itself.
:::

## Configuration

Configure a provider and sender address. You can also add an email-specific logo:

```yaml
email:
  provider:
    name: emails/smtp
    options:
      smtpUrl: smtp://user:password@mail.example.com:587
  from: noreply@example.com
  logoUrl: https://example.com/email-logo.png # Optional
```

`<red>email.provider.name</red>` and `<red>email.from</red>` are the minimum. Only `<yellow>RCTF_EMAIL_FROM</yellow>` and `<yellow>RCTF_EMAIL_LOGO_URL</yellow>` map into the `<red>email</red>` block, so the provider name always comes from a file in `rctf.d/{:dir}`. The credential inside `<red>options</red>` is the part that can stay out of the file, for example in `<yellow>RCTF_SMTP_URL</yellow>`.

rCTF builds the `From` header from the CTF name and `<red>email.from</red>`, so the configured value has to be a bare address: `noreply@example.com` is sent as `"My CTF" <noreply@example.com>`. A value that already carries a display name ends up nested inside a second one.

When `<red>email.logoUrl</red>` is unset, emails use the top-level `<red>logoLightUrl</red>` and `<red>logoDarkUrl</red>` values instead. The logo can also be set with the `<yellow>RCTF_EMAIL_LOGO_URL</yellow>` environment variable.

The provider is constructed while the API starts, so an unknown provider name or a missing credential fails the boot rather than the first send: the process exits during startup and the container restarts. Read the container logs after editing the `<red>email</red>` block instead of waiting for a registration to prove it works.

No inbound port is required. Every provider is an outbound client and rCTF exposes no webhook route, so the mail service never needs to reach the instance. Only egress matters: a connection to your mail server for `<green>emails/smtp</green>`, and HTTPS to the vendor API for `<green>emails/ses</green>`, `<green>emails/postmark</green>`, and `<green>emails/mailgun</green>`.

:::note
Without an email provider, registration skips verification, account recovery and password reset are unavailable, and email-based division ACLs cannot be enforced. Removing the block from a running deployment also stops reset links that are already in flight.
:::

Registration, recovery, and password reset emails are [rate limited](/api#rate-limits) by client IP and destination address, with or without captcha. Configure [proxy trust](/configuration#proxy) correctly so the limiter sees the participant's IP rather than the proxy's.

## Messages

| Message                   | Subject                                     | Link              |
| ------------------------- | ------------------------------------------- | ----------------- |
| Registration verification | `[<dim>ctfName</dim>] Verify your email`    | `/verify`         |
| Account recovery          | `[<dim>ctfName</dim>] Recover your account` | `/verify`         |
| Email change              | `[<dim>ctfName</dim>] Update your email`    | `/verify`         |
| Password reset            | `[<dim>ctfName</dim>] Reset your password`  | `/reset-password` |

Each subject is prefixed with the current CTF name, and each link is that path on `<red>origin</red>` with the token in a `token` query parameter.

A send that fails does not fail the request. The `emails` module logs the error and the endpoint answers as it would have on success, which keeps a broken provider or a rejected recipient from turning registration, recovery, and reset into a 500. Delivery problems are visible in the API log only, so watch it after any change to the `<red>email</red>` block and during the first minutes of an event.

## Providers

:::::tabs
::::tab[emails/smtp]
Sends emails over SMTP using Nodemailer, which parses `<red>smtpUrl</red>` into its transport options.

```yaml
email:
  provider:
    name: emails/smtp
    options:
      smtpUrl: smtp://user:password@mail.example.com:587
  from: noreply@example.com
```

| Option               | Environment Variable | Description         |
| -------------------- | -------------------- | ------------------- |
| `<red>smtpUrl</red>` | `<yellow>RCTF_SMTP_URL</yellow>` | SMTP connection URL |

The URL decides more than the hostname, and a wrong one parses without complaint:

- The scheme sets TLS, not the port. `smtp://` always parses to `secure: false{:ts}`, so `smtp://mail.example.com:465` opens a plaintext connection to a port that expects TLS from the first byte. Prefer `smtp://` with 587, which starts in the clear and upgrades with STARTTLS; use `smtps://` if you have to use 465.
- The scheme is not optional. `mail.example.com:587` parses `mail.example.com` as the scheme and `587` as the hostname, and with credentials in front the password is read as the username.
- A query string becomes transport options. `?requireTLS=true` makes Nodemailer refuse to send unless the STARTTLS upgrade succeeds, and `tls.` keys nest under its `tls` object, as in `?tls.rejectUnauthorized=false`. Other dotted keys are dropped.

::::
::::tab[emails/ses]
Sends emails through Amazon Simple Email Service.

```yaml
email:
  provider:
    name: emails/ses
    options:
      awsKeyId: AKIAIOSFODNN7EXAMPLE
      awsKeySecret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      awsRegion: us-east-1
  from: noreply@example.com
```

| Option                    | Environment Variable       | Description           |
| ------------------------- | -------------------------- | --------------------- |
| `<red>awsKeyId</red>`     | `<yellow>RCTF_SES_KEY_ID</yellow>`     | AWS access key ID     |
| `<red>awsKeySecret</red>` | `<yellow>RCTF_SES_KEY_SECRET</yellow>` | AWS secret access key |
| `<red>awsRegion</red>`    | `<yellow>RCTF_SES_REGION</yellow>`     | AWS region            |

:::warning
Make sure your SES account is out of the sandbox and the sender address is verified before you use it.
:::
::::
::::tab[emails/postmark]
Sends emails through the [Postmark](https://postmarkapp.com/) API.

```yaml
email:
  provider:
    name: emails/postmark
    options:
      serverToken: your-server-token
  from: noreply@example.com
```

| Option                   | Environment Variable              | Description           |
| ------------------------ | --------------------------------- | --------------------- |
| `<red>serverToken</red>` | `<yellow>RCTF_POSTMARK_SERVER_TOKEN</yellow>` | Postmark server token |

::::
::::tab[emails/mailgun]
Sends emails through the [Mailgun](https://www.mailgun.com/) API.

```yaml
email:
  provider:
    name: emails/mailgun
    options:
      apiKey: your-api-key
      domain: mail.example.com
  from: noreply@example.com
```

| Option              | Environment Variable        | Description            |
| ------------------- | --------------------------- | ---------------------- |
| `<red>apiKey</red>` | `<yellow>RCTF_MAILGUN_API_KEY</yellow>` | Mailgun API key        |
| `<red>domain</red>` | `<yellow>RCTF_MAILGUN_DOMAIN</yellow>`  | Mailgun sending domain |

::::
:::::

## Local development

`compose.dev.yml{:file}` runs a [Mailpit](https://mailpit.axllent.org/) container next to Postgres and Redis. It accepts SMTP on `127.0.0.1:1025` and serves what it captures at `http://127.0.0.1:8025`:

```ansi
$ <red>docker</red> compose <dim>-f</dim> compose.dev.yml up <dim>-d</dim>
```

Point rCTF at it from your own config file. `rctf.d/{:dir}` ignores every file it holds except its own `.gitignore{:file}`, so this block stays in your working copy:

```yaml title="rctf.d/00-development.yaml"
email:
  provider:
    name: emails/smtp
    options:
      smtpUrl: smtp://127.0.0.1:1025
  from: noreply@example.com
```

Mailpit needs no credentials and accepts any sender and recipient, so verification, recovery, and reset links are readable in its web UI without sending mail to a real address.
