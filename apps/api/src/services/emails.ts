import path from 'node:path'
import { config } from '@rctf/config'
import type { DatabaseClient } from '@rctf/db'
import mustache from 'mustache'
import pino from 'pino'
import type { TypedRedis } from '../cache/scripts'
import { emailProvider } from '../providers/instances/emails'
import { getResolvedSettings } from './settings'

export type EmailKind = 'register' | 'recover' | 'update' | 'reset'

const logger = pino({ level: process.env.LOG_LEVEL ?? 'info' }).child({
  module: 'emails',
})

// Frontend page each kind's call to action points at, and its button label.
// The path used to be hardcoded in both templates, which only worked while
// every email led to /verify.
const callsToAction: Record<EmailKind, { path: string; label: string }> = {
  register: { path: 'verify', label: 'Verify email' },
  recover: { path: 'verify', label: 'Verify email' },
  update: { path: 'verify', label: 'Verify email' },
  reset: { path: 'reset-password', label: 'Reset password' },
}

// FIXME(es3n1n): this is sketchy
// TODO(es3n1n): we might want to migrate to eta/handlebars, but that's unfortunately a breaking change
const emailHTML = await Bun.file(
  path.join(__dirname, '/../../templates/email.html')
).text()
const emailTXT = await Bun.file(
  path.join(__dirname, '/../../templates/email.txt')
).text()

export const formatEmailSender = (
  displayName: string,
  address: string
): string => {
  const escapedDisplayName = displayName
    .replace(/[\r\n]+/g, ' ')
    .replace(/(["\\])/g, '\\$1')

  return `"${escapedDisplayName}" <${address}>`
}

export const resolveEmailLogoUrls = (
  emailLogoUrl: string | undefined,
  resolvedLightUrl: string | null,
  resolvedDarkUrl: string | null,
  configuredLightUrl: string,
  configuredDarkUrl: string
) => {
  if (emailLogoUrl) {
    return { lightUrl: emailLogoUrl, darkUrl: emailLogoUrl }
  }

  const lightUrl =
    resolvedLightUrl ||
    configuredLightUrl ||
    resolvedDarkUrl ||
    configuredDarkUrl ||
    null
  const darkUrl =
    resolvedDarkUrl ||
    configuredDarkUrl ||
    resolvedLightUrl ||
    configuredLightUrl ||
    null

  return { lightUrl, darkUrl }
}

export const sendVerificationEmail = async (
  db: DatabaseClient,
  to: string,
  kind: EmailKind,
  token: string,
  redis?: TypedRedis
) => {
  if (!emailProvider || !config.email) {
    throw new Error('Email provider is not set.')
  }

  const { ctfName, logoLightUrl, logoDarkUrl } = await getResolvedSettings(
    db,
    redis
  )
  const emailLogoUrls = resolveEmailLogoUrls(
    config.email.logoUrl,
    logoLightUrl,
    logoDarkUrl,
    config.logoLightUrl,
    config.logoDarkUrl
  )

  const emailView = {
    ctf_name: ctfName,
    logo_light_url: emailLogoUrls.lightUrl,
    logo_dark_url: emailLogoUrls.darkUrl,
    origin: config.origin,
    token: encodeURIComponent(token),
    register: kind === 'register',
    recover: kind === 'recover',
    update: kind === 'update',
    reset: kind === 'reset',
    cta_path: callsToAction[kind].path,
    cta_label: callsToAction[kind].label,
  }
  const subject = {
    register: `[${ctfName}] Verify your email`,
    recover: `[${ctfName}] Recover your account`,
    update: `[${ctfName}] Update your email`,
    reset: `[${ctfName}] Reset your password`,
  }[kind]

  await emailProvider.send({
    from: formatEmailSender(ctfName, config.email.from),
    to: to,
    subject,
    html: mustache.render(emailHTML, emailView),
    text: mustache.render(emailTXT, emailView),
  })
}

// Sending is the last step of flows whose response must not depend on it. A
// throw here reaches the global handler as a 500, and only a registered
// address ever gets this far, so on the recovery paths that 500 would say the
// address exists. The operator finds the failure in the log; the requester
// retries within their bucket. Returns whether the message went out, for
// callers that can act on it.
export const trySendVerificationEmail = async (
  db: DatabaseClient,
  to: string,
  kind: EmailKind,
  token: string,
  redis?: TypedRedis
): Promise<boolean> => {
  try {
    await sendVerificationEmail(db, to, kind, token, redis)
    return true
  } catch (error) {
    logger.error({ err: error, kind }, 'Failed to send a verification email')
    return false
  }
}
