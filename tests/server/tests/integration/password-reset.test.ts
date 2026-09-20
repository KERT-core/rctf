import { config } from '@rctf/config'
import { createDatabase, users } from '@rctf/db'
import {
  BadEndpoint,
  BadPassword,
  BadRateLimit,
  BadToken,
  BadTokenVerification,
  BadUnknownUser,
  GoodLogin,
  GoodPasswordSet,
  GoodRegisterV2,
  GoodToken,
  GoodVerify,
  GoodVerifySent,
} from '@rctf/types'
import { beforeAll, beforeEach, describe, expect, test } from 'bun:test'
import { eq } from 'drizzle-orm'
import type { Hono } from 'hono'
import { createToken, TokenKind } from '../../../../apps/api/src/lib/tokens'
import { createRedis } from '../../../../apps/api/src/util/redis'
import { getApp, request } from '../../app'
import { emailFailure } from '../../setup'
import { clearDatabase, expectResponse, lastEmailTo } from '../../util'

let app: Hono<any>
const getDb = () => createDatabase(config.database.sql).db

const PASSWORD = 'correct-horse-battery-staple'
const NEW_PASSWORD = 'a-different-correct-horse'

const send = (
  method: string,
  path: string,
  body: unknown,
  authToken?: string
) =>
  request(app, path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    },
    body: JSON.stringify(body),
  })

const post = (path: string, body: unknown, authToken?: string) =>
  send('POST', path, body, authToken)

const get = (path: string, authToken: string) =>
  request(app, path, {
    method: 'GET',
    headers: { Authorization: `Bearer ${authToken}` },
  })

// config is module-level and shared by every test in the process, so it has to
// be put back even when the body throws.
const withoutEmailProvider = async <T>(fn: () => Promise<T>): Promise<T> => {
  const previous = config.email
  config.email = undefined
  try {
    return await fn()
  } finally {
    config.email = previous
  }
}

const register = async (withPassword = true) => {
  const name = crypto.randomUUID()
  const email = `${crypto.randomUUID()}@reset.test`
  const res = await post('/api/v2/auth/register', {
    name,
    email,
    ...(withPassword ? { password: PASSWORD } : {}),
  })
  await expectResponse(res, GoodVerifySent)

  const verified = await post('/api/v2/auth/verify', {
    verifyToken: lastEmailTo(email)!.token,
  })
  const body = await expectResponse(verified, GoodRegisterV2)
  return {
    name,
    email,
    authToken: body.data.authToken as string,
    teamToken: body.data.teamToken as string,
  }
}

const requestReset = async (email: string) => {
  const res = await post('/api/v2/auth/reset-password', { email })
  await expectResponse(res, GoodVerifySent)
  return lastEmailTo(email)
}

beforeAll(async () => {
  app = await getApp()
})

beforeEach(async () => {
  await clearDatabase()
  const redis = await createRedis()
  await redis.flushdb()
})

describe('requesting a password reset', () => {
  test('emails a link to the reset page, not the verify page', async () => {
    const { email } = await register()

    const mail = await requestReset(email)
    expect(mail?.path).toBe('reset-password')
    expect(mail?.subject).toContain('Reset your password')
  })

  test('answers goodVerifySent for an address nobody holds', async () => {
    // Identical response to the known case. Both rate-limit buckets are
    // consumed before the lookup, so the limiter is not an oracle either.
    const unknown = `${crypto.randomUUID()}@reset.test`
    const res = await post('/api/v2/auth/reset-password', { email: unknown })
    await expectResponse(res, GoodVerifySent)
    expect(lastEmailTo(unknown)).toBeUndefined()
  })

  test('answers badEndpoint with no email provider', async () => {
    const { email } = await register()

    await withoutEmailProvider(async () => {
      const res = await post('/api/v2/auth/reset-password', { email })
      await expectResponse(res, BadEndpoint)
    })
  })

  test('still answers goodVerifySent when the relay is down', async () => {
    // A throw here used to reach the global handler as a 500, and only a
    // registered address gets as far as the send, so that 500 disclosed
    // whether an account existed.
    const { email } = await register()

    emailFailure.enabled = true
    try {
      const res = await post('/api/v2/auth/reset-password', { email })
      await expectResponse(res, GoodVerifySent)
    } finally {
      emailFailure.enabled = false
    }
  })

  test('rate limits by address', async () => {
    // burst 2 per address. Flushed after register so the assertion is about
    // the address bucket and not whatever the per-IP one already holds.
    const { email } = await register()
    await (await createRedis()).flushdb()

    await requestReset(email)
    await requestReset(email)

    const limited = await post('/api/v2/auth/reset-password', { email })
    await expectResponse(limited, BadRateLimit)
  })
})

describe('confirming a password reset', () => {
  test('sets the new password and returns a usable token', async () => {
    const { name, email } = await register()
    const mail = await requestReset(email)

    const res = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: mail!.token,
      password: NEW_PASSWORD,
    })
    const body = await expectResponse(res, GoodPasswordSet)

    const probe = await get('/api/v1/auth/test', body.data.authToken)
    await expectResponse(probe, GoodToken)

    const login = await post('/api/v2/auth/login', {
      identifier: name,
      password: NEW_PASSWORD,
    })
    await expectResponse(login, GoodLogin)
  })

  test('revokes the tokens the account already had', async () => {
    const { email, authToken, teamToken } = await register()

    const before = await post('/api/v2/auth/verify', { verifyToken: teamToken })
    await expectResponse(before, GoodVerify)

    const mail = await requestReset(email)
    const res = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: mail!.token,
      password: NEW_PASSWORD,
    })
    await expectResponse(res, GoodPasswordSet)

    const stale = await get('/api/v1/auth/test', authToken)
    await expectResponse(stale, BadToken)

    const staleTeam = await post('/api/v2/auth/verify', {
      verifyToken: teamToken,
    })
    await expectResponse(staleTeam, BadTokenVerification)
  })

  test('cannot be replayed', async () => {
    // Single use falls out of the epoch check rather than a stored marker:
    // setUserPassword stamps the epoch with now, and isTokenRevoked compares
    // inclusively, so the token that performed the reset fails on its next
    // use.
    const { email } = await register()
    const mail = await requestReset(email)

    const first = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: mail!.token,
      password: NEW_PASSWORD,
    })
    await expectResponse(first, GoodPasswordSet)

    const second = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: mail!.token,
      password: `${NEW_PASSWORD}-again`,
    })
    await expectResponse(second, BadTokenVerification)
  })

  test('is dead once the password changes by another route', async () => {
    const { email, authToken } = await register()
    const mail = await requestReset(email)

    const changed = await send(
      'PUT',
      '/api/v2/users/me/auth/password',
      { password: NEW_PASSWORD, currentPassword: PASSWORD },
      authToken
    )
    await expectResponse(changed, GoodPasswordSet)

    const res = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: mail!.token,
      password: `${NEW_PASSWORD}-other`,
    })
    await expectResponse(res, BadTokenVerification)
  })

  test('sets a first password on an account that had none', async () => {
    // The authority is the mailbox, which recoverUser already treats as
    // enough for full account access, so this grants nothing new.
    const { name, email } = await register(false)

    const noPassword = await post('/api/v2/auth/login', {
      identifier: name,
      password: NEW_PASSWORD,
    })
    expect(noPassword.status).toBe(401)

    const mail = await requestReset(email)
    const res = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: mail!.token,
      password: NEW_PASSWORD,
    })
    await expectResponse(res, GoodPasswordSet)

    const login = await post('/api/v2/auth/login', {
      identifier: name,
      password: NEW_PASSWORD,
    })
    await expectResponse(login, GoodLogin)
  })

  test('rejects a token of the wrong kind', async () => {
    const { teamToken } = await register()

    const res = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: teamToken,
      password: NEW_PASSWORD,
    })
    await expectResponse(res, BadTokenVerification)
  })

  test('rejects a token that decrypts to nothing', async () => {
    const res = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: 'not-a-token',
      password: NEW_PASSWORD,
    })
    await expectResponse(res, BadTokenVerification)
  })

  test('answers badUnknownUser when the account is gone', async () => {
    const { email } = await register()
    const mail = await requestReset(email)

    const db = getDb()
    await db.delete(users).where(eq(users.email, email))

    const res = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: mail!.token,
      password: NEW_PASSWORD,
    })
    await expectResponse(res, BadUnknownUser)
  })

  test('rejects a password shorter than the minimum', async () => {
    const { email } = await register()
    const mail = await requestReset(email)

    const res = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: mail!.token,
      password: 'short',
    })
    await expectResponse(res, BadPassword)
  })

  test('answers badEndpoint with no email provider', async () => {
    // Removing the provider revokes every credential derived from email.
    const { email } = await register()
    const mail = await requestReset(email)

    await withoutEmailProvider(async () => {
      const res = await post('/api/v2/auth/reset-password/confirm', {
        resetToken: mail!.token,
        password: NEW_PASSWORD,
      })
      await expectResponse(res, BadEndpoint)
    })
  })

  test('rate limits by IP', async () => {
    // burst 10. The token is unguessable, so this meters the argon2 rather
    // than guessing.
    const forged = await createToken(
      TokenKind.PasswordReset,
      crypto.randomUUID()
    )
    await (await createRedis()).flushdb()

    for (let i = 0; i < 10; i++) {
      await post('/api/v2/auth/reset-password/confirm', {
        resetToken: forged,
        password: NEW_PASSWORD,
      })
    }

    const limited = await post('/api/v2/auth/reset-password/confirm', {
      resetToken: forged,
      password: NEW_PASSWORD,
    })
    await expectResponse(limited, BadRateLimit)
  })
})
