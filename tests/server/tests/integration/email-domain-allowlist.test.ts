import { config } from '@rctf/config'
import { createDatabase, users } from '@rctf/db'
import { BadEmailChangeDivision, GoodEmailSet } from '@rctf/types'
import { afterAll, beforeAll, describe, test } from 'bun:test'
import { eq } from 'drizzle-orm'
import type { Hono } from 'hono'
import { createLoginVerification } from '../../../../apps/api/src/cache/auth-cache'
import { createRedis } from '../../../../apps/api/src/util/redis'
import { getApp, request } from '../../app'
import { expectResponse, generateAuthToken } from '../../util'

let app: Hono<any>
let oldEmail: typeof config.email
let oldDomains: typeof config.allowedEmailDomains

const getDb = () => createDatabase(config.database.sql).db
const cleanups: Array<() => Promise<void>> = []

const createTestUser = async (emailDomain: string) => {
  const db = getDb()
  const id = crypto.randomUUID()
  const email = `${crypto.randomUUID()}@${emailDomain}`
  const name = crypto.randomUUID()

  const [user] = await db
    .insert(users)
    .values({ id, email, name, division: 'hs', perms: 0 })
    .returning()

  cleanups.push(async () => {
    await db.delete(users).where(eq(users.id, id))
  })

  return user!
}

beforeAll(async () => {
  app = await getApp()
  oldEmail = config.email
  oldDomains = config.allowedEmailDomains
})

afterAll(async () => {
  config.email = oldEmail
  config.allowedEmailDomains = oldDomains

  for (const cleanup of cleanups) {
    await cleanup()
  }
})

const setEmailRequest = (version: 1 | 2, authToken: string, email: string) =>
  request(app, `/api/v${version}/users/me/auth/email`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${authToken}`,
    },
    body: JSON.stringify({ email }),
  })

const verifyRequest = (version: 1 | 2, verifyToken: string) =>
  request(app, `/api/v${version}/auth/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ verifyToken }),
  })

describe('email domain allowlist on email change', () => {
  test('v1 set-email rejects a disallowed domain', async () => {
    config.email = undefined
    config.allowedEmailDomains = ['knu.ac.kr']

    const user = await createTestUser('knu.ac.kr')
    const authToken = await generateAuthToken(user.id)

    const res = await setEmailRequest(
      1,
      authToken,
      `${crypto.randomUUID()}@gmail.com`
    )

    await expectResponse(res, BadEmailChangeDivision)
  })

  test('v2 set-email rejects a disallowed domain', async () => {
    config.email = undefined
    config.allowedEmailDomains = ['knu.ac.kr']

    const user = await createTestUser('knu.ac.kr')
    const authToken = await generateAuthToken(user.id)

    const res = await setEmailRequest(
      2,
      authToken,
      `${crypto.randomUUID()}@gmail.com`
    )

    await expectResponse(res, BadEmailChangeDivision)
  })

  test('v1 set-email allows an approved domain', async () => {
    config.email = undefined
    config.allowedEmailDomains = ['knu.ac.kr']

    const user = await createTestUser('gmail.com')
    const authToken = await generateAuthToken(user.id)

    const res = await setEmailRequest(
      1,
      authToken,
      `${crypto.randomUUID()}@knu.ac.kr`
    )

    await expectResponse(res, GoodEmailSet)
  })

  test('empty allowlist permits any domain', async () => {
    config.email = undefined
    config.allowedEmailDomains = []

    const user = await createTestUser('knu.ac.kr')
    const authToken = await generateAuthToken(user.id)

    const res = await setEmailRequest(
      1,
      authToken,
      `${crypto.randomUUID()}@gmail.com`
    )

    await expectResponse(res, GoodEmailSet)
  })

  test('v1 verify update branch rejects a disallowed domain', async () => {
    config.email = {
      provider: {
        name: 'emails/smtp',
        options: { smtpUrl: 'smtp://example.com' },
      },
      from: 'no-reply@example.com',
    }
    config.allowedEmailDomains = ['knu.ac.kr']

    const user = await createTestUser('knu.ac.kr')
    const token = await createLoginVerification(await createRedis(), {
      kind: 'update',
      userId: user.id,
      email: `${crypto.randomUUID()}@gmail.com`,
    })

    const res = await verifyRequest(1, token)

    await expectResponse(res, BadEmailChangeDivision)
  })

  test('v2 verify update branch rejects a disallowed domain', async () => {
    config.email = {
      provider: {
        name: 'emails/smtp',
        options: { smtpUrl: 'smtp://example.com' },
      },
      from: 'no-reply@example.com',
    }
    config.allowedEmailDomains = ['knu.ac.kr']

    const user = await createTestUser('knu.ac.kr')
    const token = await createLoginVerification(await createRedis(), {
      kind: 'update',
      userId: user.id,
      email: `${crypto.randomUUID()}@gmail.com`,
    })

    const res = await verifyRequest(2, token)

    await expectResponse(res, BadEmailChangeDivision)
  })

  test('v2 verify update branch accepts an allowed domain', async () => {
    config.email = {
      provider: {
        name: 'emails/smtp',
        options: { smtpUrl: 'smtp://example.com' },
      },
      from: 'no-reply@example.com',
    }
    config.allowedEmailDomains = ['knu.ac.kr']

    const user = await createTestUser('gmail.com')
    const token = await createLoginVerification(await createRedis(), {
      kind: 'update',
      userId: user.id,
      email: `${crypto.randomUUID()}@knu.ac.kr`,
    })

    const res = await verifyRequest(2, token)

    await expectResponse(res, GoodEmailSet)
  })
})
