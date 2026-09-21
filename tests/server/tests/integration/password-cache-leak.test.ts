import { config } from '@rctf/config'
import { createDatabase, users } from '@rctf/db'
import { GoodRegisterV2, GoodToken, GoodVerifySent } from '@rctf/types'
import { beforeAll, beforeEach, describe, expect, test } from 'bun:test'
import { eq } from 'drizzle-orm'
import type { Hono } from 'hono'
import { getCachedUser } from '../../../../apps/api/src/cache/auth-cache'
import { createRedis } from '../../../../apps/api/src/util/redis'
import { getApp, request } from '../../app'
import { clearDatabase, expectResponse, lastEmailTo } from '../../util'

let app: Hono<any>
const getDb = () => createDatabase(config.database.sql).db

const HASH_KEYS = ['passwordHash', 'password_hash']

const registerWithPassword = async (name: string) => {
  const email = `${crypto.randomUUID()}@cache.test`
  const res = await request(app, '/api/v2/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name,
      email,
      password: 'correct-horse-battery-staple',
    }),
  })
  await expectResponse(res, GoodVerifySent)

  const verified = await request(app, '/api/v2/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ verifyToken: lastEmailTo(email)!.token }),
  })
  return await expectResponse(verified, GoodRegisterV2)
}

beforeAll(async () => {
  app = await getApp()
})

beforeEach(async () => {
  await clearDatabase()
  const redis = await createRedis()
  await redis.flushdb()
})

describe('password hash containment', () => {
  // The type only forces the call sites to be revisited; nothing type-checks
  // the JSON that reaches Redis, so this is where the invariant is held.
  test('the cached user blob carries no password hash', async () => {
    const name = crypto.randomUUID()
    const body = await registerWithPassword(name)

    // an authenticated request populates the cache
    const test = await request(app, '/api/v1/auth/test', {
      method: 'GET',
      headers: { Authorization: `Bearer ${body.data.authToken}` },
    })
    await expectResponse(test, GoodToken)

    const db = getDb()
    const row = await db
      .select({ id: users.id, hash: users.passwordHash })
      .from(users)
      .where(eq(users.name, name))
      .then(r => r[0])
    expect(typeof row?.hash).toBe('string')

    const redis = await createRedis()
    const cached = await getCachedUser(redis, row!.id)
    expect(cached).not.toBeNull()

    const keys = Object.keys(cached as object)
    for (const forbidden of HASH_KEYS) {
      expect(keys).not.toContain(forbidden)
    }
    expect(JSON.stringify(cached)).not.toContain(row!.hash as string)
  })

  test('the cached user carries the fields revocation depends on', async () => {
    const name = crypto.randomUUID()
    const body = await registerWithPassword(name)

    await request(app, '/api/v1/auth/test', {
      method: 'GET',
      headers: { Authorization: `Bearer ${body.data.authToken}` },
    })

    const db = getDb()
    const row = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.name, name))
      .then(r => r[0])

    const redis = await createRedis()
    const cached = await getCachedUser(redis, row!.id)

    expect(typeof cached?.tokenEpoch).toBe('number')
    expect(cached?.hasPassword).toBe(true)
  })
})
